package io.rwsafe.control;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.rwsafe.control.config.InternalConnector;
import io.rwsafe.control.support.ApiClient;
import io.rwsafe.control.support.ControlTestEnvironment;
import io.rwsafe.control.support.EventsJson;
import io.rwsafe.control.support.IcapClient;
import io.rwsafe.control.support.LogCapture;
import io.rwsafe.control.support.Synthetic;
import io.rwsafe.dataplane.boot.IcapServer;
import io.rwsafe.dataplane.boot.MetricsEndpoint;
import io.rwsafe.dataplane.controlplane.EventShipper;
import io.rwsafe.dataplane.events.BoundedEventQueue;
import io.rwsafe.dataplane.server.EngineConfig;
import io.rwsafe.dataplane.server.IcapEngine;
import io.rwsafe.detect.DetectorSet;
import io.rwsafe.policy.Snapshots;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * The log scanner (AGENTS.md 4.14, SR-PRIV-6, MASKING_AND_PRIVACY part C "log scanner"): the real data plane (ICAP engine,
 * event shipper, spool, metrics endpoint) runs against this control plane's capture sink in one JVM, and synthetic
 * request and response bodies carrying random marker tokens and identifier values pass every verdict path (allow,
 * redact, block as JSON and as a page, malformed JSON, oversize, encoded, streamed response allowed and aborted, a
 * marker in the request URL, ICAP framing errors), plus refused ingestion batches that carry markers. Everything the
 * JVM logs (Logback, java.util.logging, uncaught exceptions, the console), the Prometheus text, the control plane's error
 * bodies and every stored row are then searched: no marker, no body fragment and no raw identity claim or client address
 * may appear. Findings name the source class and the marker class, never the value.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(OutputCaptureExtension.class)
class LogScannerEndToEndTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) throws Exception {
        ControlTestEnvironment.register(r, true, true);
    }

    @LocalServerPort
    int port;
    @Autowired
    InternalConnector internal;
    @Autowired
    DataSource dataSource;

    /** Marker class to values; the values never appear in a message of this test. */
    private final Map<String, List<String>> bodyMarkers = new LinkedHashMap<>();
    private final Map<String, List<String>> identityMarkers = new LinkedHashMap<>();
    /** Group names from the proxy's group claim: never logged and never on a verdict event, so not in the spool either. */
    private final Map<String, List<String>> groupMarkers = new LinkedHashMap<>();
    private final SecureRandom random = new SecureRandom();

    private String marker(String cls) {
        String m = token();
        bodyMarkers.computeIfAbsent(cls, k -> new ArrayList<>()).add(m);
        return m;
    }

    private String token() {
        byte[] b = new byte[8];
        random.nextBytes(b);
        return "Mrk" + HexFormat.of().formatHex(b);
    }

    private void bodyValue(String cls, String value) {
        bodyMarkers.computeIfAbsent(cls, k -> new ArrayList<>()).add(value);
    }

    /** One running data plane: engine, ICAP listener, event queue and shipper, metrics endpoint. */
    private record DataPlane(BoundedEventQueue queue, EventShipper shipper, Thread shipperThread, IcapServer server,
                             int icap, MetricsEndpoint metrics) {

        static DataPlane start(URI events, Path spool) throws Exception {
            BoundedEventQueue queue = new BoundedEventQueue(1000);
            EventShipper shipper = new EventShipper(queue, events, spool, 1024 * 1024, Duration.ofMillis(200));
            Thread shipperThread = new Thread(shipper, "rwsafe-event-shipper-test");
            shipperThread.start();
            IcapEngine engine = new IcapEngine(Snapshots.builtinDevelopment(), DetectorSet.standard(), queue,
                EngineConfig.defaults().withBodyLimits(16 * 1024, 64L * 1024 * 1024).withWindow(1024, 128)
                    .withTimeouts(400, 3_000).withGroupClaimEncoding(EngineConfig.GroupClaimEncoding.PLAIN));
            IcapServer server = new IcapServer(engine, 0);
            int icap = server.start("127.0.0.1", 0);
            MetricsEndpoint metrics = new MetricsEndpoint("127.0.0.1", 0, engine, queue, shipper, null, 0);
            return new DataPlane(queue, shipper, shipperThread, server, icap, metrics);
        }

        String metricsText() throws Exception {
            return HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"
                + metrics.port() + "/metrics")).GET().build(), HttpResponse.BodyHandlers.ofString()).body();
        }

        void stop() throws InterruptedException {
            metrics.close();
            server.close();
            shipper.stop();
            shipperThread.join(10_000);
        }
    }

    @Test
    void noBodyFragmentReachesALogAMetricAnErrorOrAStoredRow(CapturedOutput console) throws Exception {
        Path spool = Files.createTempDirectory(ControlTestEnvironment.dir(), "spool");
        URI sink = URI.create("http://127.0.0.1:" + internal.port() + "/internal/v1/verdict-events");
        List<String> answers = new ArrayList<>();
        List<String> errorPages = new ArrayList<>();
        List<String> metricsTexts = new ArrayList<>();
        prepareIdentity();
        String spooled;
        int shipped;
        try (LogCapture logs = new LogCapture()) {
            // Phase A (PR 24 review D-05): the capture sink is unreachable, so the batches go to the on-disk spool.
            int closedPort;
            try (java.net.ServerSocket s = new java.net.ServerSocket(0)) {
                closedPort = s.getLocalPort();
            }
            DataPlane outage = DataPlane.start(URI.create("http://127.0.0.1:" + closedPort
                + "/internal/v1/verdict-events"), spool);
            try {
                core(outage.icap(), errorPages, "outage");
                for (int i = 0; i < 100 && (outage.shipper().spoolBytes() == 0 || outage.queue().size() > 0); i++) {
                    Thread.sleep(100);
                }
                metricsTexts.add(outage.metricsText());
            } finally {
                outage.stop();
            }
            spooled = spoolText(spool);
            assertTrue(!spooled.isEmpty(), "the outage wrote the verdict spool");

            // Phase B: the capture sink is up; the new shipper replays the spool, then every verdict path runs.
            DataPlane live = DataPlane.start(sink, spool);
            try {
                int expectedEvents = 3 + drive(live.icap(), errorPages);
                shipped = awaitShipped(live.shipper(), live.queue(), expectedEvents);
                metricsTexts.add(live.metricsText());
                refusedBatches(answers);
                refusedNoticeAndRegistryRequests(answers);
                ApiClient viewer = new ApiClient(port);
                assertEquals(200, viewer.login("synthetic-viewer", ControlTestEnvironment.PASSWORDS.get("synthetic-viewer"))
                    .status());
                answers.add(viewer.get("/api/v1/traffic").raw().body());
            } finally {
                live.stop();
            }

            // Positive control: a marker planted in a log statement (one as a placeholder argument, one as an argument
            // without a placeholder) must be found, or the capture proves nothing.
            String planted = token();
            String plantedArgument = token();
            org.slf4j.LoggerFactory.getLogger("io.rwsafe.logscanner.positivecontrol").info("planted {}", planted);
            org.slf4j.LoggerFactory.getLogger("io.rwsafe.logscanner.positivecontrol").info("planted", plantedArgument);

            assertTrue(shipped >= 10, "the data plane shipped " + shipped + " events");
            assertTrue(metricsTexts.get(1).contains("icap_transactions_total"), "the metrics text was read");
            assertTrue(logs.events() > 0 && logs.logback().contains("verdict batch refused"),
                "the Logback capture saw the control plane's own statements");

            Map<String, String> sources = new LinkedHashMap<>();
            sources.put("logback", logs.logback());
            sources.put("java.util.logging", logs.jul());
            sources.put("uncaught exceptions", logs.uncaught());
            sources.put("console", console.getAll());
            sources.put("prometheus text", String.join("\n", metricsTexts));
            sources.put("data-plane block and error pages", String.join("\n", errorPages));
            sources.put("control-plane answers", String.join("\n", answers));
            sources.put("database rows", databaseRows());
            List<String> control = new ArrayList<>();
            scan(sources, Map.of("positive control", List.of(planted, plantedArgument)), control);
            assertTrue(control.contains("logback <- positive control") && control.contains("console <- positive control"),
                "the scan found the planted markers: " + control);
            assertTrue(logs.logback().toLowerCase(Locale.ROOT).contains(plantedArgument.toLowerCase(Locale.ROOT)),
                "an argument without a placeholder is captured");

            List<String> found = new ArrayList<>();
            scan(sources, bodyMarkers, found);
            scan(sources, identityMarkers, found);
            // The spool holds the wire format, whose identity claim is raw by design (C1 is pseudonymised at the control
            // plane); bodies and group names never.
            scan(Map.of("verdict spool", spooled), bodyMarkers, found);
            sources.put("verdict spool", spooled);
            scan(sources, groupMarkers, found);
            assertTrue(found.isEmpty(), "body or identity fragments found (source <- marker class): " + found);
        }
    }

    private String userHeaders;
    private String groups;
    private String identity;

    /** The identity headers every request carries (D-05): a domain claim, a client address, a group claim. */
    private void prepareIdentity() {
        String user = "SYNREALM\\" + token().toLowerCase(Locale.ROOT);
        identityMarkers.put("identity claim", List.of(user.toLowerCase(Locale.ROOT), user.substring(9)));
        String address = "198.51.100." + (1 + random.nextInt(254));
        identityMarkers.put("client address", List.of(address));
        // The group claim (PO decision Q-39) in the configured plain encoding: estate-style and Turkish-letter names.
        String groupA = "grp-" + token().toLowerCase(Locale.ROOT);
        String tokenB = token();
        String groupB = "Hazine-Müdürlüğü-" + tokenB;
        // The ASCII token too: a log could hold the UTF-8 octets decoded as ISO-8859-1.
        groupMarkers.put("group claim", List.of(groupA, groupB, tokenB));
        groups = "X-Authenticated-Groups: " + groupA + "," + groupB + "\r\n";
        userHeaders = "X-Authenticated-User: " + user + "\r\nX-Client-IP: " + address + "\r\n";
        identity = userHeaders + groups;
    }

    /** Allow, redact and block with marked bodies: three verdict events. */
    private void core(int icap, List<String> errorPages, String phase) throws Exception {
        String tckn = Synthetic.tckn(random.nextLong());
        String iban = Synthetic.iban(random.nextLong());
        String key = Synthetic.awsKey();
        bodyValue("TCKN in a body", tckn);
        bodyValue("IBAN in a body", iban);
        bodyValue("secret in a body", key);
        send(icap, claude(json("synthetic summary " + marker(phase + " allowed prompt")), identity));
        String redactedMarker = marker(phase + " redacted prompt");
        String redacted = send(icap, claude(json("customer " + tckn + " iban " + iban + " " + redactedMarker), identity));
        // The markers are real body content: the redacted request travels on with its marker and without the TCKN.
        assertTrue(redacted.contains(redactedMarker) && !redacted.contains(tckn) && redacted.contains("[REDACTED:TCKN]"),
            "the redact path rewrote the body");
        String blocked = send(icap, claude(json("deploy with " + key + " " + marker(phase + " blocked prompt")),
            identity));
        assertTrue(blocked.contains("HTTP/1.1 403"), "the block path answered");
        errorPages.add(blocked);
    }

    /**
     * Every other verdict path of the data plane with marked bodies and the identity headers; the block and error pages
     * it answers are collected (an allowed, redacted or relayed message carries its own markers onward by design).
     * Returns how many verdict events the data plane should emit.
     */
    private int drive(int icap, List<String> errorPages) throws Exception {
        core(icap, errorPages, "live");
        int events = 3;
        String tckn = Synthetic.tckn(random.nextLong());
        String card = Synthetic.card(random.nextLong());
        String key = Synthetic.awsKey();
        bodyValue("TCKN in a body", tckn);
        bodyValue("card in a body", card);
        // A browser form blocked with the page.
        byte[] form = ("prompt=synthetic+" + key + "+" + marker("blocked form")).getBytes(StandardCharsets.UTF_8);
        errorPages.add(send(icap, IcapClient.reqmod("POST /share HTTP/1.1\nHost: chatgpt.com\nAccept: text/html\n"
            + "Content-Type: application/x-www-form-urlencoded\nContent-Length: " + form.length + "\n", form, identity)));
        events++;
        // Malformed JSON, oversize, an encoded body.
        byte[] broken = ("{\"model\":\"claude-synthetic\",\"messages\":[{\"role\":\"user\",\"content\":\"card " + card + " "
            + marker("malformed JSON")).getBytes(StandardCharsets.UTF_8);
        errorPages.add(send(icap, claude(broken, identity)));
        errorPages.add(send(icap, claude(json((marker("oversize body") + " ").repeat(1500)), identity)));
        byte[] encoded = json("synthetic " + marker("encoded body"));
        errorPages.add(send(icap, IcapClient.reqmod("POST /v1/messages HTTP/1.1\nHost: api.anthropic.com\n"
            + "Content-Type: application/json\nContent-Encoding: gzip\nContent-Length: " + encoded.length + "\n",
            encoded, identity)));
        events += 3;
        // A repeated group claim is no claim (the strictest policy); its names must not surface either.
        send(icap, claude(json("synthetic " + marker("repeated group claim")), userHeaders + groups + groups));
        events++;
        // A marker in the request URL.
        byte[] small = json("synthetic hello");
        send(icap, IcapClient.reqmod("POST /v1/messages?trace=" + marker("request URL")
            + " HTTP/1.1\nHost: api.anthropic.com\nContent-Type: application/json\nContent-Length: " + small.length
            + "\n", small, identity));
        events++;
        // Streamed responses: one relayed, one aborted at the identifier.
        send(icap, IcapClient.respmod(chatRequest(), "HTTP/1.1 200 OK\nContent-Type: text/event-stream\n",
            sse(marker("streamed response"), null), identity));
        send(icap, IcapClient.respmod(chatRequest(), "HTTP/1.1 200 OK\nContent-Type: text/event-stream\n",
            sse(marker("aborted stream"), tckn), identity));
        events += 2;
        // Whole (non-streaming) JSON responses: clean, carrying an identifier, malformed (D-05).
        for (byte[] response : List.of(json("synthetic answer " + marker("JSON response")),
            json("customer " + tckn + " " + marker("JSON response with an identifier")),
            ("{\"content\":\"" + marker("malformed JSON response")).getBytes(StandardCharsets.UTF_8))) {
            send(icap, IcapClient.respmod(chatRequest(), "HTTP/1.1 200 OK\nContent-Type: application/json\n"
                + "Content-Length: " + response.length + "\n", response, identity));
            events++;
        }
        // An ICAP header line without a colon, a chunk size that is not hex: framing errors on fresh connections.
        String text = new String(claude(json("synthetic"), identity), StandardCharsets.UTF_8);
        errorPages.add(send(icap, text.replaceFirst("Allow: 204\r\n", "Allow: 204\r\n" + marker("ICAP header line")
            + "\r\n").getBytes(StandardCharsets.UTF_8)));
        int bodyAt = text.lastIndexOf("\r\n\r\n", text.length() - 8) + 4;
        errorPages.add(send(icap, (text.substring(0, bodyAt) + marker("chunk size") + "\r\nsynthetic\r\n0\r\n\r\n")
            .getBytes(StandardCharsets.UTF_8)));
        return events;
    }

    /** Refused notice acknowledgements and registry changes that carry markers (D-05): their logs are scanned too. */
    private void refusedNoticeAndRegistryRequests(List<String> answers) throws Exception {
        ApiClient sink = new ApiClient(internal.port());
        String intake = io.rwsafe.control.notice.NoticeIntakeController.PATH;
        String user = "SYNREALM\\" + marker("acknowledgement claim").toLowerCase(Locale.ROOT);
        List<ObjectNode> refused = new ArrayList<>();
        refused.add(JSON.createObjectNode().put("userClaim", user).put("noticeVersion", "v-" + marker("notice version"))
            .put("acknowledgedAt", java.time.Instant.now().toString()).put("source", "banner"));
        refused.add(JSON.createObjectNode().put("userClaim", user).put("noticeVersion", "x")
            .put("acknowledgedAt", java.time.Instant.now().toString()).put("source", marker("notice source")));
        refused.add(JSON.createObjectNode().put("userClaim", user).put("noticeVersion", "x")
            .put("acknowledgedAt", marker("acknowledged at")).put("source", "banner"));
        refused.add(JSON.createObjectNode().put("userClaim", user).put("noticeVersion", "x")
            .put("acknowledgedAt", java.time.Instant.now().toString()).put("source", "banner")
            .put("comment", marker("unknown notice field")));
        for (ObjectNode r : refused) {
            ApiClient.Response response = sink.post(intake, JSON.createArrayNode().add(r).toString(), false);
            assertTrue(response.status() == 400 || response.status() == 422, "a refused acknowledgement");
            answers.add(response.raw().body());
        }
        ApiClient admin = new ApiClient(port);
        assertEquals(200, admin.login("synthetic-admin", ControlTestEnvironment.PASSWORDS.get("synthetic-admin")).status());
        String tckn = Synthetic.tckn(random.nextLong());
        bodyValue("TCKN in a registry reason", tckn);
        answers.add(admin.post("/api/v1/policy/rules/class.TCKN/versions", JSON.createObjectNode().put("action", "BLOCK")
            .put("mode", "monitor").put("reasonCode", "SYN_" + marker("reason code").toUpperCase(Locale.ROOT) + "_123456")
            .toString(), true).raw().body());
        answers.add(admin.post("/api/v1/policy/rules/platform.devin/retirement", JSON.createObjectNode()
            .put("reason", "kayit " + marker("retirement reason") + " ref" + tckn).toString(), true).raw().body());
    }

    /** The control plane's ingestion refusing batches that carry markers in every way the contract refuses. */
    private void refusedBatches(List<String> answers) throws Exception {
        ApiClient sink = new ApiClient(internal.port());
        ObjectNode unknown = EventsJson.event("claude", "ALLOW", null, null);
        unknown.put("prompt", marker("unknown ingestion field"));
        ObjectNode platform = EventsJson.event(marker("invalid platform"), "ALLOW", null, null);
        ObjectNode reason = EventsJson.event("claude", "BLOCK", null, null);
        reason.put("reason", "x." + marker("invalid reason"));
        ObjectNode correlation = EventsJson.event("claude", "ALLOW", null, null);
        correlation.put("correlationId", Synthetic.githubToken());
        bodyValue("secret in a correlation id", Synthetic.githubToken());
        ObjectNode claim = EventsJson.event("claude", "ALLOW", marker("oversize claim").repeat(20), null);
        for (ObjectNode e : List.of(unknown, platform, reason, correlation, claim)) {
            ApiClient.Response r = sink.post("/internal/v1/verdict-events", EventsJson.batch(e), false);
            assertEquals(400, r.status());
            answers.add(r.raw().body());
        }
        ArrayNode typed = JSON.createArrayNode();
        typed.add(EventsJson.event("claude", "ALLOW", null, null).put("bodyBytes", marker("mistyped field")));
        answers.add(sink.post("/internal/v1/verdict-events", typed.toString(), false).raw().body());
        answers.add(sink.post("/internal/v1/verdict-events", "[{\"eventId\": " + marker("bare JSON token") + "}]", false)
            .raw().body());
    }

    private static String send(int icap, byte[] frame) throws Exception {
        try (IcapClient c = new IcapClient(icap)) {
            return c.exchange(frame).text();
        }
    }

    /** A Claude API request (a fail-closed AI flow) carrying {@code body}. */
    private static byte[] claude(byte[] body, String icapHeaders) {
        return IcapClient.reqmod("POST /v1/messages HTTP/1.1\nHost: api.anthropic.com\nContent-Type: application/json\n"
            + "Content-Length: " + body.length + "\n", body, icapHeaders);
    }

    private static String chatRequest() {
        return "POST /backend-api/conversation HTTP/1.1\nHost: chatgpt.com\nContent-Type: application/json\n"
            + "Accept: text/event-stream\n";
    }

    private static byte[] json(String prompt) {
        return ("{\"model\":\"claude-synthetic\",\"max_tokens\":64,\"messages\":[{\"role\":\"user\",\"content\":\""
            + prompt + "\"}]}").getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] sse(String marker, String leak) {
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < 30; i++) {
            s.append("event: delta\ndata: {\"text\":\"synthetic ").append(marker).append(' ').append(i).append("\"}\n\n");
        }
        if (leak != null) {
            s.append("event: delta\ndata: {\"text\":\"customer ").append(leak).append("\"}\n\n");
            for (int i = 0; i < 30; i++) {
                s.append("event: delta\ndata: {\"text\":\"synthetic tail ").append(i).append("\"}\n\n");
            }
        }
        return s.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static int awaitShipped(EventShipper shipper, BoundedEventQueue queue, int expected) throws Exception {
        for (int i = 0; i < 100 && (shipper.shipped() < expected || queue.size() > 0); i++) {
            Thread.sleep(100);
        }
        return (int) shipper.shipped();
    }

    private String databaseRows() {
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        StringBuilder all = new StringBuilder();
        for (String table : jdbc.queryForList("SELECT table_name FROM information_schema.tables WHERE table_schema = "
            + "'public' AND table_type = 'BASE TABLE'", String.class)) {
            for (String row : jdbc.queryForList("SELECT row_to_json(t)::text FROM \"" + table.replace("\"", "") + "\" t",
                String.class)) {
                all.append(table).append(' ').append(row).append('\n');
            }
        }
        assertTrue(all.indexOf("verdict_event ") >= 0, "the scan read the stored verdict events");
        return all.toString();
    }

    private static String spoolText(Path spool) throws Exception {
        StringBuilder all = new StringBuilder();
        try (var files = Files.list(spool)) {
            for (Path f : files.toList()) {
                all.append(Files.readString(f, StandardCharsets.UTF_8));
            }
        }
        return all.toString();
    }

    private static void scan(Map<String, String> sources, Map<String, List<String>> markers, List<String> found) {
        for (var source : sources.entrySet()) {
            String text = source.getValue().toLowerCase(Locale.ROOT);
            TreeSet<String> classes = new TreeSet<>();
            for (var m : markers.entrySet()) {
                for (String value : m.getValue()) {
                    if (text.contains(value.toLowerCase(Locale.ROOT))) {
                        classes.add(m.getKey());
                    }
                }
            }
            classes.forEach(cls -> found.add(source.getKey() + " <- " + cls));
        }
    }
}
