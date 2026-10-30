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

    @Test
    void noBodyFragmentReachesALogAMetricAnErrorOrAStoredRow(CapturedOutput console) throws Exception {
        Path spool = Files.createTempDirectory(ControlTestEnvironment.dir(), "spool");
        List<String> answers = new ArrayList<>();
        List<String> errorPages = new ArrayList<>();
        String metricsText;
        int shipped;
        try (LogCapture logs = new LogCapture()) {
            BoundedEventQueue queue = new BoundedEventQueue(1000);
            EventShipper shipper = new EventShipper(queue, URI.create("http://127.0.0.1:" + internal.port()
                + "/internal/v1/verdict-events"), spool, 1024 * 1024, Duration.ofMillis(200));
            Thread shipperThread = new Thread(shipper, "rwsafe-event-shipper-test");
            shipperThread.start();
            IcapEngine engine = new IcapEngine(Snapshots.builtinDevelopment(), DetectorSet.standard(), queue,
                EngineConfig.defaults().withBodyLimits(16 * 1024, 64L * 1024 * 1024).withWindow(1024, 128)
                    .withTimeouts(400, 3_000));
            IcapServer server = new IcapServer(engine, 0);
            int icap = server.start("127.0.0.1", 0);
            MetricsEndpoint metrics = new MetricsEndpoint("127.0.0.1", 0, engine, queue, shipper, null, 0);
            try {
                int expectedEvents = drive(icap, errorPages);
                shipped = awaitShipped(shipper, queue, expectedEvents);
                metricsText = HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"
                    + metrics.port() + "/metrics")).GET().build(), HttpResponse.BodyHandlers.ofString()).body();
                refusedBatches(answers);
                ApiClient viewer = new ApiClient(port);
                assertEquals(200, viewer.login("synthetic-viewer", ControlTestEnvironment.PASSWORDS.get("synthetic-viewer"))
                    .status());
                answers.add(viewer.get("/api/v1/traffic").raw().body());
            } finally {
                metrics.close();
                server.close();
                shipper.stop();
                shipperThread.join(10_000);
            }

            assertTrue(shipped >= 10, "the data plane shipped " + shipped + " events");
            assertTrue(metricsText.contains("icap_transactions_total"), "the metrics text was read");
            assertTrue(logs.events() > 0 && logs.logback().contains("verdict batch refused"),
                "the Logback capture saw the control plane's own statements");

            Map<String, String> sources = new LinkedHashMap<>();
            sources.put("logback", logs.logback());
            sources.put("java.util.logging", logs.jul());
            sources.put("uncaught exceptions", logs.uncaught());
            sources.put("console", console.getAll());
            sources.put("prometheus text", metricsText);
            sources.put("data-plane block and error pages", String.join("\n", errorPages));
            sources.put("control-plane answers", String.join("\n", answers));
            sources.put("database rows", databaseRows());
            List<String> found = new ArrayList<>();
            scan(sources, bodyMarkers, found);
            scan(sources, identityMarkers, found);
            // The spool holds the wire format, whose identity claim is raw by design (C1 is pseudonymised at the control
            // plane); bodies never.
            scan(Map.of("verdict spool", spoolText(spool)), bodyMarkers, found);
            assertTrue(found.isEmpty(), "body or identity fragments found (source <- marker class): " + found);
        }
    }

    /**
     * Every verdict path of the data plane with marked bodies; the block and error pages it answers are collected (an
     * allowed, redacted or relayed message carries its own markers onward by design). Returns how many verdict events
     * the data plane should emit.
     */
    private int drive(int icap, List<String> errorPages) throws Exception {
        String user = "SYNREALM\\" + token().toLowerCase(Locale.ROOT);
        identityMarkers.put("identity claim", List.of(user.toLowerCase(Locale.ROOT), user.substring(9)));
        String address = "198.51.100." + (1 + random.nextInt(254));
        identityMarkers.put("client address", List.of(address));
        String identity = "X-Authenticated-User: " + user + "\r\nX-Client-IP: " + address + "\r\n";
        String tckn = Synthetic.tckn(random.nextLong());
        String iban = Synthetic.iban(random.nextLong());
        String card = Synthetic.card(random.nextLong());
        String key = Synthetic.awsKey();
        bodyValue("TCKN in a body", tckn);
        bodyValue("IBAN in a body", iban);
        bodyValue("card in a body", card);
        bodyValue("secret in a body", key);
        int events = 0;

        // 1 allow, 2 redact, 3 block (JSON), all with identity headers.
        send(icap, claude(json("synthetic summary " + marker("allowed prompt")), identity));
        String redactedMarker = marker("redacted prompt");
        String redacted = send(icap, claude(json("customer " + tckn + " iban " + iban + " " + redactedMarker), identity));
        // The markers are real body content: the redacted request travels on with its marker and without the TCKN.
        assertTrue(redacted.contains(redactedMarker) && !redacted.contains(tckn) && redacted.contains("[REDACTED:TCKN]"),
            "the redact path rewrote the body");
        String blocked = send(icap, claude(json("deploy with " + key + " " + marker("blocked prompt")), identity));
        assertTrue(blocked.contains("HTTP/1.1 403"), "the block path answered");
        errorPages.add(blocked);
        events += 3;
        // 4 a browser form blocked with the page.
        byte[] form = ("prompt=synthetic+" + key + "+" + marker("blocked form")).getBytes(StandardCharsets.UTF_8);
        errorPages.add(send(icap, IcapClient.reqmod("POST /share HTTP/1.1\nHost: chatgpt.com\nAccept: text/html\n"
            + "Content-Type: application/x-www-form-urlencoded\nContent-Length: " + form.length + "\n", form, "")));
        events++;
        // 5 malformed JSON, 6 oversize, 7 an encoded body.
        byte[] broken = ("{\"model\":\"claude-synthetic\",\"messages\":[{\"role\":\"user\",\"content\":\"card " + card + " "
            + marker("malformed JSON")).getBytes(StandardCharsets.UTF_8);
        errorPages.add(send(icap, claude(broken, "")));
        errorPages.add(send(icap, claude(json((marker("oversize body") + " ").repeat(1500)), "")));
        byte[] encoded = json("synthetic " + marker("encoded body"));
        errorPages.add(send(icap, IcapClient.reqmod("POST /v1/messages HTTP/1.1\nHost: api.anthropic.com\n"
            + "Content-Type: application/json\nContent-Encoding: gzip\nContent-Length: " + encoded.length + "\n",
            encoded, "")));
        events += 3;
        // 8 a marker in the request URL.
        byte[] small = json("synthetic hello");
        send(icap, IcapClient.reqmod("POST /v1/messages?trace=" + marker("request URL")
            + " HTTP/1.1\nHost: api.anthropic.com\nContent-Type: application/json\nContent-Length: " + small.length
            + "\n", small, ""));
        events++;
        // 9 a streamed response relayed, 10 one aborted at the identifier.
        send(icap, IcapClient.respmod(chatRequest(), "HTTP/1.1 200 OK\nContent-Type: text/event-stream\n",
            sse(marker("streamed response"), null)));
        send(icap, IcapClient.respmod(chatRequest(), "HTTP/1.1 200 OK\nContent-Type: text/event-stream\n",
            sse(marker("aborted stream"), tckn)));
        events += 2;
        // 11 an ICAP header line without a colon, 12 a chunk size that is not hex: framing errors on fresh connections.
        byte[] good = claude(json("synthetic"), "");
        String text = new String(good, StandardCharsets.UTF_8);
        errorPages.add(send(icap, text.replaceFirst("Allow: 204\r\n", "Allow: 204\r\n" + marker("ICAP header line")
            + "\r\n").getBytes(StandardCharsets.UTF_8)));
        int bodyAt = text.lastIndexOf("\r\n\r\n", text.length() - 8) + 4;
        errorPages.add(send(icap, (text.substring(0, bodyAt) + marker("chunk size") + "\r\nsynthetic\r\n0\r\n\r\n")
            .getBytes(StandardCharsets.UTF_8)));
        return events;
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
