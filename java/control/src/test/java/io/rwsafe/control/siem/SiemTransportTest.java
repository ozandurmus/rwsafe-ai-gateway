package io.rwsafe.control.siem;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import io.rwsafe.control.config.ControlProperties;
import io.rwsafe.control.siem.SiemDeliveryException.Reason;
import io.rwsafe.control.siem.SiemFormats.LineFormat;
import io.rwsafe.persistence.AuditContext;
import io.rwsafe.persistence.LocalAccount;
import io.rwsafe.platform.verdict.Verdict;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The two transports against local receivers with certificates generated at runtime: syslog over TLS (RFC 5425) with
 * CEF and LEEF, and the HEC stub over HTTPS. End to end from the real ingestion path, proving that the raw identity claim,
 * the raw client address and an account name never leave (SR-SIEM-2), and that only a verified TLS peer receives
 * anything (SR-SIEM-3).
 */
class SiemTransportTest {

    private static final String CLAIM = "SYNTHCORP\\synthetic.person";
    private static final String ADDRESS = "192.0.2.44";
    private static final List<String> RAW = List.of("synthetic.person", "synthcorp", "192.0.2.44", "192.0.2.",
        "synthetic-glass");

    @TempDir
    Path dir;
    private SiemFixture fx;
    private TestPki pki;
    private SSLContext client;
    private final List<AutoCloseable> closeables = new ArrayList<>();
    private final List<SiemExporter> exporters = new ArrayList<>();

    @BeforeEach
    void setUp() throws Exception {
        fx = new SiemFixture();
        pki = new TestPki("synthetic SIEM test CA");
        client = SiemTls.clientContext(pki.writeCaBundle(dir));
    }

    @AfterEach
    void tearDown() throws Exception {
        exporters.forEach(SiemExporter::stop);
        for (AutoCloseable c : closeables) {
            c.close();
        }
    }

    private TlsSyslogReceiver receiver(SSLContext server) throws Exception {
        TlsSyslogReceiver r = new TlsSyslogReceiver(server);
        closeables.add(r);
        return r;
    }

    private SyslogTlsSink syslog(int port, LineFormat format) {
        return new SyslogTlsSink("127.0.0.1", port, format, client, "rwsafe-control", 13, "1.0", Duration.ofSeconds(5),
            Duration.ofSeconds(5));
    }

    private void export(SiemSink sink) {
        SiemExporter e = new SiemExporter(sink, fx.db.siemExport(), fx.records, SiemFixture.settings(100, 50, 50, false),
            new SiemMetrics(sink.destination(), 100));
        exporters.add(e);
        e.start();
    }

    private void seedAccountAndEvents() {
        fx.db.localAccounts().createIfAbsent(new LocalAccount("synthetic-glass", "$2a$12$" + "y".repeat(53),
            List.of("security_admin"), true), new AuditContext("system:bootstrap", "local_account.create", "FIRST_START",
            null));
        fx.ingest(2, CLAIM, ADDRESS);
    }

    private static void assertNoRawIdentity(String exported) {
        String lower = exported.toLowerCase(Locale.ROOT);
        for (String raw : RAW) {
            assertFalse(lower.contains(raw), "a raw identity left for the SIEM: " + raw);
        }
    }

    @Test
    void cefOverTlsSyslogCarriesPseudonymsOnly() throws Exception {
        TlsSyslogReceiver receiver = receiver(pki.loopbackServer());
        seedAccountAndEvents();
        export(syslog(receiver.port(), LineFormat.CEF));
        List<String> messages = receiver.take(3, 10_000);
        assertEquals(3, messages.size());
        assertTrue(receiver.errors.isEmpty(), receiver.errors.toString());

        String audit = messages.get(0);
        assertTrue(audit.startsWith("<110>1 "), "facility 13, informational: " + audit.substring(0, 8));
        assertTrue(audit.contains(" rwsafe-control rwsafe - audit - CEF:0|rwsafe|ai-gateway|1.0|audit.local_account"
            + ".create|"));
        Cef auditCef = Cef.parse(audit.substring(audit.indexOf("CEF:0|")));
        assertEquals(fx.pseudonymiser.user("synthetic-glass"), auditCef.extension.get("cs3"));

        for (String m : messages.subList(1, 3)) {
            assertTrue(m.startsWith("<108>1 "), "block is a warning");
            Cef cef = Cef.parse(m.substring(m.indexOf("CEF:0|")));
            assertEquals(fx.pseudonymiser.user(CLAIM), cef.extension.get("suser"));
            assertEquals(fx.pseudonymiser.subnet(ADDRESS), cef.extension.get("cs1"));
            assertEquals(Set.of("rt", "externalId", "cat", "act", "reason", "suser", "cs1Label", "cs1", "cs2Label", "cs2",
                "cs3Label", "cs3", "cs4Label", "cs4", "cs5Label", "cs5", "cs6Label", "cs6", "flexString1Label",
                "flexString1", "flexString2Label", "flexString2", "cn1Label", "cn1", "cn2Label", "cn2", "cn3Label", "cn3"),
                new TreeSet<>(cef.extensionKeys), "the fixed key set");
        }
        messages.forEach(SiemTransportTest::assertNoRawIdentity);
        assertEquals(1, receiver.accepted.get(), "one long-lived connection");
    }

    @Test
    void leefOverTlsSyslogKeepsOneAttributePerTab() throws Exception {
        TlsSyslogReceiver receiver = receiver(pki.loopbackServer());
        seedAccountAndEvents();
        export(syslog(receiver.port(), LineFormat.LEEF));
        List<String> messages = receiver.take(3, 10_000);
        assertEquals(3, messages.size());
        String verdict = messages.get(1);
        String leef = verdict.substring(verdict.indexOf("LEEF:1.0|"));
        assertTrue(leef.startsWith("LEEF:1.0|rwsafe|ai-gateway|1.0|verdict.BLOCK|devTime="), leef);
        assertTrue(leef.contains("\tusrName=" + fx.pseudonymiser.user(CLAIM) + "\t"));
        assertTrue(leef.contains("\tclientSubnet=" + fx.pseudonymiser.subnet(ADDRESS) + "\t"));
        messages.forEach(SiemTransportTest::assertNoRawIdentity);
    }

    @Test
    void aReceiverOutsideTheConfiguredCaGetsNothing() throws Exception {
        TlsSyslogReceiver stranger = receiver(new TestPki("unrelated synthetic CA").loopbackServer());
        SyslogTlsSink sink = syslog(stranger.port(), LineFormat.CEF);
        SiemDeliveryException e = assertThrows(SiemDeliveryException.class,
            () -> sink.deliver(List.of(Rows.RECORDS.verdict(Rows.verdict(Verdict.BLOCK, "openai", "r")))));
        assertEquals(Reason.TLS, e.reason());
        assertNull(stranger.next(200), "nothing was received");
        sink.close();
    }

    @Test
    void aReceiverWhoseCertificateNamesAnotherHostGetsNothing() throws Exception {
        TlsSyslogReceiver other = receiver(pki.otherNameServer());
        SyslogTlsSink sink = syslog(other.port(), LineFormat.CEF);
        SiemDeliveryException e = assertThrows(SiemDeliveryException.class,
            () -> sink.deliver(List.of(Rows.RECORDS.verdict(Rows.verdict(Verdict.BLOCK, "openai", "r")))));
        assertEquals(Reason.TLS, e.reason());
        assertNull(other.next(200));
        sink.close();
    }

    @Test
    void aClosedConnectionIsDetectedAndReplacedBeforeTheNextBatch() throws Exception {
        TlsSyslogReceiver receiver = receiver(pki.loopbackServer());
        SyslogTlsSink sink = syslog(receiver.port(), LineFormat.CEF);
        sink.deliver(List.of(Rows.RECORDS.verdict(Rows.verdict(Verdict.ALLOW, "openai", null))));
        assertTrue(receiver.next(5_000) != null);
        receiver.dropConnections();
        Thread.sleep(200);
        sink.deliver(List.of(Rows.RECORDS.verdict(Rows.verdict(Verdict.WARN, "openai", "r"))));
        String second = receiver.next(5_000);
        assertTrue(second != null && second.contains("verdict.WARN"), "the batch went over a new connection");
        assertEquals(2, receiver.accepted.get());
        sink.close();
    }

    @Test
    void aReceiverThatStopsDrainingTimesOutInsteadOfHangingTheSender() throws Exception {
        TlsSyslogReceiver receiver = receiver(pki.loopbackServer());
        receiver.stalled = true;
        SyslogTlsSink sink = new SyslogTlsSink("127.0.0.1", receiver.port(), LineFormat.CEF, client, "rwsafe-control", 13,
            "1.0", Duration.ofSeconds(5), Duration.ofMillis(300));
        List<SiemRecord> big = new ArrayList<>();
        SiemRecord one = Rows.RECORDS.verdict(Rows.verdict(Verdict.BLOCK, "openai", "customer_data"));
        for (int i = 0; i < 20_000; i++) {
            big.add(one);
        }
        long t0 = System.nanoTime();
        SiemDeliveryException e = assertThrows(SiemDeliveryException.class, () -> sink.deliver(big));
        long millis = (System.nanoTime() - t0) / 1_000_000;
        assertEquals(Reason.TIMEOUT, e.reason());
        assertTrue(millis < 5_000, "the watchdog closed the connection after " + millis + " ms");
        sink.close();
    }

    private Path tokenFile(String token) throws Exception {
        Path f = Files.createTempFile(dir, "hec", ".token");
        Files.writeString(f, token + "\n");
        return f;
    }

    private static String runtimeToken() {
        byte[] b = new byte[16];
        new SecureRandom().nextBytes(b);
        return HexFormat.of().formatHex(b);
    }

    @Test
    void hecReceivesFixedJsonEventsAndRetriesAfterAnUnavailableAnswer() throws Exception {
        String token = runtimeToken();
        HecStub stub = new HecStub(pki.loopbackServer(), token);
        closeables.add(stub);
        stub.answerNext(503);
        seedAccountAndEvents();
        HecSink sink = new HecSink(stub.url(), tokenFile(token), client, "rwsafe-control", "rwsafe_ai",
            Duration.ofSeconds(5));
        assertFalse(sink.toString().contains(token));
        export(sink);
        List<JsonNode> events = stub.take(3, 10_000);
        assertEquals(3, events.size());
        assertTrue(stub.requests.get() >= 2, "the 503 was retried");
        assertEquals(0, stub.unauthorised.get());
        assertTrue(stub.paths.stream().allMatch(HecSink.EVENT_PATH::equals));

        JsonNode audit = events.get(0);
        assertEquals("rwsafe:audit", audit.get("sourcetype").asText());
        Set<String> auditKeys = keys(audit.get("event"));
        assertTrue(SiemSchemaTest.AUDIT_EVENT_KEYS.containsAll(auditKeys), auditKeys.toString());
        assertTrue(auditKeys.containsAll(Set.of("eventId", "action", "usrName", "auditedTable", "operation", "rowKey")));
        for (JsonNode verdict : events.subList(1, 3)) {
            assertEquals(SiemSchemaTest.HEC_ENVELOPE_KEYS, keys(verdict));
            assertEquals(SiemSchemaTest.VERDICT_EVENT_KEYS, keys(verdict.get("event")));
            assertEquals(fx.pseudonymiser.user(CLAIM), verdict.get("event").get("usrName").asText());
        }
        events.forEach(e -> assertNoRawIdentity(e.toString()));
    }

    @Test
    void hecWithTheWrongTokenIsAnAuthenticationFailure() throws Exception {
        HecStub stub = new HecStub(pki.loopbackServer(), runtimeToken());
        closeables.add(stub);
        HecSink sink = new HecSink(stub.url() + "/services/collector/event", tokenFile(runtimeToken()), client,
            "rwsafe-control", null, Duration.ofSeconds(5));
        SiemDeliveryException e = assertThrows(SiemDeliveryException.class,
            () -> sink.deliver(List.of(Rows.RECORDS.verdict(Rows.verdict(Verdict.BLOCK, "openai", "r")))));
        assertEquals(Reason.AUTH, e.reason());
        assertEquals(1, stub.unauthorised.get());
        sink.close();
    }

    @Test
    void hecRefusesEverythingButHttpsAndAVerifiedPeer() throws Exception {
        Path token = tokenFile(runtimeToken());
        for (String url : new String[] {"http://127.0.0.1:8088", "127.0.0.1:8088", "https://user@127.0.0.1:8088",
            "https://127.0.0.1:8088/services/collector?x=1", ""}) {
            assertThrows(IllegalStateException.class,
                () -> new HecSink(url, token, client, "h", null, Duration.ofSeconds(1)), url);
        }
        HecStub stranger = new HecStub(new TestPki("unrelated synthetic CA").loopbackServer(), runtimeToken());
        closeables.add(stranger);
        HecSink sink = new HecSink(stranger.url(), token, client, "h", null, Duration.ofSeconds(5));
        SiemDeliveryException e = assertThrows(SiemDeliveryException.class,
            () -> sink.deliver(List.of(Rows.RECORDS.verdict(Rows.verdict(Verdict.BLOCK, "openai", "r")))));
        assertEquals(Reason.TLS, e.reason());
        assertEquals(0, stranger.requests.get());
        sink.close();
    }

    @Test
    void anIncompleteDestinationIsNotStartedAndShowsWhy() throws Exception {
        ControlProperties.Siem siem = new ControlProperties.Siem(true, null, null, null, 0, 0, 0, null, null,
            new ControlProperties.Syslog("127.0.0.1", 6514, "cef", dir.resolve("absent-ca.crt"), null, 0, null, null),
            new ControlProperties.Hec("http://127.0.0.1:8088", tokenFile(runtimeToken()), pki.writeCaBundle(dir), null,
                null));
        SiemExportService service = new SiemExportService(new ControlProperties(null, null, null, null, null, null, siem),
            fx.db, fx.pseudonymiser);
        service.start();
        SiemExportService.Health h = service.health();
        service.stop();
        assertEquals("DOWN", h.state());
        assertTrue(h.detail().contains("syslog: not started, the SIEM CA bundle file is missing"), h.detail());
        assertTrue(h.detail().contains("hec: not started, the HEC URL must be https"), h.detail());
        assertFalse(h.detail().contains(dir.toString()), "no path in the health detail");

        SiemExportService off = new SiemExportService(new ControlProperties(null, null, null, null, null, null, null),
            fx.db, fx.pseudonymiser);
        off.start();
        assertEquals("UNKNOWN", off.health().state());
        off.stop();
        assertThrows(IllegalArgumentException.class, () -> new ControlProperties.Siem(true, "middle", null, null, 0, 0,
            0, null, null, null, null));
    }

    private static Set<String> keys(JsonNode n) {
        Set<String> out = new TreeSet<>();
        n.fieldNames().forEachRemaining(out::add);
        return out;
    }
}
