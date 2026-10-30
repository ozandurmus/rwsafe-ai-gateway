package io.rwsafe.control.capture;

import static io.rwsafe.control.support.EventsJson.batch;
import static io.rwsafe.control.support.EventsJson.event;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.rwsafe.control.config.InternalConnector;
import io.rwsafe.control.notice.AcknowledgementPayload;
import io.rwsafe.control.notice.NoticeAcknowledgementService;
import io.rwsafe.control.notice.NoticeCatalogue;
import io.rwsafe.control.privacy.Pseudonymiser;
import io.rwsafe.control.support.ApiClient;
import io.rwsafe.control.support.ControlTestEnvironment;
import io.rwsafe.control.support.Synthetic;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Redacted capture end to end on the control plane (Q-4 b; SR-PRIV-10, SR-PRIV-11, SR-HOST-2; AGENTS.md 4.7, 4.13,
 * 4.14): content is stored sealed only for an acknowledged user, below the watermark, when no detector still hits;
 * metadata and verdicts are stored in every case; only security_admin and privacy_officer read it, with a reason and a
 * case id, every request ledgered; the masked role and the viewer never reach it; no log line carries it; retention and
 * key rotation delete it with receipts.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(OutputCaptureExtension.class)
class RedactedCaptureIntegrationTest {

    /** A synthetic marker that must never appear in any log line (AGENTS.md 4.14). */
    private static final String MARK = "synthetic-capture-canary-" + UUID.randomUUID().toString().substring(0, 8);
    private static final String ACKED = "SYNTHETIC\\capture-acked";
    private static final String NOT_ACKED = "SYNTHETIC\\capture-not-acked";
    private static final AtomicReference<Double> USED = new AtomicReference<>(0.10);
    private static Path keyDir;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) throws Exception {
        ControlTestEnvironment.register(r, true, true);
        keyDir = Files.createTempDirectory(ControlTestEnvironment.dir(), "capture-keys");
        CaptureKeyringTest.writeKey(keyDir, "cap-test-a");
        r.add("rwsafe.capture.mode", () -> "redacted");
        r.add("rwsafe.capture.key-dir", keyDir::toString);
        r.add("RWSAFE_ENDUSER_CONTROLLER_NAME", () -> "Örnek Kurum A.Ş.");
        r.add("RWSAFE_ENDUSER_DPO_CONTACT", () -> "basvuru.synthetic.example.test");
        r.add("RWSAFE_ENDUSER_POLICY_LINK", () -> "https://intranet.synthetic.example.test/politika");
        r.add("RWSAFE_ENDUSER_RETENTION_METADATA", () -> "400");
        r.add("RWSAFE_ENDUSER_RETENTION_REDACTED", () -> "90");
        r.add("RWSAFE_ENDUSER_RETENTION_RAW", () -> "30");
    }

    /** The database volume's fill level, set by each test. */
    @TestConfiguration
    static class Disk {
        @Bean
        @Primary
        DiskUsageProbe settableProbe() {
            return new DiskUsageProbe() {
                @Override
                public double usedFraction(Path path) {
                    return USED.get();
                }
            };
        }
    }

    @LocalServerPort
    int port;
    @Autowired
    InternalConnector internal;
    @Autowired
    DataSource dataSource;
    @Autowired
    NoticeAcknowledgementService notices;
    @Autowired
    NoticeCatalogue notice;
    @Autowired
    Pseudonymiser pseudonymiser;
    @Autowired
    CaptureWatermark watermark;
    @Autowired
    CaptureSink sink;
    @Autowired
    CaptureKeyring keys;
    @Autowired
    CaptureRetentionJob retention;

    private JdbcTemplate jdbc() {
        return new JdbcTemplate(dataSource);
    }

    @BeforeEach
    void belowTheWatermarkAndAcknowledged() {
        USED.set(0.10);
        watermark.check();
        notices.record(List.of(new AcknowledgementPayload(ACKED, notice.currentVersion().orElseThrow(),
            Instant.now().toString(), "banner")));
    }

    private ApiClient signedIn(String login) throws Exception {
        ApiClient c = new ApiClient(port);
        assertEquals(200, c.login(login, ControlTestEnvironment.PASSWORDS.get(login)).status());
        return c;
    }

    private static ObjectNode captured(String verdict, String user, String text) {
        ObjectNode e = event("claude", verdict, user, "192.0.2.10");
        e.putObject("capture").put("text", text).put("truncated", false).put("redactedBytes", text.length());
        return e;
    }

    private static String prompt() {
        return "{\"prompt\":\"" + MARK + " customer [REDACTED:TCKN] asks synthetic-estate about fees\"}";
    }

    private void ingest(ObjectNode... events) throws Exception {
        ApiClient.Response r = new ApiClient(internal.port()).post("/internal/v1/verdict-events", batch(events), false);
        assertEquals(202, r.status(), String.valueOf(r.body()));
    }

    private int stored(ObjectNode e) {
        return jdbc().queryForObject("SELECT count(*) FROM redacted_capture WHERE event_id = ?::uuid", Integer.class,
            e.get("eventId").asText());
    }

    private int events(ObjectNode e) {
        return jdbc().queryForObject("SELECT count(*) FROM verdict_event WHERE event_id = ?::uuid", Integer.class,
            e.get("eventId").asText());
    }

    private static String readBody(String reason, String caseId) {
        ObjectNode b = new com.fasterxml.jackson.databind.ObjectMapper().createObjectNode();
        if (reason != null) {
            b.put("reasonCode", reason);
        }
        if (caseId != null) {
            b.put("caseId", caseId);
        }
        return b.toString();
    }

    @Test
    void anAcknowledgedRedactIsStoredSealedAndReadOnlyWithAReason(CapturedOutput output) throws Exception {
        ObjectNode e = captured("REDACT", ACKED, prompt());
        ingest(e);
        assertEquals(1, stored(e));
        byte[] ciphertext = jdbc().queryForObject("SELECT ciphertext FROM redacted_capture WHERE event_id = ?::uuid",
            byte[].class, e.get("eventId").asText());
        assertFalse(new String(ciphertext, java.nio.charset.StandardCharsets.ISO_8859_1).contains(MARK),
            "stored as ciphertext");
        assertEquals(keys.activeId().orElseThrow(), jdbc().queryForObject("SELECT key_id FROM redacted_capture WHERE "
            + "event_id = ?::uuid", String.class, e.get("eventId").asText()));
        String path = "/api/v1/captures/" + e.get("eventId").asText() + "/read";

        ApiClient admin = signedIn("synthetic-admin");
        ApiClient.Response noReason = admin.post(path, readBody(null, null), true);
        assertEquals(403, noReason.status());
        assertEquals("CAPTURE_REASON_REQUIRED", noReason.body().get("reason").asText());
        ApiClient.Response ok = admin.post(path, readBody("INCIDENT_INVESTIGATION", "CASE-2026-0001"), true);
        assertEquals(200, ok.status(), String.valueOf(ok.body()));
        String text = ok.body().get("text").asText();
        assertTrue(text.contains(MARK) && text.contains("[REDACTED:TCKN]"));
        assertFalse(text.contains("synthetic-estate"), "the estate layer ran at persistence");
        assertFalse(ok.body().get("withheld").asBoolean());
        ApiClient.Response officer = signedIn("synthetic-officer").post(path, readBody("DSAR", "DSAR-0007"), true);
        assertEquals(200, officer.status());

        String admins = pseudonymiser.user("synthetic-admin");
        assertEquals(List.of("REFUSED_NO_REASON", "SERVED"), jdbc().queryForList("SELECT outcome FROM capture_read "
            + "WHERE event_id = ?::uuid AND actor_fingerprint = ? ORDER BY read_id", String.class,
            e.get("eventId").asText(), admins));
        assertTrue(jdbc().queryForObject("SELECT count(*) FROM audit_event WHERE table_name = 'capture_read'",
            Integer.class) >= 3, "every read request is in the audit ledger");

        for (String login : new String[] {"synthetic-viewer", "synthetic-aiview", "synthetic-dual"}) {
            ApiClient.Response refused = signedIn(login).post(path, readBody("INCIDENT_INVESTIGATION", "CASE-1"), true);
            assertEquals(403, refused.status(), login);
            assertFalse(String.valueOf(refused.body()).contains(MARK), login);
            JsonNode detail = signedIn(login).get("/api/v1/traffic/" + e.get("eventId").asText()).body();
            assertFalse(String.valueOf(detail).contains(MARK), "no read path of " + login + " carries content");
        }
        assertFalse(output.getAll().contains(MARK), "no log line carries captured content (AGENTS.md 4.14)");
    }

    @Test
    void contentIsDroppedButMetadataKeptWhenAGateSaysNo(CapturedOutput output) throws Exception {
        long noAck = sink.counts().get(CaptureSink.Outcome.NO_ACKNOWLEDGEMENT);
        long hit = sink.counts().get(CaptureSink.Outcome.DETECTOR_HIT);
        long verdict = sink.counts().get(CaptureSink.Outcome.NOT_REDACT_VERDICT);
        ObjectNode notAcked = captured("REDACT", NOT_ACKED, prompt());
        ObjectNode leaking = captured("REDACT", ACKED, "{\"prompt\":\"" + MARK + " customer " + Synthetic.tckn(31)
            + "\"}");
        ObjectNode blocked = captured("BLOCK", ACKED, prompt());
        ingest(notAcked, leaking, blocked);
        for (ObjectNode e : List.of(notAcked, leaking, blocked)) {
            assertEquals(1, events(e), "metadata and verdict are stored");
            assertEquals(0, stored(e), "content is not");
        }
        assertEquals(noAck + 1, sink.counts().get(CaptureSink.Outcome.NO_ACKNOWLEDGEMENT), "SR-PRIV-10");
        assertEquals(hit + 1, sink.counts().get(CaptureSink.Outcome.DETECTOR_HIT), "SR-PRIV-11");
        assertEquals(verdict + 1, sink.counts().get(CaptureSink.Outcome.NOT_REDACT_VERDICT));
        assertFalse(output.getAll().contains(MARK));
    }

    @Test
    void theWatermarkStopsContentAndResumesWithHysteresis() throws Exception {
        long skipped = sink.counts().get(CaptureSink.Outcome.WATERMARK);
        USED.set(0.90);
        watermark.check();
        ObjectNode above = captured("REDACT", ACKED, prompt());
        ingest(above);
        assertEquals(1, events(above));
        assertEquals(0, stored(above), "SR-HOST-2: above 85 % no redacted content persists");
        assertEquals(skipped + 1, sink.counts().get(CaptureSink.Outcome.WATERMARK));
        JsonNode health = signedIn("synthetic-viewer").get("/api/v1/health").body();
        JsonNode component = null;
        for (JsonNode c : health.get("components")) {
            if (c.get("component").asText().equals("capture-watermark")) {
                component = c;
            }
        }
        assertEquals("DOWN", component.get("state").asText());
        assertTrue(component.get("detail").asText().contains("captures skipped"));

        USED.set(0.82);
        watermark.check();
        ObjectNode stillAbove = captured("REDACT", ACKED, prompt());
        ingest(stillAbove);
        assertEquals(0, stored(stillAbove), "no resume above 80 %");

        USED.set(0.78);
        watermark.check();
        ObjectNode below = captured("REDACT", ACKED, prompt());
        ingest(below);
        assertEquals(1, stored(below), "resumed below 80 %; raw would still be off above 70 %");
    }

    @Test
    void theContractBoundsTheCaptureObject() throws Exception {
        ObjectNode missing = event("claude", "REDACT", ACKED, "192.0.2.10");
        missing.putObject("capture").put("text", "synthetic").put("truncated", false);
        ObjectNode tooLong = captured("REDACT", ACKED, "x".repeat(64 * 1024 + 1));
        ObjectNode extra = captured("REDACT", ACKED, "synthetic");
        ((ObjectNode) extra.get("capture")).put("raw", "synthetic");
        for (ObjectNode bad : List.of(missing, tooLong, extra)) {
            ApiClient.Response r = new ApiClient(internal.port()).post("/internal/v1/verdict-events", batch(bad),
                false);
            assertEquals(400, r.status());
            assertEquals(0, events(bad), "the whole batch is refused");
        }
    }

    @Test
    void retentionAndKeyRotationDeleteWithReceipts() throws Exception {
        ObjectNode old = captured("REDACT", ACKED, prompt());
        ingest(old);
        assertEquals(1, stored(old));
        CaptureKeyringTest.writeKey(keyDir, "cap-test-b");
        Files.writeString(keyDir.resolve("active"), "cap-test-b");
        assertEquals(0, retention.runOnce().shredded(), "rotation alone shreds nothing");
        ObjectNode fresh = captured("REDACT", ACKED, prompt());
        ingest(fresh);
        assertEquals("cap-test-b", jdbc().queryForObject("SELECT key_id FROM redacted_capture WHERE event_id = "
            + "?::uuid", String.class, fresh.get("eventId").asText()));

        Files.delete(keyDir.resolve("cap-test-a.key"));
        CaptureRetentionJob.Run run = retention.runOnce();
        assertTrue(run.shredded() >= 1);
        assertEquals(0, stored(old), "crypto-shredded and deleted");
        assertEquals(1, stored(fresh));
        assertEquals(1, events(old), "the event's metadata stays");
        assertTrue(jdbc().queryForObject("SELECT count(*) FROM capture_deletion_receipt WHERE reason = 'KEY_SHREDDED' "
            + "AND ?::uuid = ANY (event_ids)", Integer.class, old.get("eventId").asText()) == 1);
        ApiClient.Response gone = signedIn("synthetic-admin").post("/api/v1/captures/" + old.get("eventId").asText()
            + "/read", readBody("INCIDENT_INVESTIGATION", "CASE-0002"), true);
        assertEquals(404, gone.status());
        assertNull(gone.body().get("text"));
    }
}
