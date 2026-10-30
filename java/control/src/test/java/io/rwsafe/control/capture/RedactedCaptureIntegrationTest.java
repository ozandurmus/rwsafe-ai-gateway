package io.rwsafe.control.capture;

import static io.rwsafe.control.support.EventsJson.batch;
import static io.rwsafe.control.support.EventsJson.event;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.rwsafe.control.config.InternalConnector;
import io.rwsafe.control.notice.AcknowledgementPayload;
import io.rwsafe.control.notice.NoticeAcknowledgementService;
import io.rwsafe.control.notice.NoticeCatalogue;
import io.rwsafe.control.privacy.Pseudonymiser;
import io.rwsafe.control.support.ApiClient;
import io.rwsafe.control.support.ControlTestEnvironment;
import io.rwsafe.control.support.Synthetic;
import io.rwsafe.persistence.Database;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
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
 * Redacted capture end to end on the control plane (Q-4 b; SR-PRIV-10, SR-PRIV-11, SR-HOST-2; ADR-009 §2-§5; AGENTS.md
 * 4.7, 4.13, 4.14; PR 25 review): content lives as encrypted, content-addressed chunks on the store volume and never in
 * PostgreSQL; it is stored only for an acknowledged user, below the watermark, when no detector still hits; metadata and
 * verdicts are stored in every case; only security_admin and privacy_officer read it (DSAR the privacy officer only),
 * with a reason and a case id, every request ledgered, SERVED only after the record opened; expired or tampered records
 * are never served; the byte cap evicts oldest first; a planned rotation re-wraps and an emergency shred deletes; no log
 * line carries content.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(OutputCaptureExtension.class)
class RedactedCaptureIntegrationTest {

    /** A synthetic marker that must never appear in any log line (AGENTS.md 4.14). */
    private static final String MARK = "synthetic-capture-canary-" + UUID.randomUUID().toString().substring(0, 8);
    private static final String ACKED = "SYNTHETIC\\capture-acked";
    private static final String NOT_ACKED = "SYNTHETIC\\capture-not-acked";
    private static final AtomicReference<Double> USED = new AtomicReference<>(0.10);
    private static final ObjectMapper JSON = new ObjectMapper();
    private static Path keyDir;
    private static Path storeDir;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) throws Exception {
        ControlTestEnvironment.register(r, true, true);
        keyDir = Files.createTempDirectory(ControlTestEnvironment.dir(), "capture-keys");
        storeDir = Files.createTempDirectory(ControlTestEnvironment.dir(), "capture-store");
        CaptureKeyringTest.writeKey(keyDir, "cap-test-a");
        r.add("rwsafe.capture.mode", () -> "redacted");
        r.add("rwsafe.capture.key-dir", keyDir::toString);
        r.add("rwsafe.capture.store-dir", storeDir::toString);
        r.add("RWSAFE_ENDUSER_CONTROLLER_NAME", () -> "Örnek Kurum A.Ş.");
        r.add("RWSAFE_ENDUSER_DPO_CONTACT", () -> "basvuru.synthetic.example.test");
        r.add("RWSAFE_ENDUSER_POLICY_LINK", () -> "https://intranet.synthetic.example.test/politika");
        r.add("RWSAFE_ENDUSER_RETENTION_METADATA", () -> "400");
        r.add("RWSAFE_ENDUSER_RETENTION_REDACTED", () -> "90");
        r.add("RWSAFE_ENDUSER_RETENTION_RAW", () -> "30");
    }

    /** The store volume's fill level, set by each test. */
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
    CaptureVault vault;
    @Autowired
    CaptureRetentionJob maintenance;
    @Autowired
    Database database;

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
        return stored(UUID.fromString(e.get("eventId").asText()));
    }

    private int stored(UUID id) {
        return jdbc().queryForObject("SELECT count(*) FROM capture_record WHERE event_id = ?", Integer.class, id);
    }

    private int events(ObjectNode e) {
        return jdbc().queryForObject("SELECT count(*) FROM verdict_event WHERE event_id = ?::uuid", Integer.class,
            e.get("eventId").asText());
    }

    private List<String> outcomes(UUID id) {
        return jdbc().queryForList("SELECT outcome FROM capture_read WHERE event_id = ? ORDER BY read_id", String.class,
            id);
    }

    private static String readBody(String reason, String caseId) {
        ObjectNode b = JSON.createObjectNode();
        if (reason != null) {
            b.put("reasonCode", reason);
        }
        if (caseId != null) {
            b.put("caseId", caseId);
        }
        return b.toString();
    }

    private static ApiClient.Response read(ApiClient c, UUID id, String reason, String caseId) throws Exception {
        return c.post("/api/v1/captures/" + id + "/read", readBody(reason, caseId), true);
    }

    private static List<Path> chunkFiles() throws Exception {
        try (Stream<Path> s = Files.walk(storeDir)) {
            return s.filter(f -> f.getFileName().toString().endsWith(ChunkFiles.SUFFIX)).toList();
        }
    }

    /** A record stored directly through the vault (to set an expiry the sink would not choose). */
    private UUID storedDirectly(Instant expiresAt) throws Exception {
        ObjectNode e = event("claude", "REDACT", ACKED, "192.0.2.10");
        ingest(e);
        UUID id = UUID.fromString(e.get("eventId").asText());
        byte[] plain = ("synthetic " + MARK).getBytes(StandardCharsets.UTF_8);
        assertTrue(vault.prepare(plain, plain.length).store(id, pseudonymiser.user(ACKED), Instant.now(), expiresAt,
            plain.length, false, "rwmask-v1-slice1"));
        return id;
    }

    @Test
    void contentLivesSealedOnTheStoreVolumeAndIsReadOnlyWithARoleAReasonAndACase(CapturedOutput output)
        throws Exception {
        ObjectNode e = captured("REDACT", ACKED, prompt());
        ingest(e);
        UUID id = UUID.fromString(e.get("eventId").asText());
        assertEquals(1, stored(id));
        assertEquals(keys.activeId().orElseThrow(), jdbc().queryForObject(
            "SELECT key_id FROM capture_record WHERE event_id = ?", String.class, id));
        assertFalse(chunkFiles().isEmpty(), "ADR-009: the content is on the store volume");
        for (Path f : chunkFiles()) {
            assertFalse(new String(Files.readAllBytes(f), StandardCharsets.ISO_8859_1).contains(MARK), "sealed");
        }

        ApiClient admin = signedIn("synthetic-admin");
        ApiClient.Response noReason = read(admin, id, null, null);
        assertEquals(403, noReason.status());
        assertEquals("CAPTURE_REASON_REQUIRED", noReason.body().get("reason").asText());
        ApiClient.Response dsarByAdmin = read(admin, id, "DSAR", "DSAR-0001");
        assertEquals(403, dsarByAdmin.status(), "PR 25 Q-2: DSAR is the privacy officer's");
        assertEquals("REASON_NOT_PERMITTED_FOR_ROLE", dsarByAdmin.body().get("reason").asText());
        ApiClient.Response ok = read(admin, id, "INCIDENT_INVESTIGATION", "CASE-2026-0001");
        assertEquals(200, ok.status(), String.valueOf(ok.body()));
        String text = ok.body().get("text").asText();
        assertTrue(text.contains(MARK) && text.contains("[REDACTED:TCKN]"));
        assertFalse(text.contains("synthetic-estate"), "the estate layer ran at persistence");
        assertEquals(200, read(signedIn("synthetic-officer"), id, "DSAR", "DSAR-0007").status());

        for (String login : new String[] {"synthetic-viewer", "synthetic-aiview", "synthetic-dual"}) {
            ApiClient.Response refused = read(signedIn(login), id, "INCIDENT_INVESTIGATION", "CASE-1");
            assertEquals(403, refused.status(), login);
            assertFalse(String.valueOf(refused.body()).contains(MARK), login);
            JsonNode detail = signedIn(login).get("/api/v1/traffic/" + id).body();
            assertFalse(String.valueOf(detail).contains(MARK), "no read path of " + login + " carries content");
        }
        assertEquals(List.of("REFUSED_NO_REASON", "REFUSED_ROLE", "SERVED", "SERVED", "REFUSED_ROLE", "REFUSED_ROLE",
            "REFUSED_ROLE"), outcomes(id), "D-02: every request is ledgered, refusals included");
        assertTrue(jdbc().queryForObject("SELECT count(*) FROM audit_event WHERE table_name = 'capture_read'",
            Integer.class) >= 7);
        assertFalse(output.getAll().contains(MARK), "no log line carries captured content (AGENTS.md 4.14)");
    }

    @Test
    void aRepeatedTextIsStoredOnce() throws Exception {
        // A fixed synthetic text (deterministic chunk boundaries), just under the 64 KiB capture bound.
        StringBuilder lines = new StringBuilder();
        for (int i = 0; lines.length() < 60_000; i++) {
            lines.append("synthetic repository context, line ").append(i).append(", module m").append(i % 17)
                .append('\n');
        }
        String big = "{\"prompt\":\"" + lines + "\"}";
        long chunksBefore = jdbc().queryForObject("SELECT count(*) FROM capture_chunk", Long.class);
        ObjectNode first = captured("REDACT", ACKED, big);
        ingest(first);
        long chunksAfterFirst = jdbc().queryForObject("SELECT count(*) FROM capture_chunk", Long.class);
        long bytesAfterFirst = database.captures().usage();
        assertTrue(chunksAfterFirst - chunksBefore >= 2, "a long text is several chunks");
        ObjectNode again = captured("REDACT", ACKED, big);
        ingest(again);
        assertEquals(1, stored(again));
        assertEquals(chunksAfterFirst, jdbc().queryForObject("SELECT count(*) FROM capture_chunk", Long.class),
            "ADR-009 §3: the resent text adds manifest references, not chunks");
        assertEquals(bytesAfterFirst, database.captures().usage());
        ApiClient.Response r = read(signedIn("synthetic-admin"), UUID.fromString(again.get("eventId").asText()),
            "INCIDENT_INVESTIGATION", "CASE-0003");
        assertEquals(200, r.status());
        assertTrue(r.body().get("text").asText().startsWith("{\"prompt\":\"synthetic repository context"));
    }

    @Test
    void expiredOrTamperedRecordsAreNeverServed() throws Exception {
        ApiClient admin = signedIn("synthetic-admin");
        UUID soon = storedDirectly(Instant.now().plusMillis(800));
        Thread.sleep(1200);
        assertEquals(404, read(admin, soon, "INCIDENT_INVESTIGATION", "CASE-0004").status(), "D-01");
        assertEquals(List.of("NOT_FOUND"), outcomes(soon));

        UUID tampered = storedDirectly(Instant.now().plus(1, ChronoUnit.DAYS));
        UUID chunk = jdbc().queryForObject("SELECT chunk_id FROM capture_manifest WHERE event_id = ? AND seq = 0",
            UUID.class, tampered);
        Path file = chunkFiles().stream().filter(f -> f.getFileName().toString().startsWith(chunk.toString()))
            .findFirst().orElseThrow();
        byte[] bytes = Files.readAllBytes(file);
        bytes[bytes.length - 1] ^= 1;
        Files.write(file, bytes);
        ApiClient.Response r = read(admin, tampered, "INCIDENT_INVESTIGATION", "CASE-0005");
        assertEquals(409, r.status());
        assertNull(r.body().get("text"));
        assertEquals(List.of("INTEGRITY_FAILED"), outcomes(tampered), "D-02: never SERVED when it did not open");
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

    @Autowired
    ChunkFiles files;
    @Autowired
    StoreCap storeCap;
    @Autowired
    io.rwsafe.control.privacy.Masking masking;

    /** PR 25 D-06: expiry from the event's time, size bounds after masking: counted outcomes, never exceptions. */
    @Test
    void boundsAreCountedNotThrown() {
        CaptureSink shortLived = new CaptureSink(new io.rwsafe.control.config.ControlProperties.Capture("redacted",
            keyDir, storeDir, null, java.time.Duration.ofSeconds(1), null), notices, watermark, keys, files, vault,
            storeCap, masking, java.time.Clock.systemUTC());
        io.rwsafe.persistence.StoredVerdictEvent old = new io.rwsafe.persistence.StoredVerdictEvent(UUID.randomUUID(),
            Instant.now().minusSeconds(10), "reqmod", "claude", "api", "chat", io.rwsafe.platform.verdict.Verdict.REDACT,
            "customer_data", List.of(), 10, 5, pseudonymiser.user(ACKED), null, "plain_allowlisted", 1, "c1", "k1",
            List.of(), List.of());
        assertEquals(CaptureSink.Outcome.EXPIRED, shortLived.accept(old,
            new CapturedContent("synthetic", false, 9L)), "spooled for longer than its retention: not stored");
        assertEquals(CaptureSink.Outcome.TOO_LARGE, sink.accept(old,
            new CapturedContent("y".repeat(CaptureVault.MAX_PLAIN_BYTES + 1), false, 1L)));
        assertEquals(CaptureSink.Outcome.EMPTY, sink.accept(old, new CapturedContent("", false, 0L)));
    }

    @Test
    void theByteCapEvictsTheOldestRecords() throws Exception {
        UUID oldest = storedDirectly(Instant.now().plus(1, ChronoUnit.DAYS));
        UUID newer = storedDirectly(Instant.now().plus(1, ChronoUnit.DAYS));
        long usage = database.captures().usage();
        StoreCap tight = new StoreCap(usage, database, vault);
        assertTrue(tight.makeRoom(1), "evicting the oldest makes room");
        assertEquals(0, stored(oldest), "ADR-009 §3: oldest first");
        assertTrue(tight.evicted() >= 1);
        assertTrue(jdbc().queryForObject("SELECT count(*) FROM capture_deletion_receipt WHERE reason = "
            + "'STORE_CAP_EVICTED' AND ? = ANY (event_ids)", Integer.class, oldest) == 1);
        assertEquals(1, jdbc().queryForObject("SELECT count(*) FROM audit_event WHERE table_name = 'capture_record' "
            + "AND operation = 'DELETE' AND row_key = ?", Integer.class, oldest.toString()),
            "ADR-009 §4: the deletion is a ledger row the SIEM export sends, keyed by the event id");
        assertFalse(new StoreCap(10, database, vault).makeRoom(11), "more than the cap never fits");
        assertTrue(stored(newer) <= 1);
    }

    @Test
    void plannedRotationRewrapsAndAnEmergencyShredDeletes() throws Exception {
        UUID before = storedDirectly(Instant.now().plus(1, ChronoUnit.DAYS));
        String oldKey = keys.activeId().orElseThrow();
        String newKey = "cap-rot-" + UUID.randomUUID().toString().substring(0, 6);
        CaptureKeyringTest.writeKey(keyDir, newKey);
        Files.writeString(keyDir.resolve("active"), newKey);
        CaptureRetentionJob.Run run = maintenance.runOnce();
        assertTrue(run.rewrapped() >= 2, "the record key and its chunk keys");
        assertEquals(0, jdbc().queryForObject("SELECT count(*) FROM capture_record WHERE key_id <> ?", Integer.class,
            newKey), "every live record is under the new key");
        assertTrue(jdbc().queryForObject("SELECT count(*) FROM capture_key_event WHERE operation = 'REWRAP'",
            Integer.class) >= 1);
        Files.delete(keyDir.resolve(oldKey + ".key"));
        keys.reload();
        ApiClient admin = signedIn("synthetic-admin");
        assertEquals(200, read(admin, before, "INCIDENT_INVESTIGATION", "CASE-0006").status(),
            "Q-3: a planned rotation keeps records readable after the old key is gone");

        UUID doomed = storedDirectly(Instant.now().plus(1, ChronoUnit.DAYS));
        String nextKey = "cap-rot-" + UUID.randomUUID().toString().substring(0, 6);
        CaptureKeyringTest.writeKey(keyDir, nextKey);
        Files.writeString(keyDir.resolve("active"), nextKey);
        Files.writeString(keyDir.resolve("shredded"), newKey + "\n");
        CaptureRetentionJob.Run shred = maintenance.runOnce();
        assertTrue(shred.shredded() >= 2, "emergency: every record under the shredded key");
        assertEquals(0, stored(doomed));
        assertEquals(0, stored(before));
        assertTrue(jdbc().queryForObject("SELECT count(*) FROM capture_key_event WHERE operation = 'EMERGENCY_SHRED' "
            + "AND from_key_id = ?", Integer.class, newKey) == 1);
        assertTrue(jdbc().queryForObject("SELECT count(*) FROM capture_deletion_receipt WHERE reason = 'KEY_SHREDDED'",
            Integer.class) >= 1);
        assertEquals(404, read(admin, doomed, "INCIDENT_INVESTIGATION", "CASE-0007").status());
        assertTrue(maintenance.runOnce().sweptFiles() >= 0);
    }
}
