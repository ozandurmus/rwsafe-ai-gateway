package io.rwsafe.persistence;

import static io.rwsafe.persistence.Events.event;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.persistence.SiemExportStore.ExportVerdict;
import io.rwsafe.persistence.SiemExportStore.LedgerRow;
import io.rwsafe.persistence.SiemExportStore.Start;
import io.rwsafe.persistence.SiemExportStore.Watermark;
import io.rwsafe.platform.verdict.Verdict;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SiemExportStoreTest {

    private static final String HASH = "$2a$12$" + "y".repeat(53);
    private static final AuditContext START = new AuditContext("system:siem-export", "siem_export.start",
        "START_FROM_EARLIEST", null);
    private DataSource ds;
    private Database db;
    private final Instant base = Instant.now().minusSeconds(60);

    @BeforeEach
    void open() {
        ds = TestDatabase.fresh();
        db = Database.migrateAndOpen(ds);
    }

    @Test
    void verdictEventsAreReadInCommitSafeOrderAfterTheWatermarkWithTheirFindings() {
        db.verdictEvents().insert(List.of(event(base, "claude", Verdict.REDACT, List.of(new FindingCount("TCKN", 2)))));
        db.verdictEvents().insert(List.of(event(base, "openai", Verdict.ALLOW, List.of()),
            event(base, "openai", Verdict.BLOCK, List.of(new FindingCount("SECRET", 1)))));
        SiemExportStore store = db.siemExport();

        List<ExportVerdict> all = new ArrayList<>();
        SiemExportStore.VerdictPosition after = null;
        for (int page = 0; page < 5; page++) {
            List<ExportVerdict> got = store.verdictsAfter(after, 2);
            if (got.isEmpty()) {
                break;
            }
            all.addAll(got);
            after = got.get(got.size() - 1).position();
        }
        assertEquals(3, all.size(), "keyset pages cover every event exactly once");
        assertEquals("claude", all.get(0).event().platform(), "the first transaction's event comes first");
        assertTrue(all.get(0).txId() < all.get(1).txId());
        assertEquals(all.get(1).txId(), all.get(2).txId(), "one batch, one transaction");
        assertEquals(List.of(new FindingCount("TCKN", 2)), all.get(0).event().findings());
        assertTrue(store.verdictsAfter(after, 10).isEmpty());
    }

    /**
     * PR 23 review D-1: the older transaction commits last. Its rows were invisible while the newer transaction's rows
     * were already committed; the barrier holds the newer rows back until the older commits, so nothing is overtaken.
     */
    @Test
    void anOlderTransactionThatCommitsLastIsNeverOvertaken() throws Exception {
        SiemExportStore store = db.siemExport();
        db.verdictEvents().insert(List.of(event(base, "claude", Verdict.ALLOW, List.of())));
        List<ExportVerdict> first = store.verdictsAfter(null, 10);
        assertEquals(1, first.size());
        SiemExportStore.VerdictPosition cursor = first.get(0).position();

        try (Connection older = ds.getConnection(); Connection newer = ds.getConnection()) {
            older.setAutoCommit(false);
            newer.setAutoCommit(false);
            UUID olderId = UUID.randomUUID();
            UUID newerId = UUID.randomUUID();
            insertEvent(older, olderId);            // the older transaction takes its id first
            insertEvent(newer, newerId);
            login(newer, "USR-00000000bb");         // the newer one writes the lower audit_id
            newer.commit();
            login(older, "USR-00000000aa");

            assertTrue(store.verdictsAfter(cursor, 10).isEmpty(), "the newer, committed row waits behind the barrier");
            assertTrue(store.ledgerAfter(null, 10).isEmpty());
            assertEquals(new SiemExportStore.Backlog(0, 2), store.backlog(new Watermark(cursor, null)),
                "the committed rows are backlog, held behind the open transaction (one verdict event, one ledger row)");

            older.commit();
            List<ExportVerdict> next = store.verdictsAfter(cursor, 10);
            assertEquals(List.of(olderId, newerId), next.stream().map(v -> v.event().eventId()).toList(),
                "both arrive, the older transaction's first");
            List<LedgerRow> ledger = store.ledgerAfter(null, 10);
            assertEquals(List.of("USR-00000000aa", "USR-00000000bb"),
                ledger.stream().map(LedgerRow::actorFingerprint).toList());
            assertTrue(ledger.get(0).auditId() > ledger.get(1).auditId(),
                "ordered by transaction, not by the identity taken before commit");
        }
    }

    @Test
    void ledgerRowsCarryAPseudonymousActorAndNeverPrintTheKey() {
        db.localAccounts().createIfAbsent(new LocalAccount("synthetic-glass", HASH, List.of("security_admin"), true),
            new AuditContext("system:bootstrap", "local_account.create", "FIRST_START", null));
        db.loginRecords().record("USR-0123456789", "local", false);
        List<LedgerRow> rows = db.siemExport().ledgerAfter(null, 10);
        assertEquals(2, rows.size());
        assertEquals("system:bootstrap", rows.get(0).actorFingerprint());
        assertEquals("local_account", rows.get(0).tableName());
        assertEquals("USR-0123456789", rows.get(1).actorFingerprint());
        assertFalse(rows.get(0).toString().contains("synthetic-glass"), "toString never prints the row key");
        assertEquals(1, db.siemExport().ledgerAfter(rows.get(0).position(), 10).size());
    }

    @Test
    void theWatermarkIsCreatedOnceUnderTheLedgerAndThenMoves() {
        SiemExportStore store = db.siemExport();
        assertTrue(store.watermark("hec").isEmpty());
        db.verdictEvents().insert(List.of(event(base, "claude", Verdict.ALLOW, List.of()),
            event(base, "claude", Verdict.WARN, List.of())));
        db.loginRecords().record("USR-0123456789", "ldap", false);
        assertEquals(new SiemExportStore.Backlog(3, 0), store.backlog(Watermark.START));

        Start latest = store.latestVerdicts();
        assertEquals(2, latest.skippedVerdicts());
        assertNull(latest.watermark().audit(), "ledger rows are never skipped");
        assertTrue(store.createWatermark("hec", latest, "latest", new AuditContext("system:siem-export",
            "siem_export.start", "START_FROM_LATEST", null)));
        assertFalse(store.createWatermark("hec", new Start(Watermark.START, 0), "earliest", START), "created once");
        assertEquals(latest.watermark(), store.watermark("hec").orElseThrow());
        assertEquals(2, store.skippedAtStart("hec"));
        assertEquals(new SiemExportStore.Backlog(2, 0), store.backlog(latest.watermark()),
            "the login row and the watermark's own ledger row");

        LedgerRow started = store.ledgerAfter(null, 10).get(1);
        assertEquals("siem_watermark", started.tableName());
        assertEquals("hec", started.rowKey());
        assertEquals("START_FROM_LATEST", started.reasonCode());

        Watermark moved = new Watermark(latest.watermark().verdict(), started.position());
        store.saveWatermark("hec", moved);
        assertEquals(moved, store.watermark("hec").orElseThrow());
        assertEquals(new SiemExportStore.Backlog(0, 0), store.backlog(moved));
        assertThrows(IllegalStateException.class, () -> store.saveWatermark("syslog", moved), "no row to move");
    }

    @Test
    void theWatermarkTableRefusesAnUnknownDestinationAHalfPositionAndAnUnledgeredInsert() throws SQLException {
        try (Connection c = ds.getConnection(); Statement s = c.createStatement()) {
            assertThrows(SQLException.class, () -> s.execute(
                "INSERT INTO siem_watermark (destination, start_from) VALUES ('hec', 'earliest')"), "no audit context");
            s.execute("BEGIN");
            s.execute("SELECT set_config('app.actor_fingerprint', 'system:test', true), "
                + "set_config('app.action_id', 'siem_export.start', true), set_config('app.reason_code', 'TEST', true)");
            assertThrows(SQLException.class, () -> s.execute(
                "INSERT INTO siem_watermark (destination, start_from) VALUES ('udp', 'earliest')"));
            s.execute("ROLLBACK");
        }
        try (Connection c = ds.getConnection(); Statement s = c.createStatement()) {
            s.execute("BEGIN");
            s.execute("SELECT set_config('app.actor_fingerprint', 'system:test', true), "
                + "set_config('app.action_id', 'siem_export.start', true), set_config('app.reason_code', 'TEST', true)");
            assertThrows(SQLException.class, () -> s.execute("INSERT INTO siem_watermark (destination, start_from, "
                + "audit_id) VALUES ('hec', 'earliest', 5)"), "a position without its transaction id");
            s.execute("ROLLBACK");
        }
    }

    private static void insertEvent(Connection c, UUID id) throws SQLException {
        try (PreparedStatement p = c.prepareStatement("INSERT INTO verdict_event (event_id, received_at, service, "
            + "platform, surface, step, verdict, body_bytes, decision_micros, transport, snapshot_version, "
            + "correlation_id, pseudonym_key_id) VALUES (?, now(), 'reqmod', 'openai', 'web', 'chat', 'ALLOW', 1, 1, "
            + "'mtls_verified', 1, 'c1', 'k1')")) {
            p.setObject(1, id);
            p.executeUpdate();
        }
    }

    private static void login(Connection c, String actor) throws SQLException {
        try (Statement s = c.createStatement()) {
            s.execute("SELECT set_config('app.actor_fingerprint', '" + actor + "', true), "
                + "set_config('app.action_id', 'session.activate', true), "
                + "set_config('app.reason_code', 'DIRECTORY_LOGIN', true)");
            s.execute("INSERT INTO login_record (actor_fingerprint, source, masked) VALUES ('" + actor
                + "', 'ldap', false)");
        }
    }
}
