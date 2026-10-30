package io.rwsafe.persistence;

import static io.rwsafe.persistence.Events.event;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.persistence.SiemExportStore.ExportVerdict;
import io.rwsafe.persistence.SiemExportStore.LedgerRow;
import io.rwsafe.persistence.SiemExportStore.Watermark;
import io.rwsafe.platform.verdict.Verdict;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SiemExportStoreTest {

    private static final String HASH = "$2a$12$" + "y".repeat(53);
    private DataSource ds;
    private Database db;
    private final Instant base = Instant.now().minusSeconds(60);

    @BeforeEach
    void open() {
        ds = TestDatabase.fresh();
        db = Database.migrateAndOpen(ds);
    }

    @Test
    void verdictEventsAreReadInIngestionOrderAfterTheWatermarkWithTheirFindings() {
        db.verdictEvents().insert(List.of(event(base, "claude", Verdict.REDACT, List.of(new FindingCount("TCKN", 2)))));
        db.verdictEvents().insert(List.of(event(base, "openai", Verdict.ALLOW, List.of()),
            event(base, "openai", Verdict.BLOCK, List.of(new FindingCount("SECRET", 1)))));
        SiemExportStore store = db.siemExport();

        List<ExportVerdict> all = new ArrayList<>();
        SiemExportStore.VerdictPosition after = null;
        for (int page = 0; page < 5; page++) {
            List<ExportVerdict> got = store.verdictsAfter(after, Duration.ZERO, 2);
            if (got.isEmpty()) {
                break;
            }
            all.addAll(got);
            after = got.get(got.size() - 1).position();
        }
        assertEquals(3, all.size(), "keyset pages cover every event exactly once");
        assertEquals("claude", all.get(0).event().platform(), "the first transaction's event comes first");
        assertEquals(List.of(new FindingCount("TCKN", 2)), all.get(0).event().findings());
        assertTrue(store.verdictsAfter(after, Duration.ZERO, 10).isEmpty());
        assertTrue(store.verdictsAfter(null, Duration.ofHours(1), 10).isEmpty(),
            "rows younger than the settle window are not read yet");
    }

    @Test
    void ledgerRowsAreReadInIdOrderWithAPseudonymousActor() {
        db.localAccounts().createIfAbsent(new LocalAccount("synthetic-glass", HASH, List.of("security_admin"), true),
            new AuditContext("system:bootstrap", "local_account.create", "FIRST_START", null));
        db.loginRecords().record("USR-0123456789", "local", false);
        List<LedgerRow> rows = db.siemExport().ledgerAfter(0, Duration.ZERO, 10);
        assertEquals(2, rows.size());
        assertTrue(rows.get(0).auditId() < rows.get(1).auditId());
        assertEquals("system:bootstrap", rows.get(0).actorFingerprint());
        assertEquals("local_account", rows.get(0).tableName());
        assertEquals("USR-0123456789", rows.get(1).actorFingerprint());
        assertTrue(!rows.get(0).toString().contains("synthetic-glass"), "toString never prints the row key");
        assertEquals(1, db.siemExport().ledgerAfter(rows.get(0).auditId(), Duration.ZERO, 10).size());
    }

    @Test
    void theWatermarkRoundTripsAndLatestSkipsTheBacklog() {
        SiemExportStore store = db.siemExport();
        assertTrue(store.watermark("hec").isEmpty());
        db.verdictEvents().insert(List.of(event(base, "claude", Verdict.ALLOW, List.of())));
        db.loginRecords().record("USR-0123456789", "ldap", false);
        assertEquals(2, store.backlog(Watermark.START, Duration.ZERO));

        Watermark latest = store.latest(Duration.ZERO);
        assertEquals(0, store.backlog(latest, Duration.ZERO));
        store.saveWatermark("hec", latest);
        assertEquals(latest, store.watermark("hec").orElseThrow());
        store.saveWatermark("hec", Watermark.START);
        Watermark back = store.watermark("hec").orElseThrow();
        assertNull(back.verdict());
        assertEquals(0, back.auditId());
    }

    @Test
    void theWatermarkTableRefusesAnUnknownDestinationAndAHalfPosition() throws SQLException {
        try (Connection c = ds.getConnection(); Statement s = c.createStatement()) {
            assertThrows(SQLException.class, () -> s.execute(
                "INSERT INTO siem_watermark (destination) VALUES ('udp')"));
            assertThrows(SQLException.class, () -> s.execute(
                "INSERT INTO siem_watermark (destination, verdict_ingested_at) VALUES ('hec', now())"));
        }
    }
}
