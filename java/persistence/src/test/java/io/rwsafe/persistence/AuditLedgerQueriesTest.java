package io.rwsafe.persistence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.persistence.AuditLedgerQueries.LedgerFilter;
import io.rwsafe.persistence.AuditLedgerQueries.LedgerPage;
import io.rwsafe.persistence.SiemExportStore.LedgerRow;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Administration -> Records -> Audit log (PO decision Q-47 decision 1.3): newest first, filtered, keyset-paged. */
class AuditLedgerQueriesTest {

    private static final String HASH = "$2a$12$" + "x".repeat(53);
    private static final Instant FROM = Instant.now().minus(1, ChronoUnit.HOURS);
    private static final Instant TO = Instant.now().plus(1, ChronoUnit.HOURS);

    private Database db;

    @BeforeEach
    void open() {
        db = Database.migrateAndOpen(TestDatabase.fresh());
        for (int i = 0; i < 5; i++) {
            db.localAccounts().createIfAbsent(new LocalAccount("synthetic-acct" + i, HASH, List.of("viewer"), true),
                new AuditContext(i % 2 == 0 ? "system:bootstrap" : "USR-00000000a" + i, "local_account.create",
                    "FIRST_START", null));
        }
        db.loginRecords().record("USR-0123456789", "local", false);
    }

    @Test
    void pagesAreNewestFirstAndContinueWithTheCursor() {
        LedgerPage first = db.auditLedger().page(new LedgerFilter(FROM, TO, null, null, 4, null));
        assertEquals(4, first.rows().size());
        List<Long> ids = new ArrayList<>(first.rows().stream().map(LedgerRow::auditId).toList());
        assertTrue(ids.get(0) > ids.get(1) && ids.get(1) > ids.get(2), "newest first");
        assertEquals(ids.get(3), first.nextBefore());
        LedgerPage second = db.auditLedger().page(new LedgerFilter(FROM, TO, null, null, 4, first.nextBefore()));
        assertEquals(2, second.rows().size());
        assertNull(second.nextBefore(), "no older row");
        second.rows().forEach(r -> ids.add(r.auditId()));
        assertEquals(6, new TreeSet<>(ids).size(), "no row twice, none skipped");
    }

    @Test
    void filtersByActionActorAndTime() {
        assertEquals(5, db.auditLedger().page(new LedgerFilter(FROM, TO, "local_account.create", null, 50, null))
            .rows().size());
        List<LedgerRow> system = db.auditLedger().page(new LedgerFilter(FROM, TO, null, "system:bootstrap", 50, null))
            .rows();
        assertEquals(3, system.size());
        system.forEach(r -> assertEquals("system:bootstrap", r.actorFingerprint()));
        assertEquals(0, db.auditLedger().page(new LedgerFilter(TO, TO.plusSeconds(60), null, null, 50, null))
            .rows().size());
        List<String> actions = db.auditLedger().actionIds();
        assertTrue(actions.containsAll(List.of("local_account.create", "session.activate")), String.valueOf(actions));
        assertEquals(new ArrayList<>(new TreeSet<>(actions)), actions, "sorted and distinct");
        assertThrows(IllegalArgumentException.class, () -> new LedgerFilter(FROM, TO, null, null, 0, null));
        assertThrows(IllegalArgumentException.class,
            () -> new LedgerFilter(FROM, TO, null, null, AuditLedgerQueries.MAX_PAGE + 1, null));
    }

    /** The ledger has no column that could hold a prompt, a response or a request body: only these. */
    @Test
    void theLedgerHoldsNoBodyColumn() {
        Set<String> columns = new TreeSet<>(db.dsl().fetch("SELECT column_name FROM information_schema.columns "
            + "WHERE table_schema = current_schema() AND table_name = 'audit_event'").getValues(0, String.class));
        assertEquals(new TreeSet<>(Set.of("audit_id", "occurred_at", "actor_fingerprint", "action_id", "reason_code",
            "correlation_id", "table_name", "operation", "row_key", "tx_id")), columns);
    }
}
