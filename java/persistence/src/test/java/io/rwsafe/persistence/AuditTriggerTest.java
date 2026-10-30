package io.rwsafe.persistence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.jooq.exception.DataAccessException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** C7: audited mutations need an audit context, the ledger row is written by the trigger, and the ledger is append-only. */
class AuditTriggerTest {

    private static final String HASH = "$2a$12$" + "x".repeat(53);

    private Database db;

    @BeforeEach
    void open() {
        db = Database.migrateAndOpen(TestDatabase.fresh());
    }

    private static LocalAccount account() {
        return new LocalAccount("breakglass", HASH, List.of("security_admin"), true);
    }

    @Test
    void aMutationWithoutAuditContextIsRefused() {
        DataAccessException e = assertThrows(DataAccessException.class, () -> db.localAccounts().createIfAbsent(account(),
            new AuditContext("", "", "", null)));
        assertTrue(e.getMessage().contains("AUDIT_CONTEXT_MISSING"));
        assertTrue(db.localAccounts().find("breakglass").isEmpty());
    }

    @Test
    void theTriggerWritesTheLedgerRow() {
        assertTrue(db.localAccounts().createIfAbsent(account(),
            new AuditContext("system:bootstrap", "local_account.create", "FIRST_START", "c-1")));
        assertFalse(db.localAccounts().createIfAbsent(account(),
            new AuditContext("system:bootstrap", "local_account.create", "FIRST_START", "c-2")));
        var rows = db.dsl().select(Schema.AUDIT_ACTOR, Schema.AUDIT_ACTION, Schema.AUDIT_REASON, Schema.AUDIT_TABLE,
            Schema.AUDIT_OPERATION, Schema.AUDIT_ROW_KEY).from(Schema.AUDIT_EVENT).fetch();
        assertEquals(1, rows.size());
        assertEquals("system:bootstrap", rows.get(0).get(Schema.AUDIT_ACTOR));
        assertEquals("local_account", rows.get(0).get(Schema.AUDIT_TABLE));
        assertEquals("INSERT", rows.get(0).get(Schema.AUDIT_OPERATION));
        assertEquals("breakglass", rows.get(0).get(Schema.AUDIT_ROW_KEY));
        assertEquals(List.of("security_admin"), db.localAccounts().find("breakglass").orElseThrow().roles());
    }

    @Test
    void theLedgerIsAppendOnly() {
        db.localAccounts().createIfAbsent(account(),
            new AuditContext("system:bootstrap", "local_account.create", "FIRST_START", null));
        assertThrows(DataAccessException.class, () -> db.dsl().update(Schema.AUDIT_EVENT)
            .set(Schema.AUDIT_ACTOR, "someone-else").execute());
        assertThrows(DataAccessException.class, () -> db.dsl().deleteFrom(Schema.AUDIT_EVENT).execute());
        assertThrows(DataAccessException.class, () -> db.dsl().truncate(Schema.AUDIT_EVENT).execute());
        assertEquals(1, db.dsl().fetchCount(Schema.AUDIT_EVENT));
    }

    @Test
    void unknownRolesAndPlainPasswordsAreRefusedByTheTable() {
        AuditContext audit = new AuditContext("system:bootstrap", "local_account.create", "FIRST_START", null);
        assertThrows(DataAccessException.class, () -> db.localAccounts().createIfAbsent(
            new LocalAccount("breakglass", HASH, List.of("root"), true), audit));
        assertThrows(DataAccessException.class, () -> db.localAccounts().createIfAbsent(
            new LocalAccount("breakglass", "synthetic-password", List.of("viewer"), true), audit));
    }
}
