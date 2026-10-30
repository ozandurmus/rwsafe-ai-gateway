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

    private void rawInsertWith(String actor, String action, String reason) {
        db.dsl().transaction(cfg -> {
            var tx = org.jooq.impl.DSL.using(cfg);
            if (actor != null) {
                tx.execute("SELECT set_config('app.actor_fingerprint', ?, true), set_config('app.action_id', ?, true), "
                    + "set_config('app.reason_code', ?, true)", actor, action, reason);
            }
            tx.insertInto(Schema.LOCAL_ACCOUNT, Schema.ACCOUNT_NAME, Schema.PASSWORD_HASH, Schema.ROLES)
                .values("breakglass", HASH, new String[] {"security_admin"}).execute();
        });
    }

    @Test
    void aMutationWithoutAValidAuditContextIsRefused() {
        assertThrows(IllegalArgumentException.class, () -> new AuditContext("", "", "", null));
        assertThrows(IllegalArgumentException.class, () -> new AuditContext("synthetic.person", "a", "b", null));
        for (String[] ctx : new String[][] {null, {"   ", "local_account.create", "FIRST_START"},
            {"system:bootstrap", " ", "FIRST_START"}, {"synthetic.person", "local_account.create", "FIRST_START"}}) {
            DataAccessException e = assertThrows(DataAccessException.class,
                () -> rawInsertWith(ctx == null ? null : ctx[0], ctx == null ? null : ctx[1], ctx == null ? null : ctx[2]));
            assertTrue(e.getMessage().contains("AUDIT_CONTEXT_MISSING"));
        }
        assertTrue(db.localAccounts().find("breakglass").isEmpty());
    }

    @Test
    void theLedgerCannotBeWrittenDirectlyAndAccountsCannotBeTruncated() {
        DataAccessException forged = assertThrows(DataAccessException.class, () -> db.dsl().insertInto(
                Schema.AUDIT_EVENT, Schema.AUDIT_ACTOR, Schema.AUDIT_ACTION, Schema.AUDIT_REASON, Schema.AUDIT_TABLE,
                Schema.AUDIT_OPERATION, Schema.AUDIT_ROW_KEY)
            .values("system:forged", "x", "y", "local_account", "INSERT", "breakglass").execute());
        assertTrue(forged.getMessage().contains("AUDIT_DIRECT_INSERT"));
        db.localAccounts().createIfAbsent(account(),
            new AuditContext("system:bootstrap", "local_account.create", "FIRST_START", null));
        assertThrows(DataAccessException.class, () -> db.dsl().truncate(Schema.LOCAL_ACCOUNT).execute());
        assertTrue(db.localAccounts().find("breakglass").isPresent());
    }

    @Test
    void theMaskedRoleIsNeverCombinedWithAnother() {
        AuditContext audit = new AuditContext("system:bootstrap", "local_account.create", "FIRST_START", null);
        assertThrows(DataAccessException.class, () -> db.localAccounts().createIfAbsent(
            new LocalAccount("synthetic-mixed", HASH, List.of("replay_viewer", "security_admin"), true), audit));
        assertTrue(db.localAccounts().createIfAbsent(
            new LocalAccount("synthetic-masked", HASH, List.of("replay_viewer"), true), audit));
    }

    @Test
    void signInsAreRecordedAndLedgered() {
        db.loginRecords().record("USR-0123456789", "local", false);
        db.loginRecords().record("USR-0123456789", "ldap", true);
        assertEquals(2, db.dsl().fetchCount(Schema.LOGIN_RECORD));
        assertEquals(1, db.dsl().fetchCount(Schema.AUDIT_EVENT, Schema.AUDIT_ACTION.eq("session.activate_masked")
            .and(Schema.AUDIT_ACTOR.eq("USR-0123456789")).and(Schema.AUDIT_TABLE.eq("login_record"))));
        assertThrows(DataAccessException.class, () -> db.dsl().deleteFrom(Schema.LOGIN_RECORD).execute());
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
