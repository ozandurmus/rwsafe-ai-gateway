package io.rwsafe.persistence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.jooq.exception.DataAccessException;
import org.jooq.impl.DSL;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** V11: local users, their ledger under the pseudonym, the last-administrator guard and the ended-session record. */
class LocalUserStoreTest {

    private static final String HASH = "$2a$12$" + "y".repeat(53);
    private static final String ADMIN = "USR-00000000a1";
    private static final String OTHER = "USR-00000000b2";

    private Database db;

    @BeforeEach
    void open() {
        db = Database.migrateAndOpen(TestDatabase.fresh());
    }

    private static AuditContext audit(String action, String reason) {
        return new AuditContext(ADMIN, action, reason, UUID.randomUUID().toString());
    }

    private static LocalUser user(String login, String subject, List<String> roles) {
        return new LocalUser(login, subject, "Synthetic Person", HASH, roles, true, true, null, null, null);
    }

    private List<Map<String, Object>> ledger(String table) {
        return db.dsl().select(Schema.AUDIT_ACTOR, Schema.AUDIT_ACTION, Schema.AUDIT_REASON, Schema.AUDIT_ROW_KEY,
                Schema.AUDIT_OPERATION).from(Schema.AUDIT_EVENT).where(Schema.AUDIT_TABLE.eq(table))
            .orderBy(DSL.field(DSL.name("audit_event", "audit_id"))).fetchMaps();
    }

    @Test
    void aCreatedUserIsLedgeredUnderItsPseudonymNeverItsLoginName() {
        LocalUser created = db.localUsers().create(user("synthetic.person", OTHER, List.of("viewer")),
            audit("local_user.create", "a synthetic reason"));
        assertTrue(created.mustChangePassword());
        assertTrue(created.enabled());
        assertTrue(created.createdAt() != null);
        List<Map<String, Object>> rows = ledger("local_user");
        assertEquals(1, rows.size());
        assertEquals(OTHER, rows.get(0).get("row_key"));
        assertEquals(ADMIN, rows.get(0).get("actor_fingerprint"));
        assertEquals("a synthetic reason", rows.get(0).get("reason_code"));
        assertFalse(created.toString().contains("synthetic.person"));
        assertFalse(created.toString().contains(HASH));

        LocalUserConflict twice = assertThrows(LocalUserConflict.class, () -> db.localUsers().create(
            user("synthetic.person", "USR-00000000c3", List.of("viewer")), audit("local_user.create", "again")));
        assertEquals("LOCAL_USER_EXISTS", twice.reason());
    }

    @Test
    void theTableRefusesBadShapesDeletesAndIdentityChanges() {
        for (LocalUser bad : List.of(user("breakglass", OTHER, List.of("viewer")),
            user("Synthetic", OTHER, List.of("viewer")),
            user("synthetic.person", "synthetic.person", List.of("viewer")),
            user("synthetic.person", OTHER, List.of("replay_viewer", "viewer")),
            user("synthetic.person", OTHER, List.of("superuser")))) {
            assertThrows(DataAccessException.class, () -> db.localUsers().create(bad, audit("local_user.create", "r")));
        }
        db.localUsers().create(user("synthetic.person", OTHER, List.of("viewer")), audit("local_user.create", "r"));
        DataAccessException delete = assertThrows(DataAccessException.class, () -> db.dsl().transaction(cfg -> {
            audit("local_user.delete", "r").apply(DSL.using(cfg));
            DSL.using(cfg).deleteFrom(Schema.LOCAL_USER).execute();
        }));
        assertTrue(delete.getMessage().contains("LOCAL_USER_KEPT"));
        DataAccessException rename = assertThrows(DataAccessException.class, () -> db.dsl().transaction(cfg -> {
            audit("local_user.rename", "r").apply(DSL.using(cfg));
            DSL.using(cfg).update(Schema.LOCAL_USER).set(Schema.LU_LOGIN, "synthetic.other").execute();
        }));
        assertTrue(rename.getMessage().contains("LOCAL_USER_IDENTITY_FIXED"));
        assertThrows(DataAccessException.class, () -> db.dsl().update(Schema.LOCAL_USER)
            .set(Schema.LU_ENABLED, false).execute(), "an update without an audit context");
    }

    /** PR 48 review D-07: a whole cost-12 hash, a generated password first, the change mark cleared only by a change. */
    @Test
    void thePasswordStateFollowsTheRules() {
        for (String weak : List.of("$2", "$2a$04$" + "y".repeat(53), "$2a$12$" + "y".repeat(52), "$1$" + "y".repeat(57))) {
            assertThrows(DataAccessException.class, () -> db.localUsers().create(new LocalUser("synthetic.weak", OTHER,
                "Synthetic Person", weak, List.of("viewer"), true, true, null, null, null), audit("local_user.create",
                "r")), weak.substring(0, 2));
        }
        DataAccessException set = assertThrows(DataAccessException.class, () -> db.localUsers().create(
            new LocalUser("synthetic.preset", OTHER, "Synthetic Person", HASH, List.of("viewer"), true, false, null,
                null, null), audit("local_user.create", "r")));
        assertTrue(set.getMessage().contains("LOCAL_USER_PASSWORD_STATE"));

        db.localUsers().create(user("synthetic.person", OTHER, List.of("viewer")), audit("local_user.create", "r"));
        DataAccessException noChange = assertThrows(DataAccessException.class, () -> db.localUsers().update(
            "synthetic.person", u -> new LocalUser(u.loginName(), u.subjectFingerprint(), u.displayName(),
                u.passwordHash(), u.roles(), true, false, null, null, java.time.Instant.now()), true,
            audit("local_user.password_change", "r")));
        assertTrue(noChange.getMessage().contains("LOCAL_USER_PASSWORD_STATE"));
        String other = "$2b$12$" + "z".repeat(53);
        DataAccessException noTime = assertThrows(DataAccessException.class, () -> db.localUsers().update(
            "synthetic.person", u -> new LocalUser(u.loginName(), u.subjectFingerprint(), u.displayName(), other,
                u.roles(), true, false, null, null, null), true, audit("local_user.password_change", "r")));
        assertTrue(noTime.getMessage().contains("LOCAL_USER_PASSWORD_STATE"), "a cleared mark needs the change time");
        LocalUser changed = db.localUsers().update("synthetic.person", u -> new LocalUser(u.loginName(),
            u.subjectFingerprint(), u.displayName(), other, u.roles(), true, false, null, null,
            java.time.Instant.now()), true, audit("local_user.password_change", "r"));
        assertFalse(changed.mustChangePassword());
        DataAccessException cleared = assertThrows(DataAccessException.class, () -> db.localUsers().update(
            "synthetic.person", u -> new LocalUser(u.loginName(), u.subjectFingerprint(), u.displayName(), HASH,
                u.roles(), true, true, null, null, null), true, audit("local_user.password_reset", "r")));
        assertTrue(cleared.getMessage().contains("LOCAL_USER_PASSWORD_STATE"));
    }

    @Test
    void theLastEnabledSecurityAdministratorStays() {
        db.localUsers().create(user("synthetic.admin", ADMIN, List.of("security_admin")), audit("local_user.create", "r"));
        LocalUserConflict disable = assertThrows(LocalUserConflict.class, () -> db.localUsers().update(
            "synthetic.admin", u -> new LocalUser(u.loginName(), u.subjectFingerprint(), u.displayName(),
                u.passwordHash(), u.roles(), false, u.mustChangePassword(), null, null, null), false,
            audit("local_user.disable", "r")));
        assertEquals("LAST_SECURITY_ADMIN", disable.reason());
        LocalUserConflict demote = assertThrows(LocalUserConflict.class, () -> db.localUsers().update(
            "synthetic.admin", u -> withRoles(u, List.of("viewer")), false, audit("local_user.roles_change", "r")));
        assertEquals("LAST_SECURITY_ADMIN", demote.reason());
        assertEquals(List.of("security_admin"), db.localUsers().find("synthetic.admin").orElseThrow().roles());

        // A break-glass administrator counts when the caller says it may sign in.
        db.localAccounts().createIfAbsent(new LocalAccount("breakglass", HASH, List.of("security_admin"), true),
            new AuditContext("system:bootstrap", "local_account.create", "FIRST_START", null));
        assertEquals(1, db.localUsers().enabledAdmins(false));
        assertEquals(2, db.localUsers().enabledAdmins(true));
        LocalUser demoted = db.localUsers().update("synthetic.admin", u -> withRoles(u, List.of("viewer")), true,
            audit("local_user.roles_change", "r"));
        assertEquals(List.of("viewer"), demoted.roles());
        LocalUserConflict missing = assertThrows(LocalUserConflict.class, () -> db.localUsers().update(
            "synthetic.nobody", u -> u, true, audit("local_user.disable", "r")));
        assertEquals("LOCAL_USER_NOT_FOUND", missing.reason());
    }

    @Test
    void anEndedSessionIsLedgeredWithTheAdministratorAsActor() {
        db.localUsers().recordSessionEnd(OTHER, ADMIN, "ldap", audit("session.end", "a synthetic reason"));
        List<Map<String, Object>> rows = ledger("session_end");
        assertEquals(1, rows.size());
        assertEquals(OTHER, rows.get(0).get("row_key"));
        assertEquals("session.end", rows.get(0).get("action_id"));
        DataAccessException forged = assertThrows(DataAccessException.class, () -> db.localUsers().recordSessionEnd(
            OTHER, "USR-00000000c3", "ldap", audit("session.end", "r")));
        assertTrue(forged.getMessage().contains("SESSION_END_ACTOR"));
    }

    @Test
    void aLocalUserSignInIsRecorded() {
        db.loginRecords().record(OTHER, "local_user", false);
        assertEquals("LOCAL_USER_LOGIN", ledger("login_record").get(0).get("reason_code"));
    }

    private static LocalUser withRoles(LocalUser u, List<String> roles) {
        return new LocalUser(u.loginName(), u.subjectFingerprint(), u.displayName(), u.passwordHash(), roles,
            u.enabled(), u.mustChangePassword(), null, null, u.passwordChangedAt());
    }
}
