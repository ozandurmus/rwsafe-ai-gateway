package io.rwsafe.persistence;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.jooq.exception.DataAccessException;
import org.jooq.impl.DSL;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** V12: directory settings versions, append-only, ledgered under the version number, the seed once and the guard. */
class DirectorySettingsStoreTest {

    private static final String ADMIN = "USR-00000000a1";
    private static final String SYSTEM = "system:deploy-seed";

    private Database db;

    @BeforeEach
    void open() {
        db = Database.migrateAndOpen(TestDatabase.fresh());
    }

    private static AuditContext audit(String actor, String action, String reason) {
        return new AuditContext(actor, action, reason, UUID.randomUUID().toString());
    }

    private static DirectorySettings settings(String actor, String kind, String reason, byte[] sealed,
                                              List<DirectorySettings.GroupRoles> groups) {
        return new DirectorySettings(0, null, actor, kind, reason, true, List.of("ldaps://synthetic-dc.example.test:636"),
            "ldaps", null, "cn=synthetic-service,dc=example,dc=test", sealed, "ou=synthetic-people,dc=example,dc=test",
            "(uid={0})", "memberOf", null, null, 5000, 10000, groups);
    }

    private static byte[] sealed() {
        byte[] b = new byte[40];
        b[0] = 1;
        return b;
    }

    private List<Map<String, Object>> ledger() {
        return db.dsl().select(Schema.AUDIT_ACTOR, Schema.AUDIT_ACTION, Schema.AUDIT_REASON, Schema.AUDIT_ROW_KEY,
                Schema.AUDIT_OPERATION).from(Schema.AUDIT_EVENT).where(Schema.AUDIT_TABLE.eq("directory_settings"))
            .orderBy(DSL.field(DSL.name("audit_event", "audit_id"))).fetchMaps();
    }

    @Test
    void eachSaveIsTheNextVersionAndIsLedgeredUnderItsNumber() {
        assertTrue(db.directorySettings().active().isEmpty());
        DirectorySettings first = db.directorySettings().save(settings(ADMIN, "connection", "a synthetic reason",
            sealed(), List.of()), 0, audit(ADMIN, "directory_settings.connection", "a synthetic reason"));
        assertEquals(1, first.version());
        assertArrayEquals(sealed(), first.bindPasswordSealed());
        DirectorySettings second = db.directorySettings().save(first.as("group_roles", ADMIN, "bind groups")
            .withGroups(List.of(new DirectorySettings.GroupRoles("synthetic-admins", List.of("security_admin",
                "viewer")), new DirectorySettings.GroupRoles("synthetic-auditors", List.of("replay_viewer")))), 1,
            audit(ADMIN, "directory_settings.group_roles", "bind groups"));
        assertEquals(2, second.version());
        DirectorySettings active = db.directorySettings().active().orElseThrow();
        assertEquals(2, active.version());
        assertEquals(List.of("security_admin", "viewer"), active.groupRoles().get(0).roles());
        assertEquals("synthetic-auditors", active.groupRoles().get(1).group());
        assertEquals(List.of(2, 1), db.directorySettings().history(10).stream()
            .map(DirectorySettingsStore.HistoryEntry::version).toList());

        List<Map<String, Object>> rows = ledger();
        assertEquals(2, rows.size());
        assertEquals("1", rows.get(0).get("row_key"));
        assertEquals("2", rows.get(1).get("row_key"));
        assertEquals(ADMIN, rows.get(1).get("actor_fingerprint"));
        assertEquals("directory_settings.group_roles", rows.get(1).get("action_id"));
        assertEquals("bind groups", rows.get(1).get("reason_code"));
        assertFalse(rows.toString().contains("synthetic-admins"), "the ledger never names a group");
        assertFalse(rows.toString().contains("example"), "the ledger never names the directory");
    }

    @Test
    void aSaveOnAStaleVersionIsRefusedAndChangesNothing() {
        db.directorySettings().save(settings(ADMIN, "connection", "r", null, List.of()), 0,
            audit(ADMIN, "directory_settings.connection", "r"));
        DirectorySettingsConflict e = assertThrows(DirectorySettingsConflict.class, () -> db.directorySettings()
            .save(settings(ADMIN, "connection", "r", null, List.of()), 0, audit(ADMIN, "directory_settings.connection",
                "r")));
        assertEquals("DIRECTORY_SETTINGS_CHANGED", e.reason());
        assertEquals(1, db.directorySettings().history(10).size());
        assertNull(db.directorySettings().active().orElseThrow().bindPasswordSealed());
    }

    @Test
    void theSeedFillsAnEmptyTableOnceAsTheSystemActor() {
        assertTrue(db.directorySettings().seedIfEmpty(settings(SYSTEM, "seed", "deploy seed", null, List.of()),
            audit(SYSTEM, "directory_settings.seed", "deploy seed")));
        assertFalse(db.directorySettings().seedIfEmpty(settings(SYSTEM, "seed", "deploy seed", null, List.of()),
            audit(SYSTEM, "directory_settings.seed", "deploy seed")));
        assertEquals(1, db.directorySettings().history(10).size());
        // A seed is never written over saved settings, and only the system actor seeds.
        assertThrows(DataAccessException.class, () -> db.directorySettings().save(settings(SYSTEM, "seed", "again",
            null, List.of()), 1, audit(SYSTEM, "directory_settings.seed", "again")));
        assertThrows(DataAccessException.class, () -> db.directorySettings().save(settings(ADMIN, "seed", "r", null,
            List.of()), 1, audit(ADMIN, "directory_settings.seed", "r")));
    }

    /** PR 50 review D-04 and D-07: the guard's further rules. */
    @Test
    void theGuardRefusesSystemEditsGroupsFirstRepeatedRolesAndEqualsSigns() {
        // The system actor only seeds.
        assertThrows(DataAccessException.class, () -> db.directorySettings().save(settings(SYSTEM, "connection", "r",
            null, List.of()), 0, audit(SYSTEM, "directory_settings.connection", "r")));
        // Group bindings never come first.
        assertThrows(DataAccessException.class, () -> db.directorySettings().save(settings(ADMIN, "group_roles", "r",
            null, List.of()), 0, audit(ADMIN, "directory_settings.group_roles", "r")));
        db.directorySettings().save(settings(ADMIN, "connection", "r", null, List.of()), 0,
            audit(ADMIN, "directory_settings.connection", "r"));
        assertThrows(DataAccessException.class, () -> db.directorySettings().save(settings(SYSTEM, "group_roles", "r",
            null, List.of()), 1, audit(SYSTEM, "directory_settings.group_roles", "r")));
        // Each role once; no '=' in a group name.
        assertThrows(DataAccessException.class, () -> db.directorySettings().save(settings(ADMIN, "group_roles", "r",
            null, List.of(new DirectorySettings.GroupRoles("synthetic", List.of("viewer", "viewer")))), 1,
            audit(ADMIN, "directory_settings.group_roles", "r")));
        assertThrows(DataAccessException.class, () -> db.directorySettings().save(settings(ADMIN, "group_roles", "r",
            null, List.of(new DirectorySettings.GroupRoles("synthetic=idari", List.of("viewer")))), 1,
            audit(ADMIN, "directory_settings.group_roles", "r")));
        DirectorySettings ok = db.directorySettings().save(settings(ADMIN, "group_roles", "r", null,
            List.of(new DirectorySettings.GroupRoles("synthetic", List.of("security_admin", "viewer")))), 1,
            audit(ADMIN, "directory_settings.group_roles", "r"));
        assertEquals(2, ok.version());
    }

    @Test
    void theHistoryIsImmutableAndTheGuardHoldsTheShape() {
        db.directorySettings().save(settings(ADMIN, "connection", "r", sealed(), List.of()), 0,
            audit(ADMIN, "directory_settings.connection", "r"));
        db.dsl().transaction(cfg -> {
            var tx = DSL.using(cfg);
            audit(ADMIN, "synthetic.tamper", "r").apply(tx);
            assertThrows(DataAccessException.class, () -> tx.update(Schema.DIRECTORY_SETTINGS)
                .set(Schema.DS_ENABLED, false).execute());
        });
        db.dsl().transaction(cfg -> {
            var tx = DSL.using(cfg);
            audit(ADMIN, "synthetic.tamper", "r").apply(tx);
            assertThrows(DataAccessException.class, () -> tx.deleteFrom(Schema.DIRECTORY_SETTINGS).execute());
        });
        assertThrows(DataAccessException.class, () -> db.dsl().truncate(Schema.DIRECTORY_SETTINGS).execute());
        // No audit context: refused. Another actor than the ledger's: refused.
        assertThrows(DataAccessException.class, () -> db.dsl().insertInto(Schema.DIRECTORY_SETTINGS)
            .set(Schema.DS_VERSION, 2).execute());
        assertThrows(DataAccessException.class, () -> db.directorySettings().save(settings("USR-00000000b2",
            "connection", "r", null, List.of()), 1, audit(ADMIN, "directory_settings.connection", "r")));
        // A group binding with a comma (a distinguished name) or the masked role with another: refused.
        assertThrows(DataAccessException.class, () -> db.directorySettings().save(settings(ADMIN, "group_roles", "r",
            null, List.of(new DirectorySettings.GroupRoles("cn=synthetic,dc=example", List.of("viewer")))), 1,
            audit(ADMIN, "directory_settings.group_roles", "r")));
        assertThrows(DataAccessException.class, () -> db.directorySettings().save(settings(ADMIN, "group_roles", "r",
            null, List.of(new DirectorySettings.GroupRoles("synthetic", List.of("replay_viewer", "viewer")))), 1,
            audit(ADMIN, "directory_settings.group_roles", "r")));
        assertThrows(DataAccessException.class, () -> db.directorySettings().save(settings(ADMIN, "group_roles", "r",
            null, List.of(new DirectorySettings.GroupRoles("synthetic", List.of("root")))), 1,
            audit(ADMIN, "directory_settings.group_roles", "r")));
        // A sealed value in another format: refused.
        assertThrows(DataAccessException.class, () -> db.directorySettings().save(settings(ADMIN, "connection", "r",
            new byte[40], List.of()), 1, audit(ADMIN, "directory_settings.connection", "r")));
        assertEquals(1, db.directorySettings().history(10).size());
        assertEquals(1, ledger().size());
    }
}
