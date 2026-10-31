package io.rwsafe.persistence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import javax.sql.DataSource;
import org.flywaydb.core.Flyway;
import org.jooq.DSLContext;
import org.jooq.SQLDialect;
import org.jooq.exception.DataAccessException;
import org.jooq.impl.DSL;
import org.junit.jupiter.api.Test;

/**
 * V9 on a database that already holds V3 withdrawal requests (PO decision Q-41, 2026-10-31): a pending request stops
 * counting (ledgered as the migration's change) and can never be activated; an active request and the version it
 * withdrew keep their history. Raw SQL at V8, because the store reads the V9 columns.
 */
class SingleAdminWithdrawalMigrationTest {

    private static final String ADMIN = "USR-00000000a1";
    private static final String OFFICER = "USR-00000000b2";

    @Test
    void aPendingV3RequestIsSupersededAndAnActiveOneKeepsItsHistory() {
        DataSource ds = TestDatabase.fresh();
        Flyway.configure().dataSource(ds).locations("classpath:db/migration").target("8").load().migrate();
        DSLContext dsl = DSL.using(ds, SQLDialect.POSTGRES);
        String row = "INSERT INTO policy_rule_version (rule_id, version, kind, data_class, action, mode, rollout_stage, "
            + "status, source, author_fingerprint, reason_code, scope_kind, scope_groups, withdraws_version, "
            + "withdrawal_reason, activated_at) VALUES ('class.%s', %d, 'class_action', '%s', '%s', 'enforce', 'all', "
            + "'%s', '%s', '%s', '%s', '%s', %s, %s, %s, %s)";
        as(dsl, "system:seed-fixture", "SEED_FIXTURE",
            String.format(row, "TCKN", 1, "TCKN", "REDACT", "active", "seed", "system:seed-fixture", "SEED_FIXTURE",
                "ANY", "'{}'", "NULL", "NULL", "now()"),
            String.format(row, "SECRET", 1, "SECRET", "BLOCK", "active", "seed", "system:seed-fixture", "SEED_FIXTURE",
                "ANY", "'{}'", "NULL", "NULL", "now()"));
        // class.TCKN v2 (grp-alpha) and class.SECRET v2 (grp-beta), active with two approvals each.
        for (String[] g : new String[][] {{"TCKN", "grp-alpha"}, {"SECRET", "grp-beta"}}) {
            as(dsl, ADMIN, "SYNTHETIC_CHANGE", String.format(row, g[0], 2, g[0], "BLOCK", "pending", "registry", ADMIN,
                "SYNTHETIC_CHANGE", "GROUPS", "ARRAY['" + g[1] + "']", "NULL", "NULL", "NULL"));
            approveAndActivate(dsl, g[0], 2);
        }
        // class.TCKN v3: a pending request with one approval; class.SECRET v3: an approved request (v2 withdrawn).
        as(dsl, ADMIN, "Synthetic", String.format(row, "TCKN", 3, "TCKN", "BLOCK", "pending", "registry", ADMIN,
            "SCOPE_WITHDRAWAL", "GROUPS", "ARRAY['grp-alpha']", "2", "'Synthetic'", "NULL"));
        as(dsl, ADMIN, "SYNTHETIC_CHANGE", "INSERT INTO policy_approval (rule_id, version, approver_role, "
            + "approver_fingerprint) VALUES ('class.TCKN', 3, 'security_admin', '" + ADMIN + "')");
        as(dsl, ADMIN, "Synthetic", String.format(row, "SECRET", 3, "SECRET", "BLOCK", "pending", "registry", ADMIN,
            "SCOPE_WITHDRAWAL", "GROUPS", "ARRAY['grp-beta']", "2", "'Synthetic'", "NULL"));
        // The V3 store activated the request and withdrew its target in one transaction (the one-active-per-scope
        // exclusion is checked at commit).
        approveAndActivate(dsl, "SECRET", 3, "UPDATE policy_rule_version SET status = 'withdrawn', withdrawn_at = now() "
            + "WHERE rule_id = 'class.SECRET' AND version = 2");

        Database db = Database.migrateAndOpen(ds);
        PolicyRegistryStore registry = db.policyRegistry();
        assertEquals("superseded", registry.version("class.TCKN", 3).orElseThrow().status());
        assertEquals(1, db.dsl().fetchCount(Schema.AUDIT_EVENT, Schema.AUDIT_ACTION.eq("policy.withdraw_request_retired")
            .and(Schema.AUDIT_ACTOR.eq("system:migration")).and(Schema.AUDIT_ROW_KEY.eq("class.TCKN@v3"))));
        assertEquals("active", registry.version("class.TCKN", 2).orElseThrow().status(), "nothing was withdrawn");
        assertEquals("POLICY_NOT_PENDING", assertThrows(RegistryConflict.class, () -> registry.approve("class.TCKN", 3,
            "privacy_officer", OFFICER, new AuditContext(OFFICER, "policy.approve", "SYNTHETIC_CHANGE", null),
            new AuditContext("system:policy-registry", "policy.activate", "SYNTHETIC_CHANGE", null), a -> { }))
            .reason(), "the second approval of the old request can never complete it");

        PolicyRuleVersion marker = registry.version("class.SECRET", 3).orElseThrow();
        assertEquals("active", marker.status());
        assertEquals(2, marker.withdrawsVersion());
        PolicyRuleVersion old = registry.version("class.SECRET", 2).orElseThrow();
        assertEquals("withdrawn", old.status());
        assertEquals(null, old.withdrawnBy(), "a V3 withdrawal names no administrator on the row");
        assertTrue(registry.active().stream().noneMatch(v -> v.key().equals("class.SECRET@v2")));
        assertEquals("WITHDRAWAL_NOT_APPLICABLE", assertThrows(RegistryConflict.class, () -> registry.withdrawScope(
            "class.SECRET", 3, ADMIN, "Synthetic", new AuditContext(ADMIN, "policy.scope_withdraw", "Synthetic", null),
            a -> { })).reason(), "a V3 request marker is history, not a scope to withdraw");
        DataAccessException retime = assertThrows(DataAccessException.class, () -> as(db.dsl(), ADMIN, "Synthetic",
            "UPDATE policy_rule_version SET withdrawal_reason = 'rewritten' WHERE rule_id = 'class.SECRET' "
                + "AND version = 3"));
        assertTrue(retime.getMessage().contains("POLICY_WITHDRAWN_FINAL"), retime.getMessage());
        assertEquals(List.of("class.SECRET@v1", "class.SECRET@v3", "class.TCKN@v1", "class.TCKN@v2"),
            registry.active().stream().map(PolicyRuleVersion::key).sorted().toList());
    }

    private static void approveAndActivate(DSLContext dsl, String dataClass, int version, String... then) {
        String approval = "INSERT INTO policy_approval (rule_id, version, approver_role, approver_fingerprint) VALUES "
            + "('class." + dataClass + "', " + version + ", '%s', '%s')";
        List<String> sql = new java.util.ArrayList<>(List.of(String.format(approval, "security_admin", ADMIN),
            String.format(approval, "privacy_officer", OFFICER),
            "UPDATE policy_rule_version SET status = 'active', activated_at = now() WHERE rule_id = 'class." + dataClass
                + "' AND version = " + version));
        sql.addAll(List.of(then));
        as(dsl, ADMIN, "SYNTHETIC_CHANGE", sql.toArray(String[]::new));
    }

    private static void as(DSLContext dsl, String actor, String reason, String... sql) {
        dsl.transaction(cfg -> {
            DSLContext tx = DSL.using(cfg);
            new AuditContext(actor, "synthetic.mutation", reason, null).apply(tx);
            for (String s : sql) {
                tx.execute(s);
            }
        });
    }
}
