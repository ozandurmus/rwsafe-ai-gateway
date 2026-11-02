package io.rwsafe.persistence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.persistence.PolicyRuleVersion.Draft;
import java.util.List;
import org.jooq.exception.DataAccessException;
import org.jooq.impl.DSL;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * V10, the pilot single-approval activation (PO decision Q-47, decision 2): one security_admin's approval with a reason
 * activates a version only through the store's single-approval path, recorded on the version and in the ledger; the
 * database refuses every other one-approval activation and every later edit of the record.
 */
class SingleApprovalActivationTest {

    private static final String ADMIN = "USR-00000000a1";
    private static final String OFFICER = "USR-00000000b2";
    private static final String REASON = "Synthetic pilot change";

    private Database db;
    private PolicyRegistryStore registry;

    @BeforeEach
    void open() {
        db = Database.migrateAndOpen(TestDatabase.fresh());
        registry = db.policyRegistry();
        assertTrue(registry.seed(List.of(
            classRule("SECRET", "BLOCK", "system:seed-fixture"),
            classRule("TCKN", "REDACT", "system:seed-fixture"),
            new Draft("platform.claude", "platform", null, null, "claude", List.of("claude.ai"), List.of(), List.of(),
                null, "enforce", "all", "system:seed-fixture", "SEED_FIXTURE"),
            new Draft("flow.ai-category", "flow", null, null, null, null, null, null, true, "enforce", "all",
                "system:seed-fixture", "SEED_FIXTURE")), audit("system:seed-fixture", "policy.seed")));
        registry.draft(classRule("TCKN", "BLOCK", ADMIN), audit(ADMIN, "policy.draft"));
    }

    private static Draft classRule(String dataClass, String action, String author) {
        return new Draft("class." + dataClass, "class_action", dataClass, action, null, null, null, null, null,
            "enforce", "all", author, author.startsWith("system:") ? "SEED_FIXTURE" : "SYNTHETIC_CHANGE");
    }

    private static AuditContext audit(String actor, String action) {
        return new AuditContext(actor, action, "SYNTHETIC_CHANGE", null);
    }

    private static PolicyRegistryStore.SingleApproval single(String actor, String reason) {
        return new PolicyRegistryStore.SingleApproval(reason,
            new AuditContext(actor, PolicyRegistryStore.ACTION_SINGLE_APPROVAL, reason, null));
    }

    private PolicyRuleVersion approve(String role, String who, PolicyRegistryStore.SingleApproval single) {
        return registry.approve("class.TCKN", 2, role, who, audit(who, "policy.approve"),
            audit(who, "policy.activate"), single, active -> { });
    }

    @Test
    void oneSecurityAdministratorActivatesAloneAndTheVersionAndTheLedgerSaySo() {
        PolicyRuleVersion active = approve("security_admin", ADMIN, single(ADMIN, REASON));
        assertEquals("active", active.status());
        assertEquals(1, active.approvals().size());
        assertEquals(new PolicyRuleVersion.SingleApproval(ADMIN, REASON), active.singleApproval());
        assertEquals("superseded", registry.version("class.TCKN", 1).orElseThrow().status());
        assertEquals(1, db.dsl().fetchCount(Schema.AUDIT_EVENT, Schema.AUDIT_TABLE.eq("policy_rule_version")
            .and(Schema.AUDIT_OPERATION.eq("UPDATE")).and(Schema.AUDIT_ROW_KEY.eq("class.TCKN@v2"))
            .and(Schema.AUDIT_ACTION.eq(PolicyRegistryStore.ACTION_SINGLE_APPROVAL))
            .and(Schema.AUDIT_ACTOR.eq(ADMIN)).and(Schema.AUDIT_REASON.eq(REASON))));
        assertEquals(0, db.dsl().fetchCount(Schema.AUDIT_EVENT, Schema.AUDIT_ACTION.eq("policy.activate")));
        assertNull(registry.version("class.TCKN", 1).orElseThrow().singleApproval());
    }

    @Test
    void withoutTheSwitchOneApprovalLeavesTheVersionPending() {
        PolicyRuleVersion once = approve("security_admin", ADMIN, null);
        assertEquals("pending", once.status());
        assertNull(once.singleApproval());
    }

    @Test
    void aPrivacyOfficersApprovalNeverActivatesAlone() {
        assertEquals("SINGLE_APPROVAL_NOT_AVAILABLE", assertThrows(RegistryConflict.class,
            () -> approve("privacy_officer", OFFICER, single(OFFICER, REASON))).reason());
        PolicyRuleVersion still = registry.version("class.TCKN", 2).orElseThrow();
        assertEquals("pending", still.status());
        assertTrue(still.approvals().isEmpty(), "the refused approval was rolled back");
        PolicyRuleVersion once = approve("privacy_officer", OFFICER, null);
        assertEquals("pending", once.status());
        assertNull(once.singleApproval());
    }

    /** PR 47 review D-03: the second of two approvals never carries (and never silently drops) a reason. */
    @Test
    void aVersionTheOtherRoleApprovedIsActivatedByTheTwoApprovalsAsBefore() {
        approve("privacy_officer", OFFICER, null);
        assertEquals("SINGLE_APPROVAL_NOT_AVAILABLE", assertThrows(RegistryConflict.class,
            () -> approve("security_admin", ADMIN, single(ADMIN, REASON))).reason());
        assertEquals(1, registry.version("class.TCKN", 2).orElseThrow().approvals().size());
        PolicyRuleVersion active = approve("security_admin", ADMIN, null);
        assertEquals("active", active.status());
        assertEquals(2, active.approvals().size());
        assertNull(active.singleApproval(), "two approvals: an ordinary activation");
        assertEquals(0, db.dsl().fetchCount(Schema.AUDIT_EVENT,
            Schema.AUDIT_ACTION.eq(PolicyRegistryStore.ACTION_SINGLE_APPROVAL)));
    }

    @Test
    void theLedgerMustNameTheAdministratorTheActionAndTheReason() {
        assertEquals("POLICY_SINGLE_APPROVAL_REFUSED", assertThrows(RegistryConflict.class, () -> approve(
            "security_admin", ADMIN, new PolicyRegistryStore.SingleApproval(REASON,
                new AuditContext(ADMIN, PolicyRegistryStore.ACTION_SINGLE_APPROVAL, "Another reason", null))))
            .reason());
        assertEquals("POLICY_SINGLE_APPROVAL_REFUSED", assertThrows(RegistryConflict.class, () -> approve(
            "security_admin", ADMIN, new PolicyRegistryStore.SingleApproval(REASON,
                new AuditContext(ADMIN, "policy.activate", REASON, null)))).reason());
        assertEquals("POLICY_SINGLE_APPROVAL_REFUSED", assertThrows(RegistryConflict.class, () -> approve(
            "security_admin", ADMIN, single(OFFICER, REASON))).reason());
        PolicyRuleVersion still = registry.version("class.TCKN", 2).orElseThrow();
        assertEquals("pending", still.status());
        assertTrue(still.approvals().isEmpty(), "the refused activation rolled the approval back");
    }

    @Test
    void theDatabaseRefusesASingleApprovalActivationTheSwitchDidNotDeclare() {
        approve("security_admin", ADMIN, null);
        // The right record and ledger, but no app.single_approval = 'on' in the transaction.
        DataAccessException undeclared = assertThrows(DataAccessException.class, () -> db.dsl().transaction(cfg -> {
            var tx = DSL.using(cfg);
            new AuditContext(ADMIN, PolicyRegistryStore.ACTION_SINGLE_APPROVAL, REASON, null).apply(tx);
            tx.execute("UPDATE policy_rule_version SET status = 'active', activated_at = now(), single_approval_by = '"
                + ADMIN + "', single_approval_reason = '" + REASON + "' WHERE rule_id = 'class.TCKN' AND version = 2");
        }));
        assertTrue(undeclared.getMessage().contains("POLICY_SINGLE_APPROVAL_REFUSED"));
        // Declared, but without the record: the two-approval rule applies.
        DataAccessException unrecorded = assertThrows(DataAccessException.class, () -> db.dsl().transaction(cfg -> {
            var tx = DSL.using(cfg);
            new AuditContext(ADMIN, PolicyRegistryStore.ACTION_SINGLE_APPROVAL, REASON, null).apply(tx);
            tx.execute("SELECT set_config('app.single_approval', 'on', true)");
            tx.execute("UPDATE policy_rule_version SET status = 'active', activated_at = now() "
                + "WHERE rule_id = 'class.TCKN' AND version = 2");
        }));
        assertTrue(unrecorded.getMessage().contains("POLICY_APPROVAL_REQUIRED"));
        assertEquals("pending", registry.version("class.TCKN", 2).orElseThrow().status());
    }

    /** PR 47 review D-02: half a single-approval record is refused by the guard, with two approvals as with one. */
    @Test
    void halfARecordIsRefusedByTheGuardEvenWithTwoApprovals() {
        approve("security_admin", ADMIN, null);
        db.dsl().transaction(cfg -> {
            var tx = DSL.using(cfg);
            new AuditContext(OFFICER, "policy.approve", "APPROVAL_PRIVACY_OFFICER", null).apply(tx);
            tx.execute("INSERT INTO policy_approval (rule_id, version, approver_role, approver_fingerprint) VALUES "
                + "('class.TCKN', 2, 'privacy_officer', '" + OFFICER + "')");
        });
        for (String set : new String[] {"single_approval_reason = '" + REASON + "'",
            "single_approval_by = '" + ADMIN + "'"}) {
            DataAccessException half = assertThrows(DataAccessException.class, () -> db.dsl().transaction(cfg -> {
                var tx = DSL.using(cfg);
                new AuditContext(ADMIN, PolicyRegistryStore.ACTION_SINGLE_APPROVAL, REASON, null).apply(tx);
                tx.execute("SELECT set_config('app.single_approval', 'on', true)");
                tx.execute("UPDATE policy_rule_version SET status = 'active', activated_at = now(), " + set
                    + " WHERE rule_id = 'class.TCKN' AND version = 2");
            }), set);
            assertTrue(half.getMessage().contains("POLICY_SINGLE_APPROVAL_REFUSED"), half.getMessage());
        }
        assertEquals("pending", registry.version("class.TCKN", 2).orElseThrow().status());
    }

    @Test
    void theRecordIsWrittenOnceByTheActivationAndNeverOnInsert() {
        approve("security_admin", ADMIN, single(ADMIN, REASON));
        DataAccessException rewrite = assertThrows(DataAccessException.class, () -> db.dsl().transaction(cfg -> {
            var tx = DSL.using(cfg);
            new AuditContext(ADMIN, "synthetic.mutation", "SYNTHETIC_CHANGE", null).apply(tx);
            tx.execute("UPDATE policy_rule_version SET single_approval_reason = 'rewritten' "
                + "WHERE rule_id = 'class.TCKN' AND version = 2");
        }));
        assertTrue(rewrite.getMessage().contains("POLICY_SINGLE_APPROVAL_FINAL"));
        DataAccessException insert = assertThrows(DataAccessException.class, () -> db.dsl().transaction(cfg -> {
            var tx = DSL.using(cfg);
            new AuditContext(ADMIN, "synthetic.mutation", "SYNTHETIC_CHANGE", null).apply(tx);
            tx.execute("INSERT INTO policy_rule_version (rule_id, version, kind, data_class, action, mode, rollout_stage,"
                + " status, source, author_fingerprint, reason_code, single_approval_by, single_approval_reason) VALUES"
                + " ('class.SECRET', 2, 'class_action', 'SECRET', 'BLOCK', 'enforce', 'all', 'pending', 'registry', '"
                + ADMIN + "', 'SYNTHETIC_CHANGE', '" + ADMIN + "', 'Synthetic')");
        }));
        assertTrue(insert.getMessage().contains("POLICY_SINGLE_APPROVAL_REFUSED"));
    }
}
