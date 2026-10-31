package io.rwsafe.persistence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.persistence.PolicyRuleVersion.Draft;
import io.rwsafe.persistence.PolicySnapshotStore.Compiled;
import io.rwsafe.persistence.PolicySnapshotStore.IssuedSnapshot;
import io.rwsafe.persistence.PolicySnapshotStore.Rendered;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;
import org.jooq.exception.DataAccessException;
import org.jooq.impl.DSL;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** AGENTS.md section 6 in the database: versioned rules, two approvals by two people, fail-closed classes, the ledger. */
class PolicyRegistryStoreTest {

    private static final String ADMIN = "USR-00000000a1";
    private static final String OFFICER = "USR-00000000b2";
    private static final String OTHER_ADMIN = "USR-00000000c3";

    private Database db;
    private PolicyRegistryStore registry;

    @BeforeEach
    void open() {
        db = Database.migrateAndOpen(TestDatabase.fresh());
        registry = db.policyRegistry();
        assertTrue(registry.seed(List.of(
            classRule("SECRET", "BLOCK", "enforce", "all", "system:seed-fixture"),
            classRule("TCKN", "REDACT", "enforce", "all", "system:seed-fixture"),
            new Draft("platform.claude", "platform", null, null, "claude", List.of("claude.ai"), List.of(), List.of(),
                null, "enforce", "all", "system:seed-fixture", "SEED_FIXTURE"),
            new Draft("flow.ai-category", "flow", null, null, null, null, null, null, true, "enforce", "all",
                "system:seed-fixture", "SEED_FIXTURE")), audit("system:seed-fixture", "policy.seed")));
    }

    private static Draft classRule(String dataClass, String action, String mode, String stage, String author) {
        return new Draft("class." + dataClass, "class_action", dataClass, action, null, null, null, null, null, mode,
            stage, author, author.startsWith("system:") ? "SEED_FIXTURE" : "SYNTHETIC_CHANGE");
    }

    /** The store keeps what the service hands it: the normal form, here lower case (synthetic ASCII names). */
    private static Draft groupRule(String dataClass, String action, String mode, List<String> groups) {
        return new Draft("class." + dataClass, "class_action", dataClass, action, null, null, null, null, null, mode,
            "all", ADMIN, "SYNTHETIC_CHANGE", "GROUPS",
            groups.stream().map(g -> g.toLowerCase(java.util.Locale.ROOT)).toList());
    }

    private static AuditContext audit(String actor, String action) {
        return new AuditContext(actor, action, "SYNTHETIC_CHANGE", null);
    }

    private PolicyRuleVersion approve(String ruleId, int version, String role, String who) {
        return registry.approve(ruleId, version, role, who, audit(who, "policy.approve"),
            audit("system:policy-registry", "policy.activate"), active -> { });
    }

    private String status(String ruleId, int version) {
        return registry.version(ruleId, version).orElseThrow().status();
    }

    @Test
    void theSeedRunsOnceAndStartsActive() {
        assertFalse(registry.seed(List.of(classRule("TR_IBAN", "REDACT", "enforce", "all", "system:seed-fixture")),
            audit("system:seed-fixture", "policy.seed")));
        assertEquals(4, registry.versions().size());
        assertTrue(registry.active().stream().allMatch(v -> v.version() == 1 && v.source().equals("seed")));
        assertEquals(4, ledgerRows("policy_rule_version", "INSERT"));
    }

    @Test
    void aVersionBecomesActiveOnlyWithBothRolesFromTwoPeople() {
        PolicyRuleVersion draft = registry.draft(classRule("TCKN", "BLOCK", "enforce", "all", ADMIN),
            audit(ADMIN, "policy.draft"));
        assertEquals(2, draft.version());
        assertEquals("pending", draft.status());

        PolicyRuleVersion once = approve("class.TCKN", 2, "security_admin", ADMIN);
        assertEquals("pending", once.status());
        assertEquals(1, once.approvals().size());
        RegistryConflict samePerson = assertThrows(RegistryConflict.class,
            () -> approve("class.TCKN", 2, "privacy_officer", ADMIN));
        assertEquals("APPROVER_ALREADY_APPROVED", samePerson.reason());
        RegistryConflict sameRole = assertThrows(RegistryConflict.class,
            () -> approve("class.TCKN", 2, "security_admin", OTHER_ADMIN));
        assertEquals("APPROVAL_ROLE_TAKEN", sameRole.reason());

        PolicyRuleVersion active = approve("class.TCKN", 2, "privacy_officer", OFFICER);
        assertEquals("active", active.status());
        assertEquals("superseded", status("class.TCKN", 1));
        assertEquals("POLICY_NOT_PENDING", assertThrows(RegistryConflict.class,
            () -> approve("class.TCKN", 2, "privacy_officer", OTHER_ADMIN)).reason());
        assertEquals(2, ledgerRows("policy_approval", "INSERT"));
        assertEquals(2, ledgerRows("policy_rule_version", "UPDATE"), "one supersede and one activation");
    }

    @Test
    void theDatabaseRefusesAnActivationWithoutApprovalsAndAnyEditOfAVersion() {
        registry.draft(classRule("SECRET", "BLOCK", "enforce", "all", ADMIN), audit(ADMIN, "policy.draft"));
        DataAccessException unapproved = assertThrows(DataAccessException.class, () -> mutate(
            "UPDATE policy_rule_version SET status = 'active', activated_at = now() WHERE rule_id = 'class.SECRET' "
                + "AND version = 2"));
        assertTrue(unapproved.getMessage().contains("POLICY_APPROVAL_REQUIRED"));
        DataAccessException edit = assertThrows(DataAccessException.class, () -> mutate(
            "UPDATE policy_rule_version SET action = 'REDACT' WHERE rule_id = 'class.SECRET' AND version = 1"));
        assertTrue(edit.getMessage().contains("POLICY_VERSION_IMMUTABLE"));
        DataAccessException delete = assertThrows(DataAccessException.class, () -> mutate(
            "DELETE FROM policy_rule_version WHERE rule_id = 'class.SECRET'"));
        assertTrue(delete.getMessage().contains("AUDIT_APPEND_ONLY"));
        DataAccessException direct = assertThrows(DataAccessException.class, () -> mutate(
            "INSERT INTO policy_rule_version (rule_id, version, kind, data_class, action, mode, rollout_stage, status, "
                + "source, author_fingerprint, reason_code, activated_at) VALUES ('class.SECRET', 9, 'class_action', "
                + "'SECRET', 'BLOCK', 'enforce', 'all', 'active', 'registry', 'USR-00000000a1', 'SYNTHETIC_CHANGE', "
                + "now())"));
        assertTrue(direct.getMessage().contains("POLICY_APPROVAL_REQUIRED"));
    }

    @Test
    void noVersionEverAllowsOrWarnsAFailClosedClassAndTheFlowIsNeverRelaxed() {
        for (String mode : new String[] {"enforce", "monitor"}) {
            for (String action : new String[] {"ALLOW", "WARN"}) {
                RegistryConflict refused = assertThrows(RegistryConflict.class, () -> registry.draft(
                    classRule("TCKN", action, mode, "all", ADMIN), audit(ADMIN, "policy.draft")));
                assertEquals("POLICY_CONSTRAINT_REFUSED", refused.reason(), mode + " " + action);
            }
        }
        assertThrows(RegistryConflict.class, () -> registry.draft(new Draft("flow.ai-category", "flow", null, null, null,
            null, null, null, false, "enforce", "all", ADMIN, "SYNTHETIC_CHANGE"), audit(ADMIN, "policy.draft")));
        assertEquals("pending", registry.draft(classRule("TCKN", "BLOCK", "monitor", "all", ADMIN),
            audit(ADMIN, "policy.draft")).status(), "a stricter monitor version is shadow-evaluated only");
        assertThrows(RegistryConflict.class, () -> registry.draft(new Draft("platform.claude", "platform", null, null,
            "claude", List.of("192.0.2.10"), List.of(), List.of(), null, "enforce", "all", ADMIN, "SYNTHETIC_CHANGE"),
            audit(ADMIN, "policy.draft")), "an address is not a host name");
    }

    @Test
    void aGroupScopedVersionRunsBesideTheAnyBaselineAndReplacesOnlyItsOwnScope() {
        registry.draft(groupRule("TCKN", "BLOCK", "enforce", List.of("GRP-ALPHA", "GRP-BETA")),
            audit(ADMIN, "policy.draft"));
        approve("class.TCKN", 2, "security_admin", ADMIN);
        approve("class.TCKN", 2, "privacy_officer", OFFICER);
        assertEquals("active", status("class.TCKN", 1), "the ANY baseline keeps applying");
        assertEquals("active", status("class.TCKN", 2));
        assertEquals(List.of("grp-alpha", "grp-beta"), registry.version("class.TCKN", 2).orElseThrow().scopeGroups());

        registry.draft(groupRule("TCKN", "REDACT", "enforce", List.of("GRP-GAMMA")), audit(ADMIN, "policy.draft"));
        approve("class.TCKN", 3, "security_admin", ADMIN);
        approve("class.TCKN", 3, "privacy_officer", OFFICER);
        assertEquals("active", status("class.TCKN", 2), "another group list is another scope");

        // The scope key is the trimmed, lower-cased, sorted list: the same groups in another case and order.
        registry.draft(groupRule("TCKN", "REDACT", "enforce", List.of("grp-beta", "Grp-Alpha")),
            audit(ADMIN, "policy.draft"));
        approve("class.TCKN", 4, "security_admin", ADMIN);
        approve("class.TCKN", 4, "privacy_officer", OFFICER);
        assertEquals("superseded", status("class.TCKN", 2));
        assertEquals("active", status("class.TCKN", 3));
        assertEquals("active", status("class.TCKN", 1));

        registry.draft(groupRule("TCKN", "BLOCK", "monitor", List.of("GRP-GAMMA")), audit(ADMIN, "policy.draft"));
        approve("class.TCKN", 5, "security_admin", ADMIN);
        approve("class.TCKN", 5, "privacy_officer", OFFICER);
        assertEquals("active", status("class.TCKN", 3), "a monitor version is another mode");
        assertEquals(List.of(1, 3, 4, 5), registry.active().stream().filter(v -> v.ruleId().equals("class.TCKN"))
            .map(PolicyRuleVersion::version).sorted().toList());

        registry.draft(classRule("TCKN", "BLOCK", "enforce", "all", ADMIN), audit(ADMIN, "policy.draft"));
        approve("class.TCKN", 6, "security_admin", ADMIN);
        approve("class.TCKN", 6, "privacy_officer", OFFICER);
        assertEquals("superseded", status("class.TCKN", 1));
        assertEquals("active", status("class.TCKN", 4), "a new ANY version leaves the group scopes alone");
    }

    @Test
    void theScopeShapeIsCheckedByTheDatabase() {
        String insert = "INSERT INTO policy_rule_version (rule_id, version, kind, data_class, action, mode, "
            + "rollout_stage, status, source, author_fingerprint, reason_code, scope_kind, scope_groups) VALUES "
            + "('class.TR_IBAN', 7, 'class_action', 'TR_IBAN', 'BLOCK', 'enforce', 'all', 'pending', 'registry', "
            + "'USR-00000000a1', 'SYNTHETIC_CHANGE', %s)";
        String many = java.util.stream.IntStream.rangeClosed(1, 33).mapToObj(i -> "'GRP-" + i + "'")
            .collect(Collectors.joining(","));
        for (String values : new String[] {
            "'GROUPS', ARRAY[]::text[]",
            "'GROUPS', ARRAY[" + many + "]",
            "'GROUPS', ARRAY['" + "G".repeat(257) + "']",
            "'GROUPS', ARRAY[' GRP-ALPHA']",
            "'GROUPS', ARRAY['']",
            "'GROUPS', ARRAY['grp-alpha', 'grp-alpha']",
            "'GROUPS', ARRAY['GRP-ALPHA']",
            "'GROUPS', ARRAY['grp-alpha', 'Grp-Alpha']",
            "'GROUPS', ARRAY['grp-alpha,grp-beta']",
            "'GROUPS', ARRAY['GRP-DELTA-I']",
            "'GROUPS', ARRAY[U&'grp-\\0130stanbul']",
            "'GROUPS', ARRAY[U&'grp-\\0131zmir']",
            "'GROUPS', ARRAY[U&'grp-i\\0307']",
            "'GROUPS', ARRAY[U&'grp-e\\0301']",
            "'GROUPS', ARRAY[U&'grp-\\0007']",
            "'ANY', ARRAY['GRP-ALPHA']",
            "'SOME', ARRAY[]::text[]"}) {
            assertThrows(DataAccessException.class, () -> mutate(String.format(insert, values)), values);
        }
        assertThrows(RegistryConflict.class, () -> registry.draft(new Draft("platform.claude", "platform", null, null,
            "claude", List.of("claude.ai"), List.of(), List.of(), null, "enforce", "all", ADMIN, "SYNTHETIC_CHANGE",
            "GROUPS", List.of("GRP-ALPHA")), audit(ADMIN, "policy.draft")), "a platform row is never group-scoped");
        assertEquals(32, registry.draft(groupRule("TR_IBAN", "BLOCK", "enforce",
            java.util.stream.IntStream.rangeClosed(1, 32).mapToObj(i -> "GRP-" + i).toList()),
            audit(ADMIN, "policy.draft")).scopeGroups().size());
    }

    @Test
    void aNewVersionIsAlwaysStageAll() {
        for (String stage : new String[] {"pilot", "pct25", "pct50"}) {
            RegistryConflict refused = assertThrows(RegistryConflict.class, () -> registry.draft(
                classRule("TCKN", "BLOCK", "enforce", stage, ADMIN), audit(ADMIN, "policy.draft")));
            assertEquals("POLICY_STAGE_RETIRED", refused.reason(), stage);
        }
    }

    @Test
    void noGroupScopeAllowsOrWarnsAFailClosedClass() {
        for (String mode : new String[] {"enforce", "monitor"}) {
            for (String action : new String[] {"ALLOW", "WARN"}) {
                assertThrows(RegistryConflict.class, () -> registry.draft(
                    groupRule("SECRET", action, mode, List.of("GRP-ALPHA")), audit(ADMIN, "policy.draft")),
                    mode + " " + action);
            }
        }
    }

    // PO decision Q-40: one administrator retires a platform row with a reason; the row stays, ledgered.

    @Test
    void oneAdministratorRetiresAPlatformRowWhichNeverComesBackButANewVersionCan() {
        List<PolicyRuleVersion> retired = registry.retirePlatform("platform.claude", ADMIN, "Synthetic retirement",
            new AuditContext(ADMIN, "policy.platform_retire", "Synthetic retirement", null), active -> { });
        assertEquals(1, retired.size());
        PolicyRuleVersion row = registry.version("platform.claude", 1).orElseThrow();
        assertEquals("retired", row.status());
        assertEquals(ADMIN, row.retirement().retiredBy());
        assertEquals("Synthetic retirement", row.retirement().reason());
        assertTrue(registry.active().stream().noneMatch(v -> v.ruleId().equals("platform.claude")));
        assertEquals(1, db.dsl().fetchCount(Schema.AUDIT_EVENT, Schema.AUDIT_TABLE.eq("policy_rule_version")
            .and(Schema.AUDIT_OPERATION.eq("UPDATE")).and(Schema.AUDIT_ACTION.eq("policy.platform_retire"))
            .and(Schema.AUDIT_ACTOR.eq(ADMIN)).and(Schema.AUDIT_REASON.eq("Synthetic retirement"))));

        assertEquals("POLICY_VERSION_NOT_FOUND", assertThrows(RegistryConflict.class, () -> registry.retirePlatform(
            "platform.claude", ADMIN, "again", new AuditContext(ADMIN, "policy.platform_retire", "again", null),
            active -> { })).reason(), "nothing active is left to retire");
        for (String sql : new String[] {
            "UPDATE policy_rule_version SET status = 'active', retired_at = NULL, retired_by = NULL, "
                + "retired_reason = NULL WHERE rule_id = 'platform.claude' AND version = 1",
            "UPDATE policy_rule_version SET retired_reason = 'rewritten' WHERE rule_id = 'platform.claude'",
            "DELETE FROM policy_rule_version WHERE rule_id = 'platform.claude'"}) {
            assertThrows(DataAccessException.class, () -> mutate(sql), sql);
        }

        registry.draft(new Draft("platform.claude", "platform", null, null, "claude", List.of("claude.ai"), List.of(),
            List.of(), null, "enforce", "all", ADMIN, "SYNTHETIC_CHANGE"), audit(ADMIN, "policy.draft"));
        approve("platform.claude", 2, "security_admin", ADMIN);
        assertEquals("pending", status("platform.claude", 2), "one approval brings nothing back");
        approve("platform.claude", 2, "privacy_officer", OFFICER);
        assertEquals("active", status("platform.claude", 2));
        assertEquals("retired", status("platform.claude", 1), "the retired row keeps its history");
    }

    @Test
    void onlyAnActivePlatformRowIsRetiredAndTheLedgerNamesTheAdministratorAndTheReason() {
        String retire = "UPDATE policy_rule_version SET status = 'retired', retired_at = now(), retired_by = '%s', "
            + "retired_reason = '%s' WHERE rule_id = '%s' AND version = 1";
        assertThrows(DataAccessException.class, () -> mutateAs(ADMIN, "Synthetic",
            String.format(retire, ADMIN, "Synthetic", "class.SECRET")), "a class rule is never retired");
        DataAccessException otherActor = assertThrows(DataAccessException.class, () -> mutateAs(OTHER_ADMIN,
            "Synthetic", String.format(retire, ADMIN, "Synthetic", "platform.claude")));
        assertTrue(otherActor.getMessage().contains("POLICY_RETIRE_REFUSED"));
        DataAccessException otherReason = assertThrows(DataAccessException.class, () -> mutateAs(ADMIN,
            "PLATFORM_RETIRED", String.format(retire, ADMIN, "Synthetic", "platform.claude")));
        assertTrue(otherReason.getMessage().contains("POLICY_RETIRE_REFUSED"));
        assertThrows(DataAccessException.class, () -> mutateAs(ADMIN, "x", String.format(retire, ADMIN, " x",
            "platform.claude")), "an untrimmed reason");
        assertThrows(DataAccessException.class, () -> mutateAs(ADMIN, "Synthetic", "UPDATE policy_rule_version SET "
            + "status = 'retired', retired_at = now(), retired_by = '" + ADMIN + "' WHERE rule_id = 'platform.claude'"),
            "no reason");
        assertEquals("active", status("platform.claude", 1));
    }

    @Test
    void aRefusedRetireCheckRollsTheRetirementBack() {
        assertThrows(IllegalStateException.class, () -> registry.retirePlatform("platform.claude", ADMIN, "Synthetic",
            new AuditContext(ADMIN, "policy.platform_retire", "Synthetic", null), active -> {
                assertTrue(active.stream().noneMatch(v -> v.ruleId().equals("platform.claude")));
                throw new IllegalStateException("synthetic refusal");
            }));
        assertEquals("active", status("platform.claude", 1));
        assertEquals(0, db.dsl().fetchCount(Schema.AUDIT_EVENT, Schema.AUDIT_ACTION.eq("policy.platform_retire")));
    }

    // PR 16 review D-01: the seed path and the supersede path cannot activate or remove a rule without two approvals.

    @Test
    void aSeedRowIsOnlyTheFixtureImportIntoAnEmptyRegistry() {
        String seed = "INSERT INTO policy_rule_version (rule_id, version, kind, data_class, action, mode, rollout_stage, "
            + "status, source, author_fingerprint, reason_code, activated_at) VALUES ('class.%s', %d, 'class_action', "
            + "'%s', 'BLOCK', '%s', '%s', 'active', 'seed', '%s', '%s', now())";
        for (String sql : new String[] {
            String.format(seed, "TCKN", 2, "TCKN", "enforce", "all", "system:seed-fixture", "SEED_FIXTURE"),
            String.format(seed, "TR_IBAN", 1, "TR_IBAN", "monitor", "all", "system:seed-fixture", "SEED_FIXTURE"),
            String.format(seed, "TR_IBAN", 1, "TR_IBAN", "enforce", "pilot", "system:seed-fixture", "SEED_FIXTURE"),
            String.format(seed, "TR_IBAN", 1, "TR_IBAN", "enforce", "all", ADMIN, "SEED_FIXTURE"),
            String.format(seed, "TR_IBAN", 1, "TR_IBAN", "enforce", "all", "system:seed-fixture", "SYNTHETIC_CHANGE")}) {
            DataAccessException e = assertThrows(DataAccessException.class, () -> mutate(sql), sql);
            assertTrue(e.getMessage().contains("POLICY_SEED_SHAPE"), sql);
        }
        registry.draft(classRule("TCKN", "BLOCK", "enforce", "all", ADMIN), audit(ADMIN, "policy.draft"));
        DataAccessException closed = assertThrows(DataAccessException.class, () -> mutate(
            String.format(seed, "TR_IBAN", 1, "TR_IBAN", "enforce", "all", "system:seed-fixture", "SEED_FIXTURE")));
        assertTrue(closed.getMessage().contains("POLICY_SEED_CLOSED"));
    }

    @Test
    void anActiveVersionIsSupersededOnlyByANewerActiveOne() {
        for (String rule : new String[] {"class.SECRET", "platform.claude", "flow.ai-category"}) {
            DataAccessException e = assertThrows(DataAccessException.class, () -> mutate(
                "UPDATE policy_rule_version SET status = 'superseded', superseded_at = now() WHERE rule_id = '" + rule
                    + "' AND version = 1"));
            assertTrue(e.getMessage().contains("POLICY_NO_REPLACEMENT"), rule);
        }
        registry.draft(groupRule("TCKN", "BLOCK", "enforce", List.of("GRP-ALPHA")), audit(ADMIN, "policy.draft"));
        approve("class.TCKN", 2, "security_admin", ADMIN);
        approve("class.TCKN", 2, "privacy_officer", OFFICER);
        DataAccessException byScoped = assertThrows(DataAccessException.class, () -> mutate(
            "UPDATE policy_rule_version SET status = 'superseded', superseded_at = now() WHERE rule_id = 'class.TCKN' "
                + "AND version = 1"));
        assertTrue(byScoped.getMessage().contains("POLICY_NO_REPLACEMENT"),
            "a group-scoped version never replaces the ANY baseline");
        DataAccessException retime = assertThrows(DataAccessException.class, () -> mutate(
            "UPDATE policy_rule_version SET activated_at = now() - interval '1 day' WHERE rule_id = 'class.SECRET'"));
        assertTrue(retime.getMessage().contains("POLICY_LIFECYCLE"));
    }

    // PR 16 review D-03: one pending version per rule; a newer draft supersedes an older one with its approvals.

    @Test
    void aNewDraftSupersedesTheOlderPendingOneWithItsApproval() {
        registry.draft(classRule("TCKN", "BLOCK", "enforce", "all", ADMIN), audit(ADMIN, "policy.draft"));
        approve("class.TCKN", 2, "security_admin", ADMIN);
        registry.draft(classRule("TCKN", "REDACT", "enforce", "all", ADMIN), audit(ADMIN, "policy.draft"));
        assertEquals("superseded", status("class.TCKN", 2));
        assertEquals("pending", status("class.TCKN", 3));
        assertEquals("POLICY_NOT_PENDING", assertThrows(RegistryConflict.class,
            () -> approve("class.TCKN", 2, "privacy_officer", OFFICER)).reason(),
            "a single person can never complete the older draft");
        assertEquals("active", status("class.TCKN", 1));
        assertEquals(1, registry.versions().stream().filter(v -> v.status().equals("pending")).count());

        DataAccessException second = assertThrows(DataAccessException.class, () -> mutate(
            "INSERT INTO policy_rule_version (rule_id, version, kind, data_class, action, mode, rollout_stage, status, "
                + "source, author_fingerprint, reason_code) VALUES ('class.TCKN', 9, 'class_action', 'TCKN', 'BLOCK', "
                + "'enforce', 'all', 'pending', 'registry', 'USR-00000000a1', 'SYNTHETIC_CHANGE')"));
        assertEquals("23P01", second.sqlState(), "the one-pending exclusion constraint");
        DataAccessException orphan = assertThrows(DataAccessException.class, () -> mutate(
            "UPDATE policy_rule_version SET status = 'superseded', superseded_at = now() WHERE rule_id = 'class.TCKN' "
                + "AND version = 3"));
        assertTrue(orphan.getMessage().contains("POLICY_NO_REPLACEMENT"));
    }

    // PR 21 Q-41: one pending version per rule, mode and scope, so drafts for different scopes run side by side.

    @Test
    void draftsForDifferentScopesArePendingSideBySide() {
        registry.draft(classRule("TCKN", "BLOCK", "enforce", "all", ADMIN), audit(ADMIN, "policy.draft"));
        registry.draft(groupRule("TCKN", "BLOCK", "enforce", List.of("grp-alpha")), audit(ADMIN, "policy.draft"));
        registry.draft(groupRule("TCKN", "BLOCK", "monitor", List.of("grp-alpha")), audit(ADMIN, "policy.draft"));
        registry.draft(groupRule("TCKN", "BLOCK", "enforce", List.of("grp-beta")), audit(ADMIN, "policy.draft"));
        assertEquals(List.of(2, 3, 4, 5), registry.versions().stream().filter(v -> v.status().equals("pending"))
            .map(PolicyRuleVersion::version).sorted().toList());
        registry.draft(groupRule("TCKN", "REDACT", "enforce", List.of("grp-alpha")), audit(ADMIN, "policy.draft"));
        assertEquals("superseded", status("class.TCKN", 3), "the same rule, mode and scope replaces its draft");
        assertEquals("pending", status("class.TCKN", 2));
        assertEquals("pending", status("class.TCKN", 4));
        approve("class.TCKN", 5, "security_admin", ADMIN);
        approve("class.TCKN", 5, "privacy_officer", OFFICER);
        approve("class.TCKN", 6, "security_admin", ADMIN);
        approve("class.TCKN", 6, "privacy_officer", OFFICER);
        assertEquals("active", status("class.TCKN", 5));
        assertEquals("active", status("class.TCKN", 6));
    }

    // PO decision Q-41 (2026-10-31): one administrator withdraws a group-scoped version with a reason, at once.

    private PolicyRuleVersion withdraw(String ruleId, int version, String admin, String reason) {
        return registry.withdrawScope(ruleId, version, admin, reason,
            new AuditContext(admin, "policy.scope_withdraw", reason, null), active -> { });
    }

    private void activeGroupVersion() {
        registry.draft(groupRule("TCKN", "BLOCK", "enforce", List.of("grp-alpha")), audit(ADMIN, "policy.draft"));
        approve("class.TCKN", 2, "security_admin", ADMIN);
        approve("class.TCKN", 2, "privacy_officer", OFFICER);
    }

    @Test
    void oneAdministratorWithdrawsAGroupScopedVersionAtOnceAndItsHistoryStays() {
        activeGroupVersion();
        assertEquals("WITHDRAWAL_NOT_APPLICABLE", assertThrows(RegistryConflict.class,
            () -> withdraw("class.TCKN", 1, ADMIN, "Synthetic")).reason(), "the ANY baseline is never withdrawn");
        assertEquals("WITHDRAWAL_NOT_APPLICABLE", assertThrows(RegistryConflict.class,
            () -> withdraw("platform.claude", 1, ADMIN, "Synthetic")).reason(), "a platform row is retired instead");
        assertEquals("POLICY_VERSION_NOT_FOUND", assertThrows(RegistryConflict.class,
            () -> withdraw("class.TCKN", 9, ADMIN, "Synthetic")).reason());

        PolicyRuleVersion withdrawn = withdraw("class.TCKN", 2, ADMIN, "Pilot finished");
        assertEquals("withdrawn", withdrawn.status(), "no second approval");
        assertEquals(ADMIN, withdrawn.withdrawnBy());
        assertEquals("Pilot finished", withdrawn.withdrawalReason());
        assertTrue(withdrawn.withdrawnAt() != null && withdrawn.activatedAt() != null, "history kept");
        assertEquals(null, withdrawn.withdrawsVersion());
        assertTrue(registry.active().stream().noneMatch(v -> v.key().equals("class.TCKN@v2")),
            "the version leaves the active set, so the next snapshot");
        assertEquals("active", status("class.TCKN", 1), "the groups fall back to the ANY baseline");
        assertEquals(2, registry.versions().stream().filter(v -> v.ruleId().equals("class.TCKN")).count(),
            "no request version is written");
        assertEquals(1, db.dsl().fetchCount(Schema.AUDIT_EVENT, Schema.AUDIT_TABLE.eq("policy_rule_version")
            .and(Schema.AUDIT_OPERATION.eq("UPDATE")).and(Schema.AUDIT_ACTION.eq("policy.scope_withdraw"))
            .and(Schema.AUDIT_ACTOR.eq(ADMIN)).and(Schema.AUDIT_REASON.eq("Pilot finished"))
            .and(Schema.AUDIT_ROW_KEY.eq("class.TCKN@v2"))));

        assertEquals("WITHDRAWAL_NOT_APPLICABLE", assertThrows(RegistryConflict.class,
            () -> withdraw("class.TCKN", 2, ADMIN, "again")).reason(), "a withdrawn version stays withdrawn");
        for (String sql : new String[] {
            "UPDATE policy_rule_version SET status = 'active', withdrawn_at = NULL, withdrawn_by = NULL, "
                + "withdrawal_reason = NULL WHERE rule_id = 'class.TCKN' AND version = 2",
            "UPDATE policy_rule_version SET withdrawal_reason = 'rewritten' WHERE rule_id = 'class.TCKN' AND version = 2",
            "UPDATE policy_rule_version SET withdrawn_by = '" + OTHER_ADMIN + "' WHERE rule_id = 'class.TCKN' "
                + "AND version = 2",
            "UPDATE policy_rule_version SET withdrawn_at = now() WHERE rule_id = 'class.TCKN' AND version = 2",
            "DELETE FROM policy_rule_version WHERE rule_id = 'class.TCKN' AND version = 2"}) {
            assertThrows(DataAccessException.class, () -> mutate(sql), sql);
        }

        // The scope comes back only as a new version under the two approvals.
        registry.draft(groupRule("TCKN", "BLOCK", "enforce", List.of("grp-alpha")), audit(ADMIN, "policy.draft"));
        approve("class.TCKN", 3, "security_admin", ADMIN);
        assertEquals("pending", status("class.TCKN", 3), "one approval brings nothing back");
        approve("class.TCKN", 3, "privacy_officer", OFFICER);
        assertEquals("active", status("class.TCKN", 3));
        assertEquals("withdrawn", status("class.TCKN", 2), "the withdrawn version keeps its history");
    }

    @Test
    void theDatabaseRefusesAWithdrawalTheLedgerDoesNotNameAsTheAdministratorsWithTheReason() {
        activeGroupVersion();
        String withdraw = "UPDATE policy_rule_version SET status = 'withdrawn', withdrawn_at = now(), "
            + "withdrawn_by = '%s', withdrawal_reason = '%s' WHERE rule_id = '%s' AND version = %d";
        DataAccessException bare = assertThrows(DataAccessException.class, () -> mutate(
            "UPDATE policy_rule_version SET status = 'withdrawn', withdrawn_at = now() WHERE rule_id = 'class.TCKN' "
                + "AND version = 2"));
        assertTrue(bare.getMessage().contains("POLICY_WITHDRAWAL_REFUSED"), "no administrator, no reason");
        DataAccessException otherActor = assertThrows(DataAccessException.class, () -> mutateAs(OTHER_ADMIN,
            "Synthetic", String.format(withdraw, ADMIN, "Synthetic", "class.TCKN", 2)));
        assertTrue(otherActor.getMessage().contains("POLICY_WITHDRAWAL_REFUSED"),
            "the ledger's actor is the withdrawing administrator");
        DataAccessException otherReason = assertThrows(DataAccessException.class, () -> mutateAs(ADMIN,
            "SYNTHETIC_CHANGE", String.format(withdraw, ADMIN, "Synthetic", "class.TCKN", 2)));
        assertTrue(otherReason.getMessage().contains("POLICY_WITHDRAWAL_REFUSED"), "the ledger carries the reason");
        assertThrows(DataAccessException.class, () -> mutateAs(ADMIN, "x",
            String.format(withdraw, ADMIN, " x", "class.TCKN", 2)), "an untrimmed reason");
        assertThrows(DataAccessException.class, () -> mutateAs(ADMIN, "Synthetic",
            String.format(withdraw, ADMIN, "Synthetic", "class.TCKN", 1)), "the ANY baseline");
        assertThrows(DataAccessException.class, () -> mutateAs(ADMIN, "Synthetic",
            String.format(withdraw, ADMIN, "Synthetic", "platform.claude", 1)), "a platform row");
        assertEquals("active", status("class.TCKN", 2));

        mutateAs(ADMIN, "Synthetic", String.format(withdraw, ADMIN, "Synthetic", "class.TCKN", 2));
        assertEquals("withdrawn", status("class.TCKN", 2), "the guarded direct path is the store's own update");
    }

    @Test
    void theTwoApprovalWithdrawalRequestIsGone() {
        activeGroupVersion();
        DataAccessException request = assertThrows(DataAccessException.class, () -> mutate("INSERT INTO "
            + "policy_rule_version (rule_id, version, kind, data_class, action, mode, rollout_stage, status, source, "
            + "author_fingerprint, reason_code, scope_kind, scope_groups, withdraws_version, withdrawal_reason) VALUES "
            + "('class.TCKN', 3, 'class_action', 'TCKN', 'BLOCK', 'enforce', 'all', 'pending', 'registry', "
            + "'USR-00000000a1', 'SCOPE_WITHDRAWAL', 'GROUPS', ARRAY['grp-alpha'], 2, 'Synthetic')"));
        assertTrue(request.getMessage().contains("POLICY_WITHDRAWAL_REQUEST_RETIRED"), request.getMessage());
        assertThrows(DataAccessException.class, () -> mutate("INSERT INTO policy_rule_version (rule_id, version, kind, "
            + "data_class, action, mode, rollout_stage, status, source, author_fingerprint, reason_code, scope_kind, "
            + "scope_groups, withdrawn_by) VALUES ('class.TCKN', 3, 'class_action', 'TCKN', 'BLOCK', 'enforce', 'all', "
            + "'pending', 'registry', 'USR-00000000a1', 'SYNTHETIC_CHANGE', 'GROUPS', ARRAY['grp-beta'], "
            + "'USR-00000000a1')"), "a new version carries no withdrawal");
        assertEquals("active", status("class.TCKN", 2));
    }

    @Test
    void aWithdrawalLeavesOtherScopesAndPendingDraftsAlone() {
        activeGroupVersion();
        registry.draft(groupRule("TCKN", "BLOCK", "enforce", List.of("grp-beta")), audit(ADMIN, "policy.draft"));
        approve("class.TCKN", 3, "security_admin", ADMIN);
        approve("class.TCKN", 3, "privacy_officer", OFFICER);
        registry.draft(groupRule("TCKN", "REDACT", "enforce", List.of("grp-alpha")), audit(ADMIN, "policy.draft"));
        withdraw("class.TCKN", 2, OTHER_ADMIN, "Synthetic");
        assertEquals("withdrawn", status("class.TCKN", 2));
        assertEquals("active", status("class.TCKN", 3), "another group scope keeps applying");
        assertEquals("pending", status("class.TCKN", 4), "a draft of the scope waits for its two approvals");
        approve("class.TCKN", 4, "security_admin", ADMIN);
        approve("class.TCKN", 4, "privacy_officer", OFFICER);
        assertEquals("active", status("class.TCKN", 4));
    }

    @Test
    void aRefusedWithdrawCheckRollsTheWithdrawalBack() {
        activeGroupVersion();
        assertThrows(IllegalStateException.class, () -> registry.withdrawScope("class.TCKN", 2, ADMIN, "Synthetic",
            new AuditContext(ADMIN, "policy.scope_withdraw", "Synthetic", null), active -> {
                assertTrue(active.stream().noneMatch(v -> v.key().equals("class.TCKN@v2")));
                throw new IllegalStateException("synthetic refusal");
            }));
        assertEquals("active", status("class.TCKN", 2));
        assertEquals(0, db.dsl().fetchCount(Schema.AUDIT_EVENT, Schema.AUDIT_ACTION.eq("policy.scope_withdraw")));
    }

    // PR 21 review D-01: retiring a platform supersedes its pending drafts and their approvals.

    @Test
    void aDraftStartedBeforeARetirementCanNeverBringThePlatformBack() {
        registry.draft(new Draft("platform.claude", "platform", null, null, "claude", List.of("claude.ai"), List.of(),
            List.of(), null, "enforce", "all", ADMIN, "SYNTHETIC_CHANGE"), audit(ADMIN, "policy.draft"));
        approve("platform.claude", 2, "security_admin", ADMIN);
        registry.retirePlatform("platform.claude", OTHER_ADMIN, "Synthetic retirement",
            new AuditContext(OTHER_ADMIN, "policy.platform_retire", "Synthetic retirement", null), active -> { });
        assertEquals("superseded", status("platform.claude", 2));
        assertEquals("POLICY_NOT_PENDING", assertThrows(RegistryConflict.class,
            () -> approve("platform.claude", 2, "privacy_officer", OFFICER)).reason(),
            "one approver alone never completes the pre-retirement draft");
        assertTrue(registry.active().stream().noneMatch(v -> v.ruleId().equals("platform.claude")));
    }

    // PR 21 review D-05: a lifecycle time is written once, by its own transition; platform rows are enforce only.

    @Test
    void lifecycleTimesNeverChangeOnAnotherTransition() {
        registry.draft(classRule("TCKN", "BLOCK", "enforce", "all", ADMIN), audit(ADMIN, "policy.draft"));
        approve("class.TCKN", 2, "security_admin", ADMIN);
        approve("class.TCKN", 2, "privacy_officer", OFFICER);
        for (String sql : new String[] {
            "UPDATE policy_rule_version SET activated_at = NULL WHERE rule_id = 'class.TCKN' AND version = 1",
            "UPDATE policy_rule_version SET superseded_at = now() - interval '1 day' WHERE rule_id = 'class.TCKN' "
                + "AND version = 1"}) {
            DataAccessException e = assertThrows(DataAccessException.class, () -> mutate(sql), sql);
            assertTrue(e.getMessage().contains("POLICY_LIFECYCLE"), e.getMessage());
        }
        registry.draft(classRule("TCKN", "REDACT", "enforce", "all", ADMIN), audit(ADMIN, "policy.draft"));
        DataAccessException clear = assertThrows(DataAccessException.class, () -> mutate(
            "UPDATE policy_rule_version SET status = 'superseded', superseded_at = now(), activated_at = NULL "
                + "WHERE rule_id = 'class.TCKN' AND version = 2"));
        assertTrue(clear.getMessage().contains("POLICY_LIFECYCLE"), clear.getMessage());
        assertThrows(RegistryConflict.class, () -> registry.draft(new Draft("platform.claude", "platform", null, null,
            "claude", List.of("claude.ai"), List.of(), List.of(), null, "monitor", "all", ADMIN, "SYNTHETIC_CHANGE"),
            audit(ADMIN, "policy.draft")), "a platform row is enforce only");
    }

    // PR 16 review D-04: the activating approval runs the caller's check in the same transaction.

    @Test
    void aRefusedActivationCheckRollsTheApprovalBack() {
        registry.draft(classRule("TCKN", "BLOCK", "enforce", "all", ADMIN), audit(ADMIN, "policy.draft"));
        approve("class.TCKN", 2, "security_admin", ADMIN);
        List<List<String>> seen = new java.util.ArrayList<>();
        IllegalStateException refused = assertThrows(IllegalStateException.class, () -> registry.approve("class.TCKN", 2,
            "privacy_officer", OFFICER, audit(OFFICER, "policy.approve"), audit(OFFICER, "policy.activate"), active -> {
                seen.add(active.stream().map(PolicyRuleVersion::key).sorted().toList());
                throw new IllegalStateException("synthetic refusal");
            }));
        assertEquals("synthetic refusal", refused.getMessage());
        assertTrue(seen.get(0).contains("class.TCKN@v2") && !seen.get(0).contains("class.TCKN@v1"),
            "the check sees the would-be active set");
        PolicyRuleVersion after = registry.version("class.TCKN", 2).orElseThrow();
        assertEquals("pending", after.status());
        assertEquals(1, after.approvals().size());
        assertEquals("active", status("class.TCKN", 1));
        assertEquals(1, ledgerRows("policy_approval", "INSERT"));
    }

    @Test
    void theFlowIsNeverRelaxedInMonitorModeEither() {
        assertThrows(RegistryConflict.class, () -> registry.draft(new Draft("flow.ai-category", "flow", null, null, null,
            null, null, null, false, "monitor", "all", ADMIN, "SYNTHETIC_CHANGE"), audit(ADMIN, "policy.draft")));
    }

    // PR 16 review D-02: a stored snapshot is re-served only when it is exactly what the compiler renders.

    @Test
    void aTamperedOrFutureSnapshotRowIsNeverServedAgain() {
        PolicySnapshotStore snapshots = db.policySnapshots();
        Instant t0 = Instant.parse("2026-10-30T10:00:00Z");
        Duration refresh = Duration.ofHours(6);
        AuditContext issuer = audit("system:snapshot-issuer", "policy_snapshot.issue");
        IssuedSnapshot first = snapshots.current(SyntheticCompiler.INSTANCE, t0, refresh, issuer);
        String forged = "{\"version\":2,\"issuedAt\":\"2027-01-01T00:00:00Z\",\"forged\":true}";
        insertSnapshot(2, "2027-01-01T00:00:00Z", first.rulesDigest(), PolicySnapshotStore.sha256(forged), forged);
        IssuedSnapshot afterFuture = snapshots.current(SyntheticCompiler.INSTANCE, t0.plusSeconds(60), refresh, issuer);
        assertEquals(3, afterFuture.version(), "a future row is not reused");
        assertEquals(t0.plusSeconds(60), afterFuture.issuedAt(), "and its future time is not carried forward");
        assertEquals(SyntheticCompiler.INSTANCE.compile(registry.active()).render(3, t0.plusSeconds(60)).document(),
            afterFuture.document());

        String tampered = "{\"version\":4,\"issuedAt\":\"" + t0.plusSeconds(90) + "\",\"tampered\":true}";
        insertSnapshot(4, t0.plusSeconds(90).toString(), first.rulesDigest(), PolicySnapshotStore.sha256(tampered),
            tampered);
        assertEquals(5, snapshots.current(SyntheticCompiler.INSTANCE, t0.plusSeconds(120), refresh, issuer).version(),
            "a document that differs from the rendering is not reused");

        String honest = SyntheticCompiler.INSTANCE.compile(registry.active()).render(6, t0.plusSeconds(150)).document();
        insertSnapshot(6, t0.plusSeconds(150).toString(), first.rulesDigest(), "c".repeat(64), honest);
        assertEquals(7, snapshots.current(SyntheticCompiler.INSTANCE, t0.plusSeconds(180), refresh, issuer).version(),
            "a stored digest that does not match its document is not reused");
        IssuedSnapshot seventh = snapshots.latest().orElseThrow();
        assertEquals(seventh, snapshots.current(SyntheticCompiler.INSTANCE, t0.plusSeconds(200), refresh, issuer),
            "an honest row is reused");
    }

    private void insertSnapshot(long version, String issuedAt, String rulesDigest, String sha, String document) {
        mutate("INSERT INTO policy_snapshot (version, snapshot_id, issued_at, rules_digest, document_sha256, document, "
            + "rule_versions, approvers) VALUES (" + version + ", 'registry-" + rulesDigest.substring(0, 12) + "', '"
            + issuedAt + "', '" + rulesDigest + "', '" + sha + "', '" + document + "', ARRAY['class.SECRET@v1'], "
            + "ARRAY['system:seed-fixture'])");
    }

    @Test
    void snapshotsAreMonotonicReusedWhileUnchangedAndAppendOnly() {
        PolicySnapshotStore snapshots = db.policySnapshots();
        Instant t0 = Instant.parse("2026-10-30T10:00:00Z");
        Duration refresh = Duration.ofHours(6);
        AuditContext issuer = audit("system:snapshot-issuer", "policy_snapshot.issue");
        IssuedSnapshot first = snapshots.current(SyntheticCompiler.INSTANCE, t0, refresh, issuer);
        assertEquals(1, first.version());
        assertEquals(List.of("system:seed-fixture"), first.approvers());
        IssuedSnapshot again = snapshots.current(SyntheticCompiler.INSTANCE, t0.plusSeconds(60), refresh, issuer);
        assertEquals(first, again);

        registry.draft(classRule("TCKN", "BLOCK", "enforce", "all", ADMIN), audit(ADMIN, "policy.draft"));
        approve("class.TCKN", 2, "security_admin", ADMIN);
        approve("class.TCKN", 2, "privacy_officer", OFFICER);
        IssuedSnapshot changed = snapshots.current(SyntheticCompiler.INSTANCE, t0.plusSeconds(120), refresh, issuer);
        assertEquals(2, changed.version());
        assertTrue(changed.approvers().containsAll(List.of(ADMIN, OFFICER)));
        IssuedSnapshot refreshed = snapshots.current(SyntheticCompiler.INSTANCE, t0.plus(Duration.ofHours(7)), refresh,
            issuer);
        assertEquals(3, refreshed.version());
        assertEquals(changed.rulesDigest(), refreshed.rulesDigest());
        assertEquals(PolicySnapshotStore.sha256(refreshed.document()), refreshed.documentSha256());

        DataAccessException older = assertThrows(DataAccessException.class, () -> mutate(
            "INSERT INTO policy_snapshot (version, snapshot_id, issued_at, rules_digest, document_sha256, document, "
                + "rule_versions, approvers) VALUES (2, 'registry-000000000000', now(), repeat('a', 64), repeat('b', 64), "
                + "'{}', ARRAY['class.SECRET@v1'], ARRAY['system:seed-fixture'])"));
        assertTrue(older.getMessage().contains("SNAPSHOT_VERSION_NOT_MONOTONIC"));
        assertThrows(DataAccessException.class, () -> mutate("DELETE FROM policy_snapshot"));
        assertEquals(3, ledgerRows("policy_snapshot", "INSERT"));
    }

    @Test
    void theTriggerCodeIsReadFromThePostgresMessage() {
        assertEquals("POLICY_LIFECYCLE", PolicyRegistryStore.triggerCode(
            "SQL [update ...]; ERROR: POLICY_LIFECYCLE: active -> pending is refused"));
        assertEquals("POLICY_CONSTRAINT_REFUSED", PolicyRegistryStore.triggerCode(
            "ERROR: new row violates check constraint"));
        assertEquals("POLICY_CONSTRAINT_REFUSED", PolicyRegistryStore.triggerCode(null));
    }

    private void mutate(String sql) {
        db.dsl().transaction(cfg -> {
            var tx = DSL.using(cfg);
            audit("system:synthetic-test", "synthetic.mutation").apply(tx);
            tx.execute(sql);
        });
    }

    private void mutateAs(String actor, String reason, String sql) {
        db.dsl().transaction(cfg -> {
            var tx = DSL.using(cfg);
            new AuditContext(actor, "synthetic.mutation", reason, null).apply(tx);
            tx.execute(sql);
        });
    }

    private int ledgerRows(String table, String operation, String action, String rowKey) {
        return db.dsl().fetchCount(Schema.AUDIT_EVENT, Schema.AUDIT_TABLE.eq(table).and(Schema.AUDIT_OPERATION
            .eq(operation)).and(Schema.AUDIT_ACTION.eq(action)).and(Schema.AUDIT_ROW_KEY.eq(rowKey)));
    }

    private int ledgerRows(String table, String operation) {
        return db.dsl().fetchCount(Schema.AUDIT_EVENT,
            Schema.AUDIT_TABLE.eq(table).and(Schema.AUDIT_OPERATION.eq(operation)));
    }

    /** A stand-in for the control plane's compiler: the digest is the active rule versions with their content. */
    private enum SyntheticCompiler implements PolicySnapshotStore.Compiler {
        INSTANCE;

        @Override
        public Compiled compile(List<PolicyRuleVersion> active) {
            List<String> keys = active.stream().map(PolicyRuleVersion::key).sorted().toList();
            String digest = PolicySnapshotStore.sha256(active.stream()
                .map(v -> v.ruleId() + "=" + v.action() + "/" + v.hostSuffixes() + "/" + v.enforceFailClosed())
                .sorted().collect(Collectors.joining(";")));
            List<String> approvers = active.stream().flatMap(v -> v.approvals().isEmpty()
                ? java.util.stream.Stream.of(v.authorFingerprint())
                : v.approvals().stream().map(PolicyRuleVersion.PolicyApproval::approverFingerprint))
                .distinct().sorted().toList();
            return new Compiled() {
                @Override
                public String rulesDigest() {
                    return digest;
                }

                @Override
                public List<String> ruleVersions() {
                    return keys;
                }

                @Override
                public List<String> approvers() {
                    return approvers;
                }

                @Override
                public Rendered render(long version, Instant issuedAt) {
                    return new Rendered("registry-" + digest.substring(0, 12),
                        "{\"version\":" + version + ",\"issuedAt\":\"" + issuedAt + "\"}");
                }
            };
        }
    }

    @Test
    void theSameSnapshotIsServedByteForByte() {
        PolicySnapshotStore snapshots = db.policySnapshots();
        Instant t0 = Instant.parse("2026-10-30T10:00:00Z");
        AuditContext issuer = audit("system:snapshot-issuer", "policy_snapshot.issue");
        IssuedSnapshot a = snapshots.current(SyntheticCompiler.INSTANCE, t0, Duration.ofHours(6), issuer);
        IssuedSnapshot b = snapshots.latest().orElseThrow();
        assertEquals(a, b);
        assertEquals(a.document(), snapshots.current(SyntheticCompiler.INSTANCE, t0.plusSeconds(30), Duration.ofHours(6),
            issuer).document());
    }
}
