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
            stage, author, "SYNTHETIC_CHANGE");
    }

    private static AuditContext audit(String actor, String action) {
        return new AuditContext(actor, action, "SYNTHETIC_CHANGE", null);
    }

    private PolicyRuleVersion approve(String ruleId, int version, String role, String who) {
        return registry.approve(ruleId, version, role, who, audit(who, "policy.approve"),
            audit("system:policy-registry", "policy.activate"));
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
    void anEnforceVersionNeverAllowsOrWarnsAFailClosedClassAndTheFlowIsNeverRelaxed() {
        for (String action : new String[] {"ALLOW", "WARN"}) {
            RegistryConflict refused = assertThrows(RegistryConflict.class, () -> registry.draft(
                classRule("TCKN", action, "enforce", "all", ADMIN), audit(ADMIN, "policy.draft")));
            assertEquals("POLICY_CONSTRAINT_REFUSED", refused.reason());
        }
        assertThrows(RegistryConflict.class, () -> registry.draft(new Draft("flow.ai-category", "flow", null, null, null,
            null, null, null, false, "enforce", "all", ADMIN, "SYNTHETIC_CHANGE"), audit(ADMIN, "policy.draft")));
        assertEquals("pending", registry.draft(classRule("TCKN", "ALLOW", "monitor", "all", ADMIN),
            audit(ADMIN, "policy.draft")).status(), "a monitor version is simulation only");
        assertThrows(RegistryConflict.class, () -> registry.draft(new Draft("platform.claude", "platform", null, null,
            "claude", List.of("192.0.2.10"), List.of(), List.of(), null, "enforce", "all", ADMIN, "SYNTHETIC_CHANGE"),
            audit(ADMIN, "policy.draft")), "an address is not a host name");
    }

    @Test
    void aStagedVersionKeepsTheBaselineUntilAVersionReachesAll() {
        registry.draft(classRule("TCKN", "BLOCK", "enforce", "pilot", ADMIN), audit(ADMIN, "policy.draft"));
        approve("class.TCKN", 2, "security_admin", ADMIN);
        approve("class.TCKN", 2, "privacy_officer", OFFICER);
        assertEquals("active", status("class.TCKN", 1));
        assertEquals("active", status("class.TCKN", 2));

        registry.draft(classRule("TCKN", "BLOCK", "enforce", "pct50", ADMIN), audit(ADMIN, "policy.draft"));
        approve("class.TCKN", 3, "security_admin", ADMIN);
        approve("class.TCKN", 3, "privacy_officer", OFFICER);
        assertEquals("active", status("class.TCKN", 1));
        assertEquals("superseded", status("class.TCKN", 2));

        registry.draft(classRule("TCKN", "BLOCK", "enforce", "all", ADMIN), audit(ADMIN, "policy.draft"));
        registry.draft(classRule("TCKN", "REDACT", "enforce", "all", ADMIN), audit(ADMIN, "policy.draft"));
        approve("class.TCKN", 5, "security_admin", ADMIN);
        approve("class.TCKN", 5, "privacy_officer", OFFICER);
        assertEquals(List.of(5), registry.active().stream().filter(v -> v.ruleId().equals("class.TCKN"))
            .map(PolicyRuleVersion::version).toList());
        assertEquals("NEWER_VERSION_ACTIVE", assertThrows(RegistryConflict.class,
            () -> approve("class.TCKN", 4, "security_admin", ADMIN)).reason());
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
