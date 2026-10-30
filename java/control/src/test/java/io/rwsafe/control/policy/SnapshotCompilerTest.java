package io.rwsafe.control.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.rwsafe.control.support.ControlTestEnvironment;
import io.rwsafe.persistence.PolicyRuleVersion;
import io.rwsafe.persistence.PolicyRuleVersion.Draft;
import io.rwsafe.persistence.PolicyRuleVersion.PolicyApproval;
import io.rwsafe.persistence.PolicySnapshotStore;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.junit.jupiter.api.Test;

/** POLICY_SNAPSHOT_CONTRACT format 1, compiled from the registry's active versions. */
class SnapshotCompilerTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private final SnapshotCompiler compiler = new SnapshotCompiler();

    static List<PolicyRuleVersion> seedActive() {
        List<PolicyRuleVersion> out = new ArrayList<>();
        for (Draft d : RegistrySeed.load(ControlTestEnvironment.seedFixture())) {
            out.add(version(d, 1, d.action(), d.mode(), d.rolloutStage()));
        }
        return out;
    }

    static PolicyRuleVersion version(Draft d, int v, String action, String mode, String stage) {
        return new PolicyRuleVersion(d.ruleId(), v, d.kind(), d.dataClass(), action, d.platformId(), d.hostSuffixes(),
            d.apiHosts(), d.loginHosts(), d.enforceFailClosed(), mode, stage, "active", "seed", d.authorFingerprint(),
            d.reasonCode(), Instant.EPOCH, Instant.EPOCH, null, List.of());
    }

    static final List<PolicyApproval> TWO_APPROVALS = List.of(
        new PolicyApproval("security_admin", "USR-00000000a1", Instant.EPOCH),
        new PolicyApproval("privacy_officer", "USR-00000000b2", Instant.EPOCH));

    /** A registry version 2 of {@code ruleId}'s class, active, with the given approvals. */
    static PolicyRuleVersion registryVersion(PolicyRuleVersion seed, String action, String mode, String stage,
                                             List<PolicyApproval> approvals) {
        return new PolicyRuleVersion(seed.ruleId(), 2, seed.kind(), seed.dataClass(), action, seed.platformId(),
            seed.hostSuffixes(), seed.apiHosts(), seed.loginHosts(), seed.enforceFailClosed(), mode, stage, "active",
            "registry", "USR-00000000a1", "SYNTHETIC_CHANGE", Instant.EPOCH, Instant.EPOCH, null, approvals);
    }

    private static List<PolicyRuleVersion> replacing(String ruleId, java.util.function.UnaryOperator<PolicyRuleVersion> f) {
        List<PolicyRuleVersion> out = new ArrayList<>();
        for (PolicyRuleVersion v : seedActive()) {
            out.add(v.ruleId().equals(ruleId) ? f.apply(v) : v);
        }
        return out;
    }

    private static List<PolicyRuleVersion> replacingClass(String dataClass, String action, String mode, String stage) {
        return replacing("class." + dataClass, v -> registryVersion(v, action, mode, stage, TWO_APPROVALS));
    }

    @Test
    void theDocumentHasExactlyTheContractFieldsInOrder() throws Exception {
        PolicySnapshotStore.Compiled compiled = compiler.compile(seedActive());
        String doc = compiled.render(13, Instant.parse("2026-10-30T18:00:00.123456Z")).document();
        JsonNode root = JSON.readTree(doc);
        List<String> fields = new ArrayList<>();
        for (Iterator<String> it = root.fieldNames(); it.hasNext(); ) {
            fields.add(it.next());
        }
        assertEquals(List.of("format", "version", "id", "issuedAt", "enforceFailClosed", "classActions", "platforms"),
            fields);
        assertEquals(1, root.get("format").asInt());
        assertEquals(13, root.get("version").asLong());
        assertTrue(root.get("id").asText().matches("registry-[0-9a-f]{12}"));
        assertEquals("2026-10-30T18:00:00Z", root.get("issuedAt").asText());
        assertTrue(root.get("enforceFailClosed").asBoolean());
        assertEquals("{\"SECRET\":\"BLOCK\",\"TCKN\":\"REDACT\",\"TR_IBAN\":\"REDACT\",\"PAYMENT_CARD\":\"REDACT\"}",
            root.get("classActions").toString());
        assertEquals(9, root.get("platforms").size());
        JsonNode claude = root.get("platforms").get(0);
        assertEquals("{\"platform\":\"claude\",\"hostSuffixes\":[\"claude.ai\",\"anthropic.com\"],"
            + "\"apiHosts\":[\"api.anthropic.com\"],\"loginHosts\":[]}", claude.toString());
        assertEquals(List.of(RegistrySeed.SEED_ACTOR), compiled.approvers());
        assertEquals(14, compiled.ruleVersions().size());
    }

    @Test
    void theDocumentIsOneTheDataPlaneCodecAccepts() throws Exception {
        Instant now = Instant.parse("2026-10-30T18:00:00Z");
        byte[] body = compiler.compile(replacingClass("TCKN", "BLOCK", "enforce", "all")).render(7, now).document()
            .getBytes(java.nio.charset.StandardCharsets.UTF_8);
        io.rwsafe.policy.PolicySnapshot parsed = io.rwsafe.policy.SnapshotCodec.parse(body, now.plusSeconds(30));
        assertEquals(7, parsed.version());
        assertEquals(io.rwsafe.policy.Action.BLOCK,
            parsed.actionFor(io.rwsafe.platform.verdict.DataClass.TCKN));
        assertEquals(9, parsed.platforms().size());
    }

    // PR 16 review D-01: a compiled version is the seed's or holds two approvals; a snapshot has platform rows.

    @Test
    void aVersionWithoutTwoApprovalsByTwoPeopleIsNeverCompiled() {
        PolicyApproval admin = TWO_APPROVALS.get(0);
        PolicyApproval officer = TWO_APPROVALS.get(1);
        List<List<PolicyApproval>> refused = List.of(
            List.of(),
            List.of(admin),
            List.of(admin, new PolicyApproval("privacy_officer", admin.approverFingerprint(), Instant.EPOCH)),
            List.of(admin, new PolicyApproval("security_admin", officer.approverFingerprint(), Instant.EPOCH)));
        for (List<PolicyApproval> approvals : refused) {
            List<PolicyRuleVersion> active = replacing("class.TCKN",
                v -> registryVersion(v, "BLOCK", "enforce", "all", approvals));
            assertEquals("SNAPSHOT_APPROVAL_MISSING",
                assertThrows(RegistryRefusal.class, () -> compiler.compile(active)).reason(), approvals.toString());
        }
        List<PolicyRuleVersion> platformWithoutApproval = replacing("platform.claude",
            v -> registryVersion(v, null, "enforce", "all", List.of()));
        assertEquals("SNAPSHOT_APPROVAL_MISSING",
            assertThrows(RegistryRefusal.class, () -> compiler.compile(platformWithoutApproval)).reason());
        List<PolicyRuleVersion> forgedSeed = replacing("class.SECRET", v -> new PolicyRuleVersion(v.ruleId(), 3,
            v.kind(), v.dataClass(), v.action(), null, null, null, null, null, "enforce", "all", "active", "seed",
            RegistrySeed.SEED_ACTOR, "SEED_FIXTURE", Instant.EPOCH, Instant.EPOCH, null, List.of()));
        assertEquals("SNAPSHOT_APPROVAL_MISSING",
            assertThrows(RegistryRefusal.class, () -> compiler.compile(forgedSeed)).reason(), "a seed is version 1");
    }

    @Test
    void aSnapshotWithoutPlatformRowsIsNeverCompiled() {
        List<PolicyRuleVersion> noPlatforms = seedActive().stream().filter(v -> !v.kind().equals("platform")).toList();
        assertEquals("SNAPSHOT_REGISTRY_INCOMPLETE",
            assertThrows(RegistryRefusal.class, () -> compiler.compile(noPlatforms)).reason());
    }

    @Test
    void theDigestFollowsTheRulesNotTheVersionOrTime() {
        String a = compiler.compile(seedActive()).rulesDigest();
        assertEquals(a, compiler.compile(seedActive()).rulesDigest());
        assertNotEquals(a, compiler.compile(replacingClass("TCKN", "BLOCK", "enforce", "all")).rulesDigest());
    }

    @Test
    void aFailClosedClassIsNeverCompiledAsAllowOrWarn() {
        // The V2 checks already refuse such a version; the compiler refuses it again, whatever enforceFailClosed says
        // (POLICY_SNAPSHOT_CONTRACT: the data plane refuses such a snapshot).
        for (String action : new String[] {"ALLOW", "WARN"}) {
            RegistryRefusal refused = assertThrows(RegistryRefusal.class,
                () -> compiler.compile(replacingClass("SECRET", action, "enforce", "all")));
            assertEquals("SNAPSHOT_FAIL_CLOSED_RELAXED", refused.reason());
        }
    }

    @Test
    void onlyActiveEnforceBaselinesAreCompiled() {
        List<PolicyRuleVersion> withStagedAndMonitor = new ArrayList<>(seedActive());
        Draft tckn = new Draft("class.TCKN", "class_action", "TCKN", "BLOCK", null, null, null, null, null, "enforce",
            "pilot", "USR-00000000a1", "SYNTHETIC_CHANGE");
        withStagedAndMonitor.add(version(tckn, 2, "BLOCK", "enforce", "pilot"));
        withStagedAndMonitor.add(version(tckn, 3, "BLOCK", "monitor", "all"));
        assertEquals(compiler.compile(seedActive()).rulesDigest(),
            compiler.compile(withStagedAndMonitor).rulesDigest());

        List<PolicyRuleVersion> withoutTckn = seedActive().stream().filter(v -> !v.ruleId().equals("class.TCKN"))
            .toList();
        assertEquals("SNAPSHOT_REGISTRY_INCOMPLETE",
            assertThrows(RegistryRefusal.class, () -> compiler.compile(withoutTckn)).reason());
        List<PolicyRuleVersion> monitorOnly = replacingClass("TCKN", "REDACT", "monitor", "all");
        assertEquals("SNAPSHOT_REGISTRY_INCOMPLETE",
            assertThrows(RegistryRefusal.class, () -> compiler.compile(monitorOnly)).reason());
    }
}
