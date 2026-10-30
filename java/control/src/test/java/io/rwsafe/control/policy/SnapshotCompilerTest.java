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

    private static List<PolicyRuleVersion> replacingClass(String dataClass, String action, String mode, String stage) {
        List<PolicyRuleVersion> out = new ArrayList<>();
        for (PolicyRuleVersion v : seedActive()) {
            if (v.ruleId().equals("class." + dataClass)) {
                Draft d = new Draft(v.ruleId(), v.kind(), v.dataClass(), v.action(), null, null, null, null, null,
                    mode, stage, "USR-00000000a1", "SYNTHETIC_CHANGE");
                out.add(version(d, 1, action, mode, stage));
            } else {
                out.add(v);
            }
        }
        return out;
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
