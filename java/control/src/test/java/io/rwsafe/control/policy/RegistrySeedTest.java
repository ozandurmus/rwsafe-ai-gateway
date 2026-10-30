package io.rwsafe.control.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.control.support.ControlTestEnvironment;
import io.rwsafe.persistence.PolicyRuleVersion.Draft;
import io.rwsafe.platform.verdict.DataClass;
import io.rwsafe.policy.PlatformRule;
import io.rwsafe.policy.PolicySnapshot;
import io.rwsafe.policy.Snapshots;
import java.io.StringReader;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/** The committed seed fixture equals the built-in development snapshot and is read strictly. */
class RegistrySeedTest {

    private static final String VALID = """
        fixture: 1
        classActions:
          - {class: SECRET, action: BLOCK}
          - {class: TCKN, action: REDACT}
          - {class: TR_IBAN, action: REDACT}
          - {class: PAYMENT_CARD, action: REDACT}
        flow: {enforceFailClosed: true}
        platforms:
          - {platform: claude, hostSuffixes: [claude.ai], apiHosts: [api.claude.ai], loginHosts: []}
        """;

    @Test
    void theCommittedFixtureEqualsTheBuiltInDevelopmentSnapshot() {
        List<Draft> drafts = RegistrySeed.load(ControlTestEnvironment.seedFixture());
        PolicySnapshot builtin = Snapshots.builtinDevelopment();
        Map<String, String> classes = drafts.stream().filter(d -> d.kind().equals("class_action"))
            .collect(Collectors.toMap(Draft::dataClass, Draft::action));
        for (DataClass c : DataClass.values()) {
            assertEquals(builtin.actionFor(c).name(), classes.get(c.name()), c.name());
        }
        assertEquals(DataClass.values().length, classes.size());
        Draft flow = drafts.stream().filter(d -> d.kind().equals("flow")).findFirst().orElseThrow();
        assertEquals(builtin.enforceFailClosed(), flow.enforceFailClosed());
        List<PlatformRule> platforms = drafts.stream().filter(d -> d.kind().equals("platform"))
            .map(d -> new PlatformRule(d.platformId(), d.hostSuffixes(), d.apiHosts(), d.loginHosts())).toList();
        assertEquals(builtin.platforms(), platforms);
        assertTrue(drafts.stream().allMatch(d -> d.mode().equals("enforce") && d.rolloutStage().equals("all")
            && d.authorFingerprint().equals(RegistrySeed.SEED_ACTOR)));
    }

    @Test
    void aValidFixtureParses() {
        assertEquals(6, RegistrySeed.parse(new StringReader(VALID)).size());
    }

    @Test
    void everyDefectRefusesTheWholeFixture() {
        String[][] defects = {
            {"fixture: 1", "fixture: 2"},
            {"flow: {enforceFailClosed: true}", "flow: {enforceFailClosed: false}"},
            {"{class: TCKN, action: REDACT}", "{class: TCKN, action: ALLOW}"},
            {"{class: TCKN, action: REDACT}", "{class: TCKN, action: WARN}"},
            {"{class: TCKN, action: REDACT}", "{class: SECRET, action: BLOCK}"},
            {"{class: TCKN, action: REDACT}", "{class: TCKN, action: REDACT, note: x}"},
            {"{class: TCKN, action: REDACT}", "{class: UNKNOWN_CLASS, action: REDACT}"},
            {"apiHosts: [api.claude.ai]", "apiHosts: [api.other.example]"},
            {"hostSuffixes: [claude.ai]", "hostSuffixes: [192.0.2.10]"},
            {"hostSuffixes: [claude.ai]", "hostSuffixes: [Claude.AI]"},
            {"platforms:", "extra: true\nplatforms:"},
        };
        for (String[] d : defects) {
            String broken = VALID.replace(d[0], d[1]);
            assertTrue(!broken.equals(VALID), d[0]);
            assertThrows(IllegalArgumentException.class, () -> RegistrySeed.parse(new StringReader(broken)), d[1]);
        }
        String overlapping = VALID + "  - {platform: other, hostSuffixes: [x.claude.ai], apiHosts: [], loginHosts: []}\n";
        assertThrows(IllegalArgumentException.class, () -> RegistrySeed.parse(new StringReader(overlapping)));
    }

    @Test
    void theFixtureCarriesNoAddressOrEstateShape() throws Exception {
        String text = Files.readString(ControlTestEnvironment.seedFixture());
        assertTrue(text.contains("fixture: 1"));
        for (Draft d : RegistrySeed.load(ControlTestEnvironment.seedFixture())) {
            if (d.hostSuffixes() != null) {
                assertTrue(d.hostSuffixes().stream().allMatch(RegistryVocabulary::hostName), d.ruleId());
            }
        }
    }
}
