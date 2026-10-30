package io.rwsafe.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.platform.verdict.DataClass;
import io.rwsafe.platform.verdict.Finding;
import io.rwsafe.platform.verdict.Verdict;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Snapshot format 2: the codec's refusals and the four evaluation steps (POLICY_SNAPSHOT_CONTRACT.md, PO Q-39). */
class ScopedRulesTest {

    private static final Instant NOW = Instant.parse("2026-10-30T18:00:00Z");
    /** ANY scope: TCKN is BLOCK here so a group rule can be looser (REDACT) without touching ALLOW or WARN. */
    private static final String ANY = "\"SECRET\":\"BLOCK\",\"TCKN\":\"BLOCK\",\"TR_IBAN\":\"REDACT\",\"PAYMENT_CARD\":\"REDACT\"";

    private static String doc(String scopedRules) {
        return "{\"format\":2,\"version\":4,\"id\":\"registry-synthetic\",\"issuedAt\":\"2026-10-30T17:00:00Z\","
            + "\"enforceFailClosed\":true,\"classActions\":{" + ANY + "},\"platforms\":[],\"scopedRules\":["
            + scopedRules + "]}";
    }

    private static String rule(String id, String groups, String mode, String classes) {
        return "{\"id\":\"" + id + "\",\"groups\":[" + groups + "],\"mode\":\"" + mode + "\",\"classActions\":{" + classes
            + "}}";
    }

    private static PolicySnapshot parse(String json) throws SnapshotCodec.Rejected {
        return SnapshotCodec.parse(json.getBytes(StandardCharsets.UTF_8), NOW);
    }

    private static String reason(String json) {
        return assertThrows(SnapshotCodec.Rejected.class, () -> parse(json)).reason();
    }

    private static Finding found(DataClass c) {
        return new Finding(c, 0, 11);
    }

    // ---- codec ----

    @Test
    void parsesFormatTwoAndNormalisesGroups() throws Exception {
        PolicySnapshot s = parse(doc(rule("scope.pilot@2", "\" Pilot-Group \",\"pilot-group\"", "enforce",
            "\"TR_IBAN\":\"BLOCK\"")));
        assertEquals(1, s.scopedRules().size());
        ScopedRule r = s.scopedRules().get(0);
        assertEquals("scope.pilot@2", r.id());
        assertEquals(Set.of("pilot-group"), r.groups());
        assertEquals(ScopedRule.Mode.ENFORCE, r.mode());
        assertEquals(Map.of(DataClass.TR_IBAN, Action.BLOCK), r.classActions());
        assertTrue(parse(doc("")).scopedRules().isEmpty(), "an empty array is a format 2 snapshot without rules");
        assertTrue(!r.toString().contains("pilot-group"), "a rule never prints its groups");
    }

    @Test
    void formatOneIsFormatTwoWithoutScopedRules() throws Exception {
        String one = doc("").replace("\"format\":2", "\"format\":1").replace(",\"scopedRules\":[]", "");
        assertTrue(parse(one).scopedRules().isEmpty());
        assertEquals("FORMAT", reason(doc("").replace("\"format\":2", "\"format\":1")),
            "scopedRules belongs to format 2");
        assertEquals("SCOPE_FIELD", reason(doc("").replace(",\"scopedRules\":[]", "")),
            "format 2 carries the array, possibly empty");
    }

    @Test
    void refusesEveryScopedRuleOutsideTheContract() {
        String ok = "\"TCKN\":\"REDACT\"";
        assertEquals("SCOPE_FIELD", reason(doc(rule("a@1", "\"g\"", "enforce", ok).replace("}}", "},\"note\":1}"))),
            "unknown field");
        assertEquals("SCOPE_FIELD", reason(doc("{\"id\":\"a@1\",\"groups\":[\"g\"],\"mode\":\"enforce\"}")),
            "missing field");
        assertEquals("SCOPE_FIELD", reason(doc(rule("r".repeat(SnapshotCodec.MAX_RULE_ID + 1), "\"g\"", "enforce", ok))));
        assertEquals("SCOPE_DUPLICATE_ID",
            reason(doc(rule("a@1", "\"g\"", "enforce", ok) + "," + rule("a@1", "\"h\"", "monitor", ok))));
        assertEquals("SCOPE_GROUPS", reason(doc(rule("a@1", "", "enforce", ok))), "empty groups");
        assertEquals("SCOPE_GROUPS", reason(doc(rule("a@1", "\"  \"", "enforce", ok))), "blank group");
        assertEquals("SCOPE_GROUPS", reason(doc(rule("a@1", "\"" + "g".repeat(257) + "\"", "enforce", ok))));
        StringBuilder many = new StringBuilder();
        for (int i = 0; i < 33; i++) {
            many.append(i == 0 ? "" : ",").append("\"g").append(i).append('"');
        }
        assertEquals("SCOPE_GROUPS", reason(doc(rule("a@1", many.toString(), "enforce", ok))), "over 32 groups");
        assertEquals("SCOPE_GROUPS", reason(doc(rule("a@1", "7", "enforce", ok))), "a group that is not a string");
        assertEquals("SCOPE_MODE", reason(doc(rule("a@1", "\"g\"", "simulate", ok))));
        assertEquals("UNKNOWN_CLASS_OR_ACTION", reason(doc(rule("a@1", "\"g\"", "enforce", "\"PASSPORT\":\"BLOCK\""))));
        assertEquals("UNKNOWN_CLASS_OR_ACTION", reason(doc(rule("a@1", "\"g\"", "enforce", "\"TCKN\":\"QUARANTINE\""))));
        StringBuilder rules = new StringBuilder();
        for (int i = 0; i < 257; i++) {
            rules.append(i == 0 ? "" : ",").append(rule("r" + i + "@1", "\"g\"", "enforce", ok));
        }
        assertEquals("SCOPE_TOO_MANY", reason(doc(rules.toString())));
        assertEquals("MALFORMED", reason(doc("").replace("\"scopedRules\":[]", "\"scopedRules\":{}")));
    }

    /** PO decision Q-39 item 4: no scope, enforce or monitor, relaxes a fail-closed class. */
    @Test
    void noScopeMayWeakenAFailClosedClass() {
        for (String mode : List.of("enforce", "monitor")) {
            for (String weak : List.of("ALLOW", "WARN")) {
                assertEquals("FAIL_CLOSED_WEAKENED",
                    reason(doc(rule("a@1", "\"g\"", mode, "\"SECRET\":\"" + weak + "\""))), mode + " " + weak);
            }
        }
        assertThrows(IllegalArgumentException.class, () -> new ScopedRule("a@1", Set.of("g"), ScopedRule.Mode.ENFORCE,
            Map.of(DataClass.TCKN, Action.ALLOW)), "the model refuses it too");
    }

    // ---- evaluation ----

    private static final String STRICT_IBAN = rule("iban.strict@1", "\"finance\"", "enforce", "\"TR_IBAN\":\"BLOCK\"");
    private static final String LOOSE_TCKN = rule("tckn.loose@1", "\"support\"", "enforce", "\"TCKN\":\"REDACT\"");
    private static final String MONITOR_CARD = rule("card.watch@1", "\"support\"", "monitor", "\"PAYMENT_CARD\":\"BLOCK\"");

    private static PolicyEvaluator evaluator(String... rules) throws Exception {
        return new PolicyEvaluator(parse(doc(String.join(",", rules))));
    }

    @Test
    void anyIsTheBaselineWhenNoRuleExists() throws Exception {
        PolicyEvaluator e = evaluator();
        EffectiveActions trusted = e.resolve(true, Set.of("support"));
        for (DataClass c : DataClass.values()) {
            assertEquals(e.strictest().actionFor(c), trusted.actionFor(c));
        }
        assertEquals(Action.BLOCK, trusted.actionFor(DataClass.TCKN));
        assertEquals(Action.REDACT, trusted.actionFor(DataClass.TR_IBAN));
    }

    @Test
    void untrustedTakesTheStrictestOfAnyAndEveryEnforceRule() throws Exception {
        PolicyEvaluator e = evaluator(STRICT_IBAN, LOOSE_TCKN, MONITOR_CARD);
        for (EffectiveActions x : List.of(e.resolve(false, Set.of("support")), e.resolve(false, null),
            e.resolve(true, null))) {
            assertEquals(Action.BLOCK, x.actionFor(DataClass.TR_IBAN), "a stricter group rule applies to everyone");
            assertEquals(Action.BLOCK, x.actionFor(DataClass.TCKN), "a looser group rule has no effect");
            assertEquals(Action.REDACT, x.actionFor(DataClass.PAYMENT_CARD), "a monitor rule never changes the action");
        }
        Decision d = e.onFindings(List.of(found(DataClass.TR_IBAN), found(DataClass.TCKN)), true,
            e.resolve(false, Set.of("support")));
        assertEquals(Verdict.BLOCK, d.verdict());
        assertEquals(List.of("iban.strict@1"), d.appliedRuleIds(), "only the rule that raised a class is applied");
        assertEquals(List.of(), d.monitorRuleIds());
        assertSame(e.strictest(), e.resolve(false, Set.of("finance")), "plain connections share one resolution");
    }

    @Test
    void trustedClaimReplacesAnyForTheClassesTheRuleSets() throws Exception {
        PolicyEvaluator e = evaluator(STRICT_IBAN, LOOSE_TCKN);
        EffectiveActions support = e.resolve(true, Set.of("support"));
        assertEquals(Action.REDACT, support.actionFor(DataClass.TCKN), "a looser group rule applies on a trusted claim");
        assertEquals(Action.REDACT, support.actionFor(DataClass.TR_IBAN), "a rule of another group does not");
        assertEquals(Action.BLOCK, support.actionFor(DataClass.SECRET), "classes the rule does not set keep ANY");
        Decision d = e.onFindings(List.of(found(DataClass.TCKN)), true, support);
        assertEquals(Verdict.REDACT, d.verdict());
        assertEquals(List.of("tckn.loose@1"), d.appliedRuleIds());

        EffectiveActions finance = e.resolve(true, Set.of("finance"));
        assertEquals(Action.BLOCK, finance.actionFor(DataClass.TCKN), "ANY for a group without a TCKN rule");
        assertEquals(Action.BLOCK, finance.actionFor(DataClass.TR_IBAN));

        EffectiveActions nobody = e.resolve(true, Set.of("unrelated"));
        assertEquals(Action.BLOCK, nobody.actionFor(DataClass.TCKN));
        assertEquals(Action.REDACT, nobody.actionFor(DataClass.TR_IBAN), "a trusted claim matching no rule is ANY");
        assertEquals(List.of(), e.onFindings(List.of(found(DataClass.TR_IBAN)), true, nobody).appliedRuleIds());
    }

    @Test
    void severalMatchingRulesStrictestWins() throws Exception {
        PolicyEvaluator e = evaluator(LOOSE_TCKN,
            rule("tckn.strict@1", "\"Audit\"", "enforce", "\"TCKN\":\"BLOCK\""),
            rule("tckn.same@1", "\"support\"", "enforce", "\"TCKN\":\"REDACT\""));
        EffectiveActions both = e.resolve(true, Set.of("support", "audit"));
        assertEquals(Action.BLOCK, both.actionFor(DataClass.TCKN));
        assertEquals(List.of("tckn.strict@1"), both.appliedFor(DataClass.TCKN), "only the winning rule is applied");
        EffectiveActions support = e.resolve(true, Set.of("support"));
        assertEquals(Action.REDACT, support.actionFor(DataClass.TCKN));
        assertEquals(List.of("tckn.loose@1", "tckn.same@1"), support.appliedFor(DataClass.TCKN));
    }

    @Test
    void monitorRulesAreReportedNeverApplied() throws Exception {
        PolicyEvaluator e = evaluator(MONITOR_CARD,
            rule("tckn.watch@1", "\"support\"", "monitor", "\"TCKN\":\"REDACT\""),
            rule("iban.same@1", "\"support\"", "monitor", "\"TR_IBAN\":\"REDACT\""));
        EffectiveActions support = e.resolve(true, Set.of("support"));
        Decision d = e.onFindings(List.of(found(DataClass.PAYMENT_CARD), found(DataClass.TCKN),
            found(DataClass.TR_IBAN)), true, support);
        assertEquals(Verdict.BLOCK, d.verdict(), "TCKN stays BLOCK from ANY");
        assertEquals(Action.REDACT, support.actionFor(DataClass.PAYMENT_CARD));
        assertEquals(List.of("card.watch@1", "tckn.watch@1"), d.monitorRuleIds(),
            "matched monitor rules whose action would differ; a rule that agrees is not listed");
        assertEquals(List.of(), d.appliedRuleIds());

        Decision plain = e.onFindings(List.of(found(DataClass.PAYMENT_CARD), found(DataClass.TCKN)), true,
            e.resolve(false, null));
        assertEquals(Verdict.BLOCK, plain.verdict());
        assertEquals(List.of("card.watch@1"), plain.monitorRuleIds(),
            "without a trusted claim a monitor rule is reported when, enforced, it would raise the class");
        assertEquals(List.of(), e.onFindings(List.of(found(DataClass.TR_IBAN)), true, support).monitorRuleIds(),
            "only rules about the found classes are reported");
    }

    // ---- PR 20 second review (Argon) ----

    /** D-02: the snapshot's group and the claim meet in one comparison form, Turkish I included. */
    @Test
    void turkishGroupNamesMatchWhateverTheCase() throws Exception {
        PolicyEvaluator e = evaluator(rule("tckn.audit@1", "\"İç-Denetim\"", "enforce", "\"TCKN\":\"REDACT\""));
        for (String claimed : List.of("İÇ-DENETİM", "IÇ-DENETIM", "ıç-denetım")) {
            EffectiveActions x = e.resolve(true, Set.of(GroupNames.normalise(claimed)));
            assertEquals(Action.REDACT, x.actionFor(DataClass.TCKN), claimed);
            assertEquals(List.of("tckn.audit@1"), x.appliedFor(DataClass.TCKN));
        }
    }

    /** D-04: a rule built in code is validated and normalised like one read from a snapshot. */
    @Test
    void aRuleBuiltInCodeIsNormalisedAndValidated() {
        Map<DataClass, Action> block = Map.of(DataClass.TCKN, Action.BLOCK);
        ScopedRule r = new ScopedRule("a@1", Set.of(" Finance "), ScopedRule.Mode.ENFORCE, block);
        assertEquals(Set.of("finance"), r.groups());
        assertThrows(IllegalArgumentException.class,
            () -> new ScopedRule("a@1", Set.of("g"), ScopedRule.Mode.ENFORCE, Map.of()), "empty class map");
        for (String bad : List.of("  ", "a,b", "g\u0001", "g".repeat(257))) {
            assertThrows(IllegalArgumentException.class,
                () -> new ScopedRule("a@1", Set.of(bad), ScopedRule.Mode.ENFORCE, block), bad.length() + " chars");
        }
        PolicyEvaluator e = new PolicyEvaluator(new PolicySnapshot(2, "registry-synthetic",
            Map.of(DataClass.TCKN, Action.REDACT), true, List.of(), null, List.of(r)));
        assertEquals(Action.BLOCK, e.resolve(true, Set.of("finance")).actionFor(DataClass.TCKN));
    }

    /** D-04: the ANY scope refuses a relaxed fail-closed class whoever builds it. */
    @Test
    void aSnapshotBuiltInCodeCannotRelaxAFailClosedClass() {
        for (Action weak : List.of(Action.ALLOW, Action.WARN)) {
            assertThrows(IllegalArgumentException.class, () -> new PolicySnapshot(2, "registry-synthetic",
                Map.of(DataClass.TCKN, weak), true, List.of()), weak.name());
        }
    }

    /** D-04: an empty claim is no claim. */
    @Test
    void anEmptyTrustedClaimTakesTheStrictest() throws Exception {
        PolicyEvaluator e = evaluator(LOOSE_TCKN, STRICT_IBAN);
        assertSame(e.strictest(), e.resolve(true, Set.of()));
    }

    /** D-05: exact fields on the document and on platform rows, non-empty rule class maps, strict UTF-8. */
    @Test
    void refusesUnknownFieldsEmptyRuleMapsAndInvalidUtf8() throws Exception {
        String extra = "\"platforms\":[],\"extra\":1";
        assertEquals("FIELDS", reason(doc("").replace("\"platforms\":[]", extra)));
        String one = doc("").replace("\"format\":2", "\"format\":1").replace(",\"scopedRules\":[]", "");
        assertEquals("FIELDS", reason(one.replace("\"platforms\":[]", extra)));
        assertEquals("FIELDS", reason(one.replace(",\"platforms\":[]", "")), "missing field");
        String platform = "{\"platform\":\"claude\",\"hostSuffixes\":[\"anthropic.com\"],\"apiHosts\":[],"
            + "\"loginHosts\":[]";
        assertEquals(1, parse(doc("").replace("\"platforms\":[]", "\"platforms\":[" + platform + "}]"))
            .platforms().size());
        assertEquals("FIELDS", reason(doc("").replace("\"platforms\":[]",
            "\"platforms\":[" + platform + ",\"note\":\"x\"}]")));
        assertEquals("SCOPE_CLASS_ACTIONS", reason(doc(rule("a@1", "\"g\"", "enforce", ""))));
        String tckn = "\"TCKN\":\"BLOCK\"";
        assertEquals("SCOPE_GROUPS", reason(doc(rule("a@1", "\"finance,audit\"", "enforce", tckn))),
            "Q-2: no comma in a group name");
        assertEquals("SCOPE_GROUPS", reason(doc(rule("a@1", "\"fin\\u0001ance\"", "enforce", tckn))),
            "control character");
        assertEquals(1, parse(doc(rule("a@1", "\"  " + "g".repeat(256) + "  \"", "enforce", tckn)))
            .scopedRules().size(), "the length counts after strip");
        byte[] bytes = doc("").getBytes(StandardCharsets.UTF_8);
        int at = doc("").indexOf("registry-synthetic");
        bytes[at] = (byte) 0xC3;
        bytes[at + 1] = (byte) 0x28;
        assertEquals("MALFORMED", assertThrows(SnapshotCodec.Rejected.class,
            () -> SnapshotCodec.parse(bytes, NOW)).reason(), "malformed UTF-8 is refused, not replaced");
    }

    @Test
    void theOldEntryPointDecidesWithTheStrictestResolution() throws Exception {
        PolicyEvaluator e = evaluator(STRICT_IBAN);
        assertEquals(Verdict.BLOCK, e.onFindings(List.of(found(DataClass.TR_IBAN)), true).verdict());
    }
}
