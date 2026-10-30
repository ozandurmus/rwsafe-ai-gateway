package io.rwsafe.policy;

import io.rwsafe.platform.verdict.DataClass;
import io.rwsafe.platform.verdict.Finding;
import io.rwsafe.platform.verdict.Verdict;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Maps findings or a non-verdict to an action (ADR-010 flow rule, SR-DLP-1), and resolves the scoped rules of a format 2
 * snapshot per transaction (POLICY_SNAPSHOT_CONTRACT.md "Format 2: scoped rules", PO decision Q-39, ICAP spec identity
 * row, OFF2-12). Pure and allocation-light: it runs on the request path for every transaction. Everything that does not
 * depend on the transaction (the group index, the strictest resolution, the ANY resolution) is compiled once here.
 */
public final class PolicyEvaluator {

    private static final DataClass[] CLASSES = DataClass.values();

    private final PolicySnapshot snapshot;
    private final List<ScopedRule> rules;
    /** Normalised group name to the indexes of the rules naming it, in snapshot order. */
    private final Map<String, int[]> rulesByGroup;
    /** Step 3: no trusted claim. */
    private final EffectiveActions strictest;
    /** Step 2 with a trusted claim that matches no scoped rule: the ANY scope alone. */
    private final EffectiveActions anyScope;

    public PolicyEvaluator(PolicySnapshot snapshot) {
        this.snapshot = snapshot;
        this.rules = snapshot.scopedRules();
        Map<String, List<Integer>> index = new HashMap<>();
        for (int i = 0; i < rules.size(); i++) {
            for (String g : rules.get(i).groups()) {
                index.computeIfAbsent(g, k -> new ArrayList<>()).add(i);
            }
        }
        Map<String, int[]> compiled = new HashMap<>();
        index.forEach((g, ix) -> compiled.put(g, ix.stream().mapToInt(Integer::intValue).toArray()));
        this.rulesByGroup = Map.copyOf(compiled);
        this.strictest = resolveStrictest();
        this.anyScope = resolveTrusted(new boolean[rules.size()]);
    }

    /**
     * The effective class actions for one transaction.
     *
     * @param trusted       the connection is mutually authenticated Secure ICAP ({@code mtls_verified})
     * @param claimedGroups the proxy's group claim normalised by {@link GroupNames#normalise}, or null when the header
     *                      is missing or unparseable; an empty set is no claim either (PR 20 review D-04)
     */
    public EffectiveActions resolve(boolean trusted, Set<String> claimedGroups) {
        if (!trusted || claimedGroups == null || claimedGroups.isEmpty()) {
            return strictest;
        }
        boolean[] matched = null;
        for (String g : claimedGroups) {
            int[] ix = rulesByGroup.get(g);
            if (ix == null) {
                continue;
            }
            if (matched == null) {
                matched = new boolean[rules.size()];
            }
            for (int i : ix) {
                matched[i] = true;
            }
        }
        return matched == null ? anyScope : resolveTrusted(matched);
    }

    /** The resolution without a trusted claim (step 3); also what {@link #onFindings(List, boolean)} decides with. */
    public EffectiveActions strictest() {
        return strictest;
    }

    /**
     * Step 2: every matching enforce rule replaces the ANY action for the classes it sets, strictest wins among them.
     * A matching monitor rule is reported when, enforced, it would change the class action.
     */
    private EffectiveActions resolveTrusted(boolean[] matched) {
        List<Action> actions = new ArrayList<>(CLASSES.length);
        List<List<String>> applied = new ArrayList<>(CLASSES.length);
        List<List<String>> monitor = new ArrayList<>(CLASSES.length);
        for (DataClass c : CLASSES) {
            Action scoped = null;
            for (int i = 0; i < rules.size(); i++) {
                ScopedRule r = rules.get(i);
                Action a = r.classActions().get(c);
                if (matched[i] && a != null && r.mode() == ScopedRule.Mode.ENFORCE) {
                    scoped = scoped == null ? a : scoped.max(a);
                }
            }
            Action effective = scoped == null ? snapshot.actionFor(c) : scoped;
            List<String> appliedIds = new ArrayList<>();
            List<String> monitorIds = new ArrayList<>();
            for (int i = 0; i < rules.size(); i++) {
                ScopedRule r = rules.get(i);
                Action a = r.classActions().get(c);
                if (!matched[i] || a == null) {
                    continue;
                }
                if (r.mode() == ScopedRule.Mode.ENFORCE) {
                    if (a == effective) {
                        appliedIds.add(r.id());
                    }
                } else if ((scoped == null ? a : scoped.max(a)) != effective) {
                    monitorIds.add(r.id());
                }
            }
            actions.add(effective);
            applied.add(appliedIds);
            monitor.add(monitorIds);
        }
        return new EffectiveActions(actions, applied, monitor);
    }

    /**
     * Step 3: per class, the strictest of the ANY action and every enforce rule's action, whatever its groups. An enforce
     * rule counts as applied when it raised the class above the ANY action; a monitor rule is reported when, enforced, it
     * would raise it further.
     */
    private EffectiveActions resolveStrictest() {
        List<Action> actions = new ArrayList<>(CLASSES.length);
        List<List<String>> applied = new ArrayList<>(CLASSES.length);
        List<List<String>> monitor = new ArrayList<>(CLASSES.length);
        for (DataClass c : CLASSES) {
            Action any = snapshot.actionFor(c);
            Action effective = any;
            for (ScopedRule r : rules) {
                Action a = r.classActions().get(c);
                if (a != null && r.mode() == ScopedRule.Mode.ENFORCE) {
                    effective = effective.max(a);
                }
            }
            List<String> appliedIds = new ArrayList<>();
            List<String> monitorIds = new ArrayList<>();
            for (ScopedRule r : rules) {
                Action a = r.classActions().get(c);
                if (a == null) {
                    continue;
                }
                if (r.mode() == ScopedRule.Mode.ENFORCE) {
                    if (a == effective && effective != any) {
                        appliedIds.add(r.id());
                    }
                } else if (effective.max(a) != effective) {
                    monitorIds.add(r.id());
                }
            }
            actions.add(effective);
            applied.add(appliedIds);
            monitor.add(monitorIds);
        }
        return new EffectiveActions(actions, applied, monitor);
    }

    /** Content was inspected, no trusted claim: decides with {@link #strictest()}. */
    public Decision onFindings(List<Finding> findings, boolean redactable) {
        return onFindings(findings, redactable, strictest);
    }

    /**
     * Content was inspected: the strictest effective class action wins; no finding allows. The decision names the scoped
     * rules behind the found classes' actions and the monitor rules that would have changed them (rule ids only).
     */
    public Decision onFindings(List<Finding> findings, boolean redactable, EffectiveActions effective) {
        Action action = Action.ALLOW;
        DataClass deciding = null;
        for (Finding f : findings) {
            Action a = effective.actionFor(f.dataClass());
            if (a == Action.REDACT && !redactable) {
                a = Action.BLOCK;
            }
            if (deciding == null || a.ordinal() > action.ordinal()) {
                deciding = f.dataClass();
            }
            action = action.max(a);
        }
        Verdict verdict = switch (action) {
            case ALLOW -> Verdict.ALLOW;
            case WARN -> Verdict.WARN;
            case REDACT -> Verdict.REDACT;
            case BLOCK -> Verdict.BLOCK;
        };
        List<String> appliedIds = List.of();
        List<String> monitorIds = List.of();
        if (effective.hasRuleIds() && !findings.isEmpty()) {
            Set<String> a = new LinkedHashSet<>();
            Set<String> m = new LinkedHashSet<>();
            boolean[] seen = new boolean[CLASSES.length];
            for (Finding f : findings) {
                DataClass c = f.dataClass();
                if (!seen[c.ordinal()]) {
                    seen[c.ordinal()] = true;
                    a.addAll(effective.appliedFor(c));
                    m.addAll(effective.monitorFor(c));
                }
            }
            appliedIds = List.copyOf(a);
            monitorIds = List.copyOf(m);
        }
        return new Decision(verdict, action, deciding == null ? null : deciding.category(), deciding, appliedIds,
            monitorIds);
    }

    /**
     * The engine could not decide on content (oversize, malformed, timeout, failure, unknown flow): a fail-closed flow
     * blocks, any other flow allows with the non-verdict recorded (ADR-010 §1, SR-DLP-1). Scope does not change it.
     */
    public Decision onNonVerdict(Verdict nonVerdict, String reason) {
        if (!nonVerdict.isNonVerdict()) {
            throw new IllegalArgumentException("not a non-verdict: " + nonVerdict);
        }
        return new Decision(nonVerdict, snapshot.enforceFailClosed() ? Action.BLOCK : Action.ALLOW, reason, null);
    }
}
