package io.rwsafe.policy;

import io.rwsafe.platform.verdict.DataClass;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * One group-scoped rule of snapshot format 2 (POLICY_SNAPSHOT_CONTRACT.md "Format 2: scoped rules", PO decision Q-39).
 * {@code groups} are directory group names normalised by {@link #normaliseGroup}; they are runtime data and never appear
 * in an event, a log line or a metrics label. {@code classActions} is partial: only the classes this rule sets.
 *
 * @param id registry rule id and version, the only part of a rule that travels on a verdict event
 */
public record ScopedRule(String id, Set<String> groups, Mode mode, Map<DataClass, Action> classActions) {

    /** {@code enforce} changes the verdict; {@code monitor} is only reported on the verdict event. */
    public enum Mode { ENFORCE, MONITOR }

    public ScopedRule {
        if (id == null || id.isBlank() || groups == null || groups.isEmpty() || mode == null || classActions == null) {
            throw new IllegalArgumentException("a scoped rule needs an id, groups, a mode and class actions");
        }
        groups = Set.copyOf(groups);
        for (Map.Entry<DataClass, Action> e : classActions.entrySet()) {
            // ADR-010 §4, PO decision Q-39 item 4: no scope relaxes a fail-closed class.
            if (e.getKey().failClosed() && (e.getValue() == Action.ALLOW || e.getValue() == Action.WARN)) {
                throw new IllegalArgumentException("a scoped rule may not set a fail-closed class to ALLOW or WARN");
            }
        }
        classActions = Map.copyOf(classActions);
    }

    /** The comparison form of a group name on both sides (snapshot and proxy claim): trimmed, lower case. */
    public static String normaliseGroup(String group) {
        return group.strip().toLowerCase(Locale.ROOT);
    }

    /** Group names are identity data: never printed (AGENTS.md 4.14). */
    @Override
    public String toString() {
        return "ScopedRule[" + id + ", " + mode + ", " + groups.size() + " groups, " + classActions + "]";
    }
}
