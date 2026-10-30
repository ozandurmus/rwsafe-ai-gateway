package io.rwsafe.policy;

import io.rwsafe.platform.verdict.DataClass;
import java.util.List;

/**
 * The class actions one transaction decides with after scope resolution (POLICY_SNAPSHOT_CONTRACT.md, format 2
 * evaluation steps 1 to 4), with the ids of the scoped rules behind each class action. Immutable; built only by
 * {@link PolicyEvaluator}. Holds rule ids, never group names.
 */
public final class EffectiveActions {

    private final List<Action> actions;
    private final List<List<String>> applied;
    private final List<List<String>> monitor;
    private final boolean anyIds;

    /** All three lists are indexed by {@link DataClass#ordinal()}. */
    EffectiveActions(List<Action> actions, List<List<String>> applied, List<List<String>> monitor) {
        this.actions = List.copyOf(actions);
        this.applied = applied.stream().map(List::copyOf).toList();
        this.monitor = monitor.stream().map(List::copyOf).toList();
        this.anyIds = this.applied.stream().anyMatch(l -> !l.isEmpty())
            || this.monitor.stream().anyMatch(l -> !l.isEmpty());
    }

    /** The action this transaction takes for a class. */
    public Action actionFor(DataClass dataClass) {
        return actions.get(dataClass.ordinal());
    }

    /** Ids of the enforce scoped rules that set {@link #actionFor} for this class; empty when the ANY action stands. */
    public List<String> appliedFor(DataClass dataClass) {
        return applied.get(dataClass.ordinal());
    }

    /** Ids of the monitor scoped rules that matched and would change this class's action if they were enforced. */
    public List<String> monitorFor(DataClass dataClass) {
        return monitor.get(dataClass.ordinal());
    }

    /** True when some class carries an applied or monitor rule id (lets the request path skip the id collection). */
    boolean hasRuleIds() {
        return anyIds;
    }

    @Override
    public String toString() {
        return "EffectiveActions" + actions;
    }
}
