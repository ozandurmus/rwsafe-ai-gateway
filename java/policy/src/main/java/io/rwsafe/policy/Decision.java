package io.rwsafe.policy;

import io.rwsafe.platform.verdict.DataClass;
import io.rwsafe.platform.verdict.Verdict;
import java.util.List;

/**
 * The outcome of evaluating one transaction: verdict, the action taken and the deciding class or reason (no value), and
 * the ids of the scoped rules applied and of the monitor rules that would have changed it (rule ids, never group names;
 * POLICY_SNAPSHOT_CONTRACT.md format 2).
 */
public record Decision(Verdict verdict, Action action, String reason, DataClass decidingClass,
                       List<String> appliedRuleIds, List<String> monitorRuleIds) {

    public Decision {
        appliedRuleIds = List.copyOf(appliedRuleIds);
        monitorRuleIds = List.copyOf(monitorRuleIds);
    }

    /** A decision no scoped rule took part in. */
    public Decision(Verdict verdict, Action action, String reason, DataClass decidingClass) {
        this(verdict, action, reason, decidingClass, List.of(), List.of());
    }
}
