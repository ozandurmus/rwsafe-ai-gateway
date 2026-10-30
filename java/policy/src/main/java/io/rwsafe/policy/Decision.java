package io.rwsafe.policy;

import io.rwsafe.platform.verdict.DataClass;
import io.rwsafe.platform.verdict.Verdict;

/** The outcome of evaluating one transaction: verdict, the action taken and the deciding class or reason (no value). */
public record Decision(Verdict verdict, Action action, String reason, DataClass decidingClass) {
}
