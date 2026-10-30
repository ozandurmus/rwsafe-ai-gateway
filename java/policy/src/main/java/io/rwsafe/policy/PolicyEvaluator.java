package io.rwsafe.policy;

import io.rwsafe.platform.verdict.DataClass;
import io.rwsafe.platform.verdict.Finding;
import io.rwsafe.platform.verdict.Verdict;
import java.util.List;

/**
 * Maps findings or a non-verdict to an action (ADR-010 flow rule, SR-DLP-1). Pure and allocation-light: it runs on the
 * request path for every transaction.
 */
public final class PolicyEvaluator {

    private final PolicySnapshot snapshot;

    public PolicyEvaluator(PolicySnapshot snapshot) {
        this.snapshot = snapshot;
    }

    /** Content was inspected: the strictest class action wins; no finding allows. */
    public Decision onFindings(List<Finding> findings, boolean redactable) {
        Action action = Action.ALLOW;
        DataClass deciding = null;
        for (Finding f : findings) {
            Action a = snapshot.actionFor(f.dataClass());
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
        return new Decision(verdict, action, deciding == null ? null : deciding.category(), deciding);
    }

    /**
     * The engine could not decide on content (oversize, malformed, timeout, failure, unknown flow): a fail-closed flow
     * blocks, any other flow allows with the non-verdict recorded (ADR-010 §1, SR-DLP-1).
     */
    public Decision onNonVerdict(Verdict nonVerdict, String reason) {
        if (!nonVerdict.isNonVerdict()) {
            throw new IllegalArgumentException("not a non-verdict: " + nonVerdict);
        }
        return new Decision(nonVerdict, snapshot.enforceFailClosed() ? Action.BLOCK : Action.ALLOW, reason, null);
    }
}
