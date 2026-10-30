package io.rwsafe.dataplane.inspect;

import io.rwsafe.platform.content.BodyBearing;
import io.rwsafe.platform.content.BodyContent;
import io.rwsafe.platform.verdict.Finding;
import io.rwsafe.platform.verdict.Verdict;
import java.util.List;

/**
 * What body inspection found: either a non-verdict (the body could not be inspected) or the findings, whether the body
 * can be rewritten, and the rewritten body when a finding exists.
 */
@BodyBearing
public final class InspectionResult {

    private final Verdict nonVerdict;
    private final String reason;
    private final List<Finding> findings;
    private final boolean redactable;
    private final byte[] redactedBody;

    private InspectionResult(Verdict nonVerdict, String reason, List<Finding> findings, boolean redactable,
                             byte[] redactedBody) {
        this.nonVerdict = nonVerdict;
        this.reason = reason;
        this.findings = List.copyOf(findings);
        this.redactable = redactable;
        this.redactedBody = redactedBody;
    }

    static InspectionResult nonVerdict(Verdict v, String reason) {
        return new InspectionResult(v, reason, List.of(), false, null);
    }

    static InspectionResult inspected(List<Finding> findings, boolean redactable, byte[] redactedBody) {
        return new InspectionResult(null, null, findings, redactable, redactedBody);
    }

    /** Null when the body was inspected. */
    public Verdict nonVerdict() {
        return nonVerdict;
    }

    public String reason() {
        return reason;
    }

    public List<Finding> findings() {
        return findings;
    }

    public boolean redactable() {
        return redactable;
    }

    @BodyContent
    public byte[] redactedBody() {
        return redactedBody;
    }

    @Override
    public String toString() {
        return "InspectionResult[nonVerdict=" + nonVerdict + ", findings=" + findings.size() + "]";
    }
}
