package io.rwsafe.platform.verdict;

/**
 * The verdict of one inspected transaction (ICAP spec §4.3, §4.4). The non-verdicts ({@link #UNINSPECTABLE} through
 * {@link #UNKNOWN_FLOW}) are explicit outcomes, never a silent allow (AGENTS.md section 5); the ADR-010 flow rule maps
 * them to an action.
 */
public enum Verdict {
    ALLOW,
    WARN,
    REDACT,
    BLOCK,
    UNINSPECTABLE,
    MALFORMED,
    INSPECTION_FAILED,
    INSPECTION_TIMEOUT,
    UNKNOWN_FLOW,
    STREAM_ABORTED;

    /** True for the outcomes where the engine could not decide on content (SR-DLP-1 "non-verdicts"). */
    public boolean isNonVerdict() {
        return this == UNINSPECTABLE || this == MALFORMED || this == INSPECTION_FAILED || this == INSPECTION_TIMEOUT
            || this == UNKNOWN_FLOW;
    }
}
