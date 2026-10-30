package io.rwsafe.control.notice;

/**
 * One element of {@code POST /internal/v1/notice-acknowledgements}: who (the directory identity claim, pseudonymised
 * before anything is stored), which notice version, when, and from which source. Every field is required; an unknown
 * field refuses the batch. {@code userClaim} lives only in this request object.
 *
 * @param source {@code banner}, {@code ide_first_run}, {@code directory_attribute} (the HR policy acknowledgement read
 *               from the directory; it counts only with its version and date, Q-35) or {@code gateway_credential_issue}
 */
public record AcknowledgementPayload(String userClaim, String noticeVersion, String acknowledgedAt, String source) {

    /** Never prints the identity claim (AGENTS.md 4.14). */
    @Override
    public String toString() {
        return "AcknowledgementPayload[" + noticeVersion + ", " + source + "]";
    }
}
