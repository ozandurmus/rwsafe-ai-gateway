package io.rwsafe.persistence;

import java.time.Instant;

/**
 * One notice acknowledgement (ADR-009 C12): proof that the user was informed of {@code noticeVersion}, never consent
 * (Q-32). The user is the {@code USR-} pseudonym; {@code recordedAt} is null before the row is stored.
 *
 * @param source {@code banner}, {@code ide_first_run}, {@code directory_attribute} (the HR policy acknowledgement
 *               imported from the directory, Q-35) or {@code gateway_credential_issue}
 */
public record NoticeAcknowledgement(String userPseudonym, String noticeVersion, Instant acknowledgedAt, String source,
                                    Instant recordedAt, String pseudonymKeyId) {
}
