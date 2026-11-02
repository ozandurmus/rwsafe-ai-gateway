package io.rwsafe.persistence;

import java.time.Instant;
import java.util.List;

/**
 * A local user (V11): the BCrypt hash only, never a password. {@code subjectFingerprint} is the login name's {@code USR-}
 * pseudonym, the key the ledger names the row by.
 */
public record LocalUser(String loginName, String subjectFingerprint, String displayName, String passwordHash,
                        List<String> roles, boolean enabled, boolean mustChangePassword, Instant createdAt,
                        Instant updatedAt, Instant passwordChangedAt) {

    public LocalUser {
        roles = List.copyOf(roles);
    }

    /** Never prints the hash, the login name or the display name. */
    @Override
    public String toString() {
        return "LocalUser[" + subjectFingerprint + ", " + roles + ", enabled=" + enabled + "]";
    }
}
