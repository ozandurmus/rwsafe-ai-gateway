package io.rwsafe.persistence;

/**
 * A registry change the stored state refuses, with a stable reason code (for example {@code POLICY_NOT_PENDING},
 * {@code APPROVER_ALREADY_APPROVED}); the message names no value.
 */
public final class RegistryConflict extends RuntimeException {

    private static final long serialVersionUID = 1L;
    private final String reason;

    public RegistryConflict(String reason, String message) {
        super(message);
        this.reason = reason;
    }

    public String reason() {
        return reason;
    }
}
