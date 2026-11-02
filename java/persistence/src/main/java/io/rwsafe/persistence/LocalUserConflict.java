package io.rwsafe.persistence;

/**
 * A local-user change the stored state refuses, with a stable reason code ({@code LOCAL_USER_EXISTS},
 * {@code LOCAL_USER_NOT_FOUND}, {@code LAST_SECURITY_ADMIN}); the message names no value.
 */
public final class LocalUserConflict extends RuntimeException {

    private static final long serialVersionUID = 1L;
    private final String reason;

    public LocalUserConflict(String reason, String message) {
        super(message);
        this.reason = reason;
    }

    public String reason() {
        return reason;
    }
}
