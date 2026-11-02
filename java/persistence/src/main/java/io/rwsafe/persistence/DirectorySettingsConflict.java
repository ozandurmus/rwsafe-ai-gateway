package io.rwsafe.persistence;

/** A directory settings save the stored state refuses, with a stable reason code; the message names no value. */
public final class DirectorySettingsConflict extends RuntimeException {

    private static final long serialVersionUID = 1L;
    private final String reason;

    public DirectorySettingsConflict(String reason, String message) {
        super(message);
        this.reason = reason;
    }

    public String reason() {
        return reason;
    }
}
