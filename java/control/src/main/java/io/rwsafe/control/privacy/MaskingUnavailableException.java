package io.rwsafe.control.privacy;

/**
 * The privacy key, the estate dictionary or the name dictionary is missing: nothing is pseudonymised or served masked
 * (AGENTS.md 4.10).
 */
public final class MaskingUnavailableException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public MaskingUnavailableException(String what) {
        super(what);
    }
}
