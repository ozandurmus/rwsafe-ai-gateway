package io.rwsafe.control.identity;

import org.springframework.http.HttpStatus;

/**
 * An Administration -> Access request refused with a stable reason code and a sentence that names no value (never a
 * login name, a display name or a password); {@code status} is what the API answers.
 */
public final class AccessRefusal extends RuntimeException {

    private static final long serialVersionUID = 1L;
    private final String reason;
    private final HttpStatus status;

    public AccessRefusal(HttpStatus status, String reason, String message) {
        super(message);
        this.status = status;
        this.reason = reason;
    }

    public String reason() {
        return reason;
    }

    public HttpStatus status() {
        return status;
    }
}
