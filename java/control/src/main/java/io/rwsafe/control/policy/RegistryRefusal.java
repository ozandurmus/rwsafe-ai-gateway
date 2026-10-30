package io.rwsafe.control.policy;

import org.springframework.http.HttpStatus;

/**
 * A registry request refused with a stable reason code and a sentence that names no value; {@code status} is what the
 * API answers (400 for a malformed request, 403 for a missing role, 409 for a rule the registry refuses, 503 when a
 * prerequisite such as the privacy key is missing).
 */
public final class RegistryRefusal extends RuntimeException {

    private static final long serialVersionUID = 1L;
    private final String reason;
    private final HttpStatus status;

    public RegistryRefusal(HttpStatus status, String reason, String message) {
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
