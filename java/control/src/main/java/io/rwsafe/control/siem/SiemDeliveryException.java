package io.rwsafe.control.siem;

/**
 * A failed delivery, classified by a fixed reason (the metric label and the health detail). The message is a fixed
 * sentence: never a server response, a host name or an exported value.
 */
public final class SiemDeliveryException extends Exception {

    /** Fixed failure classes. */
    public enum Reason { CONNECT, TLS, IO, TIMEOUT, AUTH, REJECTED, UNAVAILABLE, DATABASE }

    private static final long serialVersionUID = 1L;

    private final Reason reason;

    public SiemDeliveryException(Reason reason, String fixedMessage) {
        super(fixedMessage, null, false, false);
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }
}
