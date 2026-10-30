package io.rwsafe.dataplane.icap;

/** A frame the decoder refuses; carries the ICAP status to answer with (ICAP spec §4.5). Never carries frame bytes. */
public final class IcapProtocolException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final int status;

    public IcapProtocolException(int status, String reason) {
        super(reason, null, false, false);
        this.status = status;
    }

    public int status() {
        return status;
    }
}
