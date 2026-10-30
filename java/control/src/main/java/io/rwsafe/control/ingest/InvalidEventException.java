package io.rwsafe.control.ingest;

/** A batch element breaks the contract; the message names the element index and the field, never the value. */
public final class InvalidEventException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public InvalidEventException(int index, String field) {
        super("event " + index + ": field '" + field + "' is missing or outside the ingestion contract");
    }

    public InvalidEventException(String message) {
        super(message);
    }
}
