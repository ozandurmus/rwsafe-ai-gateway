package io.rwsafe.control.siem;

import io.rwsafe.control.siem.SiemField.SiemStream;
import io.rwsafe.persistence.SiemExportStore.VerdictPosition;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * One event on its way to the SIEM, in a format-neutral shape: the fixed fields of {@link SiemField} with values that are
 * already cleaned (SR-SIEM-1) and length-capped per field. Built only by {@link SiemRecords}. The watermark position
 * travels with it ({@code verdictPosition} for a verdict event, {@code auditId} for a ledger row) and is never exported.
 *
 * @param eventClassId CEF Device Event Class ID and LEEF EventID, for example {@code verdict.BLOCK}
 * @param name         the CEF Name, a fixed sentence plus a vocabulary token
 * @param severity     0 to 10 (CEF); the syslog and LEEF severities derive from it
 */
public record SiemRecord(SiemStream stream, String eventClassId, String name, int severity, Instant time,
                         List<Value> values, VerdictPosition verdictPosition, long auditId) {

    static final int MAX_CLASS_ID = 96;
    static final int MAX_NAME = 128;

    /** One field and its cleaned text. */
    public record Value(SiemField field, String text) {
    }

    public SiemRecord {
        Objects.requireNonNull(stream, "stream");
        Objects.requireNonNull(time, "time");
        if (stream == SiemStream.BOTH) {
            throw new IllegalArgumentException("a record belongs to one stream");
        }
        if (severity < 0 || severity > 10) {
            throw new IllegalArgumentException("severity is 0 to 10");
        }
        if ((stream == SiemStream.VERDICT) != (verdictPosition != null)) {
            throw new IllegalArgumentException("a verdict record carries its position, an audit record its id");
        }
        eventClassId = nonEmpty(SiemText.clean(eventClassId, MAX_CLASS_ID), "unknown");
        name = nonEmpty(SiemText.clean(name, MAX_NAME), "rwsafe event");
        List<Value> cleaned = new ArrayList<>(values.size());
        Set<SiemField> seen = EnumSet.noneOf(SiemField.class);
        for (Value v : values) {
            if (!v.field().allowedIn(stream) || !seen.add(v.field())) {
                throw new IllegalArgumentException(v.field() + " is not a field of a " + stream + " record");
            }
            String text = SiemText.clean(v.text(), v.field().maxLength());
            if (text != null && !text.isEmpty()) {
                cleaned.add(new Value(v.field(), text));
            }
        }
        values = List.copyOf(cleaned);
    }

    public String value(SiemField field) {
        for (Value v : values) {
            if (v.field() == field) {
                return v.text();
            }
        }
        return null;
    }

    /** RFC 5424 severity: 4 warning for 7 and above, 5 notice for 5 and 6, otherwise 6 informational. */
    public int syslogSeverity() {
        return severity >= 7 ? 4 : severity >= 5 ? 5 : 6;
    }

    private static String nonEmpty(String s, String fallback) {
        return s == null || s.isEmpty() ? fallback : s;
    }

    /** Never prints a value. */
    @Override
    public String toString() {
        return "SiemRecord[" + stream + ", " + eventClassId + "]";
    }
}
