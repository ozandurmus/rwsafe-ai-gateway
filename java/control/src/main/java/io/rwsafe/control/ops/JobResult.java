package io.rwsafe.control.ops;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * What one run of a scheduled job did: ok or failed, a fixed failure code (an exception's simple class name or an
 * upper-case reason code, never a message), and counts under fixed keys (rows, files, keys; never a value).
 */
public record JobResult(boolean ok, String failure, Map<String, Long> counts) {

    public JobResult {
        counts = counts == null ? Map.of() : java.util.Collections.unmodifiableMap(new LinkedHashMap<>(counts));
    }

    public static JobResult ok(Map<String, Long> counts) {
        return new JobResult(true, null, counts);
    }

    public static JobResult failed(String failure, Map<String, Long> counts) {
        return new JobResult(false, failure, counts);
    }

    /** The failure code of a caught exception: its simple class name, never its message. */
    public static JobResult failed(Throwable t) {
        return failed(t.getClass().getSimpleName(), Map.of());
    }
}
