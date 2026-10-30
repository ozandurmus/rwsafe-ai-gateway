package io.rwsafe.detect;

import io.rwsafe.platform.verdict.Finding;
import java.util.List;

/** Replaces every finding's range with its class token; overlapping ranges collapse into one token of the first class. */
public final class Redactor {

    private Redactor() {
    }

    /** {@code findings} must be sorted by start offset (as {@link DetectorSet#scan} returns them). */
    public static String redact(String text, List<Finding> findings) {
        if (findings.isEmpty()) {
            return text;
        }
        StringBuilder out = new StringBuilder(text.length());
        int cursor = 0;
        int i = 0;
        while (i < findings.size()) {
            Finding f = findings.get(i);
            int start = Math.max(f.start(), cursor);
            int end = f.end();
            int j = i + 1;
            while (j < findings.size() && findings.get(j).start() < end) {
                end = Math.max(end, findings.get(j).end());
                j++;
            }
            if (end > start) {
                out.append(text, cursor, start).append(f.dataClass().redactionToken());
                cursor = end;
            }
            i = j;
        }
        out.append(text, cursor, text.length());
        return out.toString();
    }
}
