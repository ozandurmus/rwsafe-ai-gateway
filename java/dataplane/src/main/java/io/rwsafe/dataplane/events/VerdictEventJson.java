package io.rwsafe.dataplane.events;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Serialises verdict events as the JSON array the control plane's ingestion endpoint accepts. Reads captured content
 * ({@link CapturedText#text()}), so this class never logs (AGENTS.md 4.14); it runs on the shipper thread only.
 */
public final class VerdictEventJson {

    /**
     * The most characters one posted array holds: a character is at most 3 UTF-8 bytes, so an array stays under 1.5 MiB,
     * below the control plane's 2 MiB request cap (one event is at most its bounded capture, escaped, plus metadata).
     */
    public static final int MAX_ARRAY_CHARS = 512 * 1024;

    private VerdictEventJson() {
    }

    /** One array to post or spool: its JSON, how many events it holds and how many of them carry captured content. */
    public record Chunk(String json, List<VerdictEvent> events, int captures) {

        public Chunk {
            events = List.copyOf(events);
        }

        @Override
        public String toString() {
            return "Chunk[events=" + events.size() + ", captures=" + captures + "]";
        }
    }

    /** All events in one array, captured content included. */
    public static String array(List<VerdictEvent> events) {
        StringBuilder s = new StringBuilder("[");
        for (int i = 0; i < events.size(); i++) {
            if (i > 0) {
                s.append(',');
            }
            object(s, events.get(i), true);
        }
        return s.append(']').toString();
    }

    /**
     * The events in order, as arrays of at most {@code maxChars} characters each (an event larger than that alone gets
     * its own array). With {@code includeCapture} false no captured content is written (the spool watermark).
     */
    public static List<Chunk> chunks(List<VerdictEvent> events, boolean includeCapture, int maxChars) {
        List<Chunk> out = new ArrayList<>();
        StringBuilder s = new StringBuilder("[");
        List<VerdictEvent> in = new ArrayList<>();
        int captures = 0;
        StringBuilder one = new StringBuilder();
        for (VerdictEvent e : events) {
            one.setLength(0);
            object(one, e, includeCapture);
            if (!in.isEmpty() && s.length() + 1 + one.length() + 1 > maxChars) {
                out.add(new Chunk(s.append(']').toString(), in, captures));
                s.setLength(0);
                s.append('[');
                in.clear();
                captures = 0;
            }
            if (!in.isEmpty()) {
                s.append(',');
            }
            s.append(one);
            in.add(e);
            if (includeCapture && e.capture() != null) {
                captures++;
            }
        }
        if (!in.isEmpty()) {
            out.add(new Chunk(s.append(']').toString(), in, captures));
        }
        return out;
    }

    private static void object(StringBuilder s, VerdictEvent e, boolean includeCapture) {
        s.append('{');
        field(s, "eventId", e.eventId().toString()).append(',');
        field(s, "receivedAt", e.receivedAt().toString()).append(',');
        field(s, "service", e.service()).append(',');
        field(s, "platform", e.platform()).append(',');
        field(s, "surface", e.surface()).append(',');
        field(s, "step", e.step()).append(',');
        field(s, "verdict", e.verdict().name()).append(',');
        field(s, "reason", e.reason()).append(',');
        s.append("\"findings\":[");
        boolean first = true;
        for (Map.Entry<String, Integer> f : new TreeMap<>(e.findings()).entrySet()) {
            if (!first) {
                s.append(',');
            }
            first = false;
            s.append('{');
            field(s, "class", f.getKey()).append(",\"count\":").append(f.getValue()).append('}');
        }
        s.append("],");
        s.append("\"bodyBytes\":").append(e.bodyBytes()).append(',');
        s.append("\"decisionMicros\":").append(e.decisionMicros()).append(',');
        field(s, "userClaim", e.userClaim()).append(',');
        field(s, "clientAddress", e.clientAddress()).append(',');
        field(s, "transport", e.transport()).append(',');
        s.append("\"snapshotVersion\":").append(e.snapshotVersion()).append(',');
        field(s, "correlationId", e.correlationId());
        // Snapshot format 2: written only when a scoped rule took part, so an event without one keeps the exact field
        // set the ingestion endpoint accepts today (it refuses unknown fields).
        ids(s, "appliedRuleIds", e.appliedRuleIds());
        ids(s, "monitorRuleIds", e.monitorRuleIds());
        // C3 (Q-4 b): written only when present, so an event without it keeps the exact earlier field set.
        CapturedText capture = e.capture();
        if (includeCapture && capture != null) {
            s.append(",\"capture\":{");
            field(s, "text", capture.text()).append(',');
            s.append("\"truncated\":").append(capture.truncated()).append(',');
            s.append("\"redactedBytes\":").append(capture.redactedBytes()).append('}');
        }
        s.append('}');
    }

    private static void ids(StringBuilder s, String name, List<String> ids) {
        if (ids.isEmpty()) {
            return;
        }
        s.append(",\"").append(name).append("\":[");
        for (int i = 0; i < ids.size(); i++) {
            if (i > 0) {
                s.append(',');
            }
            string(s, ids.get(i));
        }
        s.append(']');
    }

    private static StringBuilder field(StringBuilder s, String name, String value) {
        s.append('"').append(name).append("\":");
        if (value == null) {
            return s.append("null");
        }
        return string(s, value);
    }

    private static StringBuilder string(StringBuilder s, String value) {
        s.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '"' || c == '\\') {
                s.append('\\').append(c);
            } else if (c < 0x20 || c == 0x2028 || c == 0x2029) {
                String hex = Integer.toHexString(c);
                s.append("\\u").append("0000", hex.length(), 4).append(hex);
            } else {
                s.append(c);
            }
        }
        return s.append('"');
    }
}
