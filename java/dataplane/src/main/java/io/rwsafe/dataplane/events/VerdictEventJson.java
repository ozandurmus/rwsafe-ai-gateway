package io.rwsafe.dataplane.events;

import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** Serialises verdict events as the JSON array the control plane's ingestion endpoint accepts. */
public final class VerdictEventJson {

    private VerdictEventJson() {
    }

    public static String array(List<VerdictEvent> events) {
        StringBuilder s = new StringBuilder("[");
        for (int i = 0; i < events.size(); i++) {
            if (i > 0) {
                s.append(',');
            }
            object(s, events.get(i));
        }
        return s.append(']').toString();
    }

    private static void object(StringBuilder s, VerdictEvent e) {
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
        s.append('}');
    }

    private static StringBuilder field(StringBuilder s, String name, String value) {
        s.append('"').append(name).append("\":");
        if (value == null) {
            return s.append("null");
        }
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
