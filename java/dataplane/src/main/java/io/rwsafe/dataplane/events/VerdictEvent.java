package io.rwsafe.dataplane.events;

import io.rwsafe.platform.verdict.Verdict;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * One verdict event: metadata (ADR-009 C1/C2/C6) and, only when capture is on, the redacted C3 text; no raw body, no
 * URL path, no header other than the proxy's identity claim and client address, which the control plane pseudonymises and masks before persistence. Field set and names
 * follow the ingestion contract {@code POST /internal/v1/verdict-events}.
 *
 * @param findings       class name to count, never a value
 * @param appliedRuleIds ids of the scoped rules that set the action of a found class (snapshot format 2); never a group
 *                       name; at most {@link #MAX_RULE_IDS}, each at most {@link #MAX_RULE_ID} characters
 * @param monitorRuleIds ids of matching monitor rules that would have changed it; same bounds
 * @param capture        the redacted (C3) content when capture is on and the engine rewrote the body; null otherwise.
 *                       Its own {@code toString()} prints no content, and this record's does not print it at all
 */
public record VerdictEvent(UUID eventId, Instant receivedAt, String service, String platform, String surface, String step,
                           Verdict verdict, String reason, Map<String, Integer> findings, long bodyBytes,
                           long decisionMicros, String userClaim, String clientAddress, String transport,
                           long snapshotVersion, String correlationId, List<String> appliedRuleIds,
                           List<String> monitorRuleIds, CapturedText capture) {

    public static final int MAX_RULE_IDS = 16;

    /** An event without captured content. */
    public VerdictEvent(UUID eventId, Instant receivedAt, String service, String platform, String surface, String step,
                        Verdict verdict, String reason, Map<String, Integer> findings, long bodyBytes,
                        long decisionMicros, String userClaim, String clientAddress, String transport,
                        long snapshotVersion, String correlationId, List<String> appliedRuleIds,
                        List<String> monitorRuleIds) {
        this(eventId, receivedAt, service, platform, surface, step, verdict, reason, findings, bodyBytes, decisionMicros,
            userClaim, clientAddress, transport, snapshotVersion, correlationId, appliedRuleIds, monitorRuleIds, null);
    }

    /** The same event without its captured content (the spool watermark strips it, SR-HOST-2). */
    public VerdictEvent withoutCapture() {
        return capture == null ? this : new VerdictEvent(eventId, receivedAt, service, platform, surface, step, verdict,
            reason, findings, bodyBytes, decisionMicros, userClaim, clientAddress, transport, snapshotVersion,
            correlationId, appliedRuleIds, monitorRuleIds, null);
    }
    public static final int MAX_RULE_ID = 128;

    public VerdictEvent {
        findings = Map.copyOf(findings);
        appliedRuleIds = boundedIds(appliedRuleIds);
        monitorRuleIds = boundedIds(monitorRuleIds);
    }

    private static List<String> boundedIds(List<String> ids) {
        List<String> out = new ArrayList<>(Math.min(ids.size(), MAX_RULE_IDS));
        for (int i = 0; i < ids.size() && out.size() < MAX_RULE_IDS; i++) {
            out.add(bounded(ids.get(i), MAX_RULE_ID));
        }
        return List.copyOf(out);
    }

    /** Proxy claims are attacker-influenced: cut to a bound before they travel (PR 11 review D-12). */
    public static String bounded(String value, int max) {
        if (value == null) {
            return null;
        }
        return value.length() <= max ? value : value.substring(0, max);
    }

    /** Never prints the identity claim, the client address or the captured content (AGENTS.md 4.14, D-12). */
    @Override
    public String toString() {
        return "VerdictEvent[" + eventId + ", " + service + ", " + platform + ", " + verdict + ", " + reason
            + (capture == null ? "" : ", captured") + "]";
    }
}
