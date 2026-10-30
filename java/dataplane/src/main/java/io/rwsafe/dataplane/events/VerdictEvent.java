package io.rwsafe.dataplane.events;

import io.rwsafe.platform.verdict.Verdict;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * One verdict event, metadata only (ADR-009 C1/C2/C6): no body, no URL path, no header other than the proxy's identity
 * claim and client address, which the control plane pseudonymises and masks before persistence. Field set and names
 * follow the ingestion contract {@code POST /internal/v1/verdict-events}.
 *
 * @param findings       class name to count, never a value
 * @param appliedRuleIds ids of the scoped rules that set the action of a found class (snapshot format 2); never a group
 *                       name; at most {@link #MAX_RULE_IDS}, each at most {@link #MAX_RULE_ID} characters
 * @param monitorRuleIds ids of matching monitor rules that would have changed it; same bounds
 */
public record VerdictEvent(UUID eventId, Instant receivedAt, String service, String platform, String surface, String step,
                           Verdict verdict, String reason, Map<String, Integer> findings, long bodyBytes,
                           long decisionMicros, String userClaim, String clientAddress, String transport,
                           long snapshotVersion, String correlationId, List<String> appliedRuleIds,
                           List<String> monitorRuleIds) {

    public static final int MAX_RULE_IDS = 16;
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

    /** Never prints the identity claim or the client address (AGENTS.md 4.14, D-12). */
    @Override
    public String toString() {
        return "VerdictEvent[" + eventId + ", " + service + ", " + platform + ", " + verdict + ", " + reason + "]";
    }
}
