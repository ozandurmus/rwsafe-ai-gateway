package io.rwsafe.dataplane.events;

import io.rwsafe.platform.verdict.Verdict;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * One verdict event, metadata only (ADR-009 C1/C2/C6): no body, no URL path, no header other than the proxy's identity
 * claim and client address, which the control plane pseudonymises and masks before persistence. Field set and names
 * follow the ingestion contract {@code POST /internal/v1/verdict-events}.
 *
 * @param findings class name to count, never a value
 */
public record VerdictEvent(UUID eventId, Instant receivedAt, String service, String platform, String surface, String step,
                           Verdict verdict, String reason, Map<String, Integer> findings, long bodyBytes,
                           long decisionMicros, String userClaim, String clientAddress, String transport,
                           long snapshotVersion, String correlationId) {

    public VerdictEvent {
        findings = Map.copyOf(findings);
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
