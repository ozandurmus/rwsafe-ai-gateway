package io.rwsafe.persistence;

import io.rwsafe.platform.verdict.Verdict;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * One verdict event as stored: the ingestion contract's fields after pseudonymisation ({@code userPseudonym},
 * {@code USR-<10 hex>}) and subnet masking ({@code clientSubnet}). There is no field for a body, a raw claim or a raw
 * address, so none can be stored.
 * {@code appliedRuleIds} and {@code monitorRuleIds} are the snapshot's scoped-rule ids ({@code <rule id>@<version>},
 * POLICY_SNAPSHOT_CONTRACT format 2) that decided, or as monitor rules would have changed, the verdict; never a group
 * name.
 */
public record StoredVerdictEvent(UUID eventId, Instant receivedAt, String service, String platform, String surface,
                                 String step, Verdict verdict, String reason, List<FindingCount> findings, long bodyBytes,
                                 long decisionMicros, String userPseudonym, String clientSubnet, String transport,
                                 long snapshotVersion, String correlationId, String pseudonymKeyId,
                                 List<String> appliedRuleIds, List<String> monitorRuleIds) {

    public StoredVerdictEvent {
        findings = List.copyOf(findings);
        appliedRuleIds = appliedRuleIds == null ? List.of() : List.copyOf(appliedRuleIds);
        monitorRuleIds = monitorRuleIds == null ? List.of() : List.copyOf(monitorRuleIds);
    }

    /** An event that names no scoped rule (snapshot format 1, or no scoped rule matched). */
    public StoredVerdictEvent(UUID eventId, Instant receivedAt, String service, String platform, String surface,
                              String step, Verdict verdict, String reason, List<FindingCount> findings, long bodyBytes,
                              long decisionMicros, String userPseudonym, String clientSubnet, String transport,
                              long snapshotVersion, String correlationId, String pseudonymKeyId) {
        this(eventId, receivedAt, service, platform, surface, step, verdict, reason, findings, bodyBytes, decisionMicros,
            userPseudonym, clientSubnet, transport, snapshotVersion, correlationId, pseudonymKeyId, List.of(), List.of());
    }
}
