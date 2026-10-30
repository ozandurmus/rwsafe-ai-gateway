package io.rwsafe.persistence;

import io.rwsafe.platform.verdict.Verdict;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * One verdict event as stored: the ingestion contract's fields after pseudonymisation ({@code userPseudonym},
 * {@code USR-<10 hex>}) and subnet masking ({@code clientSubnet}). There is no field for a body, a raw claim or a raw
 * address, so none can be stored.
 */
public record StoredVerdictEvent(UUID eventId, Instant receivedAt, String service, String platform, String surface,
                                 String step, Verdict verdict, String reason, List<FindingCount> findings, long bodyBytes,
                                 long decisionMicros, String userPseudonym, String clientSubnet, String transport,
                                 long snapshotVersion, String correlationId, String pseudonymKeyId) {

    public StoredVerdictEvent {
        findings = List.copyOf(findings);
    }
}
