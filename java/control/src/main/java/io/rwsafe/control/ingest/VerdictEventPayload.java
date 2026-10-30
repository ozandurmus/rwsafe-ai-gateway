package io.rwsafe.control.ingest;

import java.util.List;

/**
 * One element of {@code POST /internal/v1/verdict-events}, exactly the data plane's contract fields
 * ({@code io.rwsafe.dataplane.events.VerdictEventJson}); an unknown field refuses the batch. Every field is boxed so a
 * missing one is seen as missing, not as zero. {@code userClaim} and {@code clientAddress} live only in this request
 * object: the ingestion service pseudonymises and masks them and nothing else reads them.
 */
public record VerdictEventPayload(String eventId, String receivedAt, String service, String platform, String surface,
                                  String step, String verdict, String reason, List<FindingPayload> findings,
                                  Long bodyBytes, Long decisionMicros, String userClaim, String clientAddress,
                                  String transport, Long snapshotVersion, String correlationId) {

    /** The JSON key is {@code class}. */
    public record FindingPayload(@com.fasterxml.jackson.annotation.JsonProperty("class") String dataClass,
                                 Integer count) {
    }

    /** Never prints the identity claim or the client address (AGENTS.md 4.14). */
    @Override
    public String toString() {
        return "VerdictEventPayload[" + eventId + ", " + service + ", " + platform + ", " + verdict + "]";
    }
}
