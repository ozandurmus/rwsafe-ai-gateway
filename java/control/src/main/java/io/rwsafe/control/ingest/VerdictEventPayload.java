package io.rwsafe.control.ingest;

import java.util.List;

/**
 * One element of {@code POST /internal/v1/verdict-events}, exactly the data plane's contract fields
 * ({@code io.rwsafe.dataplane.events.VerdictEventJson}); an unknown field refuses the batch. Every field is boxed so a
 * missing one is seen as missing, not as zero. {@code userClaim} and {@code clientAddress} live only in this request
 * object: the ingestion service pseudonymises and masks them and nothing else reads them. {@code appliedRuleIds} and
 * {@code monitorRuleIds} are optional (snapshot format 2 scoped-rule ids, at most 16 of at most 128 characters each).
 * {@code capture} is optional: the redacted text of a REDACT verdict (Q-4 b), which only the capture sink reads.
 */
public record VerdictEventPayload(String eventId, String receivedAt, String service, String platform, String surface,
                                  String step, String verdict, String reason, List<FindingPayload> findings,
                                  Long bodyBytes, Long decisionMicros, String userClaim, String clientAddress,
                                  String transport, Long snapshotVersion, String correlationId,
                                  List<String> appliedRuleIds, List<String> monitorRuleIds,
                                  io.rwsafe.control.capture.CapturedContent capture) {

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
