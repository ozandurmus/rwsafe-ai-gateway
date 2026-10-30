package io.rwsafe.control.api;

import io.rwsafe.control.ingest.IngestionService;
import io.rwsafe.control.privacy.MaskedView;
import io.rwsafe.control.privacy.TextMasker;
import io.rwsafe.persistence.FindingCount;
import io.rwsafe.persistence.StoredVerdictEvent;
import io.rwsafe.persistence.VerdictQueries;
import io.rwsafe.platform.verdict.Verdict;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * The read API's response types. Stored rows are already pseudonymised (C1) and hold no value (C2, C6); the masked
 * projection additionally passes every free-text field through the text masker. Ids stay as they are for navigation.
 */
public final class Views {

    private Views() {
    }

    public record VerdictCountView(Verdict verdict, long count) {
    }

    public record PlatformCountView(String platform, long total, long redacted, long blocked, long nonVerdicts) {
    }

    public record HourView(Instant hour, long total, Map<Verdict, Long> byVerdict) {
    }

    public record FindingClassView(String dataClass, long events, long hits) {
    }

    public record OverviewView(Instant from, Instant to, long total, List<VerdictCountView> verdicts,
                               List<PlatformCountView> platforms, List<HourView> hours,
                               List<FindingClassView> findings) implements MaskedView {

        static OverviewView of(VerdictQueries.Overview o) {
            return new OverviewView(o.from(), o.to(), o.total(),
                o.verdicts().stream().map(v -> new VerdictCountView(v.verdict(), v.count())).toList(),
                o.platforms().stream().map(p -> new PlatformCountView(p.platform(), p.total(), p.redacted(),
                    p.blocked(), p.nonVerdicts())).toList(),
                o.hours().stream().map(h -> new HourView(h.hour(),
                    h.byVerdict().values().stream().mapToLong(Long::longValue).sum(), new TreeMap<>(h.byVerdict())))
                    .toList(),
                o.findings().stream().map(f -> new FindingClassView(f.dataClass(), f.events(), f.hits())).toList());
        }

        @Override
        public MaskedView masked(TextMasker m) {
            return new OverviewView(from, to, total, verdicts, platforms.stream().map(p -> new PlatformCountView(
                m.mask(p.platform()), p.total(), p.redacted(), p.blocked(), p.nonVerdicts())).toList(), hours, findings);
        }
    }

    public record FindingView(String dataClass, int count) {
    }

    /**
     * One event. {@code user} is the {@code USR-} pseudonym and {@code clientSubnet} the masked subnet label; neither
     * the claim nor the address exists anywhere to show, and both are kept as they are in the masked projection (masking a
     * subnet label again would only make the two views disagree).
     */
    public record EventView(String eventId, Instant receivedAt, String service, String platform, String surface,
                            String step, Verdict verdict, String reason, List<FindingView> findings, long bodyBytes,
                            long decisionMicros, String user, String clientSubnet, String transport,
                            long snapshotVersion, String correlationId, String pseudonymKeyId,
                            List<String> appliedRuleIds, List<String> monitorRuleIds) implements MaskedView {

        static EventView of(StoredVerdictEvent e) {
            return new EventView(e.eventId().toString(), e.receivedAt(), e.service(), e.platform(), e.surface(),
                e.step(), e.verdict(), e.reason(), e.findings().stream().map(Views::finding).toList(), e.bodyBytes(),
                e.decisionMicros(), e.userPseudonym(), e.clientSubnet(), e.transport(), e.snapshotVersion(),
                e.correlationId(), e.pseudonymKeyId(), e.appliedRuleIds(), e.monitorRuleIds());
        }

        /** The scoped-rule ids are vocabulary (`class.<CLASS>@<version>`, checked on ingestion): unchanged when masked. */
        @Override
        public EventView masked(TextMasker m) {
            return new EventView(eventId, receivedAt, m.mask(service), m.mask(platform), m.mask(surface), m.mask(step),
                verdict, m.mask(reason), findings, bodyBytes, decisionMicros, user, clientSubnet,
                m.mask(transport), snapshotVersion,
                IngestionService.canonicalUuid(correlationId) ? correlationId : TextMasker.WITHHELD, pseudonymKeyId,
                appliedRuleIds, monitorRuleIds);
        }
    }

    public record TrafficView(List<EventView> items, String nextCursor) implements MaskedView {

        @Override
        public MaskedView masked(TextMasker m) {
            return new TrafficView(items.stream().map(e -> e.masked(m)).toList(), nextCursor);
        }
    }

    public record PlatformsView(List<String> platforms) implements MaskedView {

        @Override
        public MaskedView masked(TextMasker m) {
            return new PlatformsView(platforms.stream().map(m::mask).toList());
        }
    }

    /**
     * The health stub: the control plane's own state now; the data-plane components (queues, 204 ratio, disk watermark,
     * drift) arrive with the snapshot feed and the metrics slice and are reported as {@code UNKNOWN} until then.
     */
    public record HealthView(Instant checkedAt, List<ComponentView> components, long eventsLastFiveMinutes,
                             long totalEvents, Instant latestEventAt) implements MaskedView {

        @Override
        public MaskedView masked(TextMasker m) {
            return new HealthView(checkedAt, components.stream().map(c -> new ComponentView(c.component(), c.state(),
                m.mask(c.detail()))).toList(), eventsLastFiveMinutes, totalEvents, latestEventAt);
        }
    }

    /** @param state {@code UP}, {@code DOWN}, {@code DEGRADED} or {@code UNKNOWN} */
    public record ComponentView(String component, String state, String detail) {
    }

    private static FindingView finding(FindingCount f) {
        return new FindingView(f.dataClass(), f.count());
    }
}
