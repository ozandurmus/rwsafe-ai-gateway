package io.rwsafe.control.api;

import io.rwsafe.control.api.ApiExceptionHandler.BadRequest;
import io.rwsafe.control.api.ApiExceptionHandler.NotFound;
import io.rwsafe.control.api.Views.ComponentView;
import io.rwsafe.control.api.Views.EventView;
import io.rwsafe.control.api.Views.HealthView;
import io.rwsafe.control.api.Views.OverviewView;
import io.rwsafe.control.api.Views.PlatformsView;
import io.rwsafe.control.api.Views.TrafficView;
import io.rwsafe.control.config.ControlProperties;
import io.rwsafe.control.policy.PolicyRegistryService;
import io.rwsafe.control.policy.SnapshotSigner;
import io.rwsafe.control.privacy.PrivacyKeys;
import io.rwsafe.control.siem.SiemExportService;
import io.rwsafe.persistence.Database;
import io.rwsafe.persistence.PolicySnapshotStore.IssuedSnapshot;
import io.rwsafe.persistence.VerdictQueries;
import io.rwsafe.platform.verdict.Verdict;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * The read API of the Overview, Traffic, Event and Health screens (ARCHITECTURE.md §3.4). The user filter takes a
 * {@code USR-} pseudonym only: there is no lookup by a real name, address or value (ADR-009 §6, masked search).
 */
@RestController
@RequestMapping("/api/v1")
public class ReadApiController {

    static final Duration DEFAULT_WINDOW = Duration.ofHours(24);
    static final Duration MAX_WINDOW = Duration.ofDays(31);

    private final Database database;
    private final PrivacyKeys keys;
    private final SnapshotSigner signer;
    private final PolicyRegistryService registry;
    private final SiemExportService siem;
    private final Clock clock;

    public ReadApiController(Database database, PrivacyKeys keys, SnapshotSigner signer, PolicyRegistryService registry,
                             SiemExportService siem) {
        this.database = database;
        this.keys = keys;
        this.signer = signer;
        this.registry = registry;
        this.siem = siem;
        this.clock = Clock.systemUTC();
    }

    @GetMapping("/overview")
    public OverviewView overview(@RequestParam(name = "from", required = false) Instant from,
                                 @RequestParam(name = "to", required = false) Instant to) {
        Instant[] w = window(from, to);
        return OverviewView.of(database.verdictQueries().overview(w[0], w[1]));
    }

    @GetMapping("/traffic")
    public TrafficView traffic(@RequestParam(name = "from", required = false) Instant from,
                               @RequestParam(name = "to", required = false) Instant to,
                               @RequestParam(name = "platform", required = false) String platform,
                               @RequestParam(name = "verdict", required = false) Verdict verdict,
                               @RequestParam(name = "service", required = false) String service,
                               @RequestParam(name = "user", required = false) String user,
                               @RequestParam(name = "limit", defaultValue = "50") int limit,
                               @RequestParam(name = "cursor", required = false) String cursor) {
        Instant[] w = window(from, to);
        // SR-PRIV-4: every filter takes a vocabulary value or a pseudonym, never a raw value to test guesses with.
        if (platform != null && !registry.platformIds().contains(platform)) {
            throw new BadRequest("INVALID_PLATFORM_FILTER", "The platform filter takes a platform id of the registry.");
        }
        if (service != null && !service.equals("reqmod") && !service.equals("respmod")) {
            throw new BadRequest("INVALID_SERVICE_FILTER", "The service filter takes reqmod or respmod.");
        }
        if (user != null && !pseudonym(user)) {
            throw new BadRequest("INVALID_USER_FILTER",
                "The user filter takes a USR- pseudonym only; real names are never searchable here.");
        }
        if (limit < 1 || limit > VerdictQueries.MAX_PAGE) {
            throw new BadRequest("INVALID_LIMIT", "The limit is between 1 and " + VerdictQueries.MAX_PAGE + ".");
        }
        VerdictQueries.TrafficPage page;
        try {
            page = database.verdictQueries().traffic(new VerdictQueries.TrafficFilter(w[0], w[1], platform, verdict,
                service, user, limit, cursor));
        } catch (IllegalArgumentException e) {
            throw new BadRequest("INVALID_CURSOR", "The page cursor is not one this server issued.");
        }
        return new TrafficView(page.items().stream().map(EventView::of).toList(), page.nextCursor());
    }

    @GetMapping("/traffic/{eventId}")
    public EventView event(@PathVariable("eventId") UUID eventId) {
        return database.verdictQueries().event(eventId).map(EventView::of)
            .orElseThrow(() -> new NotFound("EVENT_NOT_FOUND", "No event with this id."));
    }

    @GetMapping("/platforms")
    public PlatformsView platforms(@RequestParam(name = "from", required = false) Instant from,
                                   @RequestParam(name = "to", required = false) Instant to) {
        Instant[] w = window(from, to);
        return new PlatformsView(database.verdictQueries().platforms(w[0], w[1]));
    }

    @GetMapping("/health")
    public HealthView health() {
        Instant now = clock.instant();
        boolean db = database.reachable();
        VerdictQueries.IngestStats stats = db ? database.verdictQueries().ingestStats(now.minus(Duration.ofMinutes(5)))
            : new VerdictQueries.IngestStats(0, null, 0);
        List<ComponentView> components = List.of(
            new ComponentView("database", db ? "UP" : "DOWN", db ? "PostgreSQL answers" : "PostgreSQL does not answer"),
            new ComponentView("privacy-key", keys.keyAvailable() ? "UP" : "DOWN",
                keys.keyAvailable() ? "pseudonymisation key loaded" : "key missing: ingestion is refused"),
            new ComponentView("masking", keys.maskingAvailable() ? "UP" : "DOWN",
                keys.maskingAvailable() ? "masked role can be served" : "masked role gets 503"),
            new ComponentView("ingestion", stats.eventsSince() > 0 ? "UP" : "UNKNOWN",
                stats.eventsSince() + " events in the last 5 minutes"),
            snapshotFeed(db, now),
            siem(),
            new ComponentView("dataplane", "UNKNOWN", "data-plane metrics are not implemented yet"));
        return new HealthView(now, components, stats.eventsSince(), stats.totalEvents(), stats.latestReceivedAt());
    }

    /** SIEM export: off, or per destination delivered counts, queue depth and the latest failure class. */
    private ComponentView siem() {
        SiemExportService.Health h = siem.health();
        return new ComponentView("siem", h.state(), h.detail());
    }

    /** The signed snapshot feed: the signing key, and the latest issued version and its age (the contract's 6 h re-sign). */
    private ComponentView snapshotFeed(boolean db, Instant now) {
        if (!signer.available()) {
            return new ComponentView("snapshot-feed", "DOWN", signer.unavailableReason() + "; the feed answers 503");
        }
        Optional<IssuedSnapshot> latest = db ? database.policySnapshots().latest() : Optional.empty();
        if (latest.isEmpty()) {
            return new ComponentView("snapshot-feed", "UNKNOWN", "no snapshot issued yet");
        }
        Duration age = Duration.between(latest.get().issuedAt(), now);
        boolean fresh = age.compareTo(ControlProperties.Policy.MAX_SNAPSHOT_AGE.plusMinutes(10)) <= 0;
        return new ComponentView("snapshot-feed", fresh ? "UP" : "DEGRADED", "version " + latest.get().version()
            + " issued " + age.toMinutes() + " minutes ago, key id " + signer.keyId());
    }

    private Instant[] window(Instant from, Instant to) {
        Instant end = to == null ? clock.instant() : to;
        Instant start = from == null ? end.minus(DEFAULT_WINDOW) : from;
        if (!start.isBefore(end)) {
            throw new BadRequest("INVALID_WINDOW", "'from' must be before 'to'.");
        }
        if (Duration.between(start, end).compareTo(MAX_WINDOW) > 0) {
            throw new BadRequest("WINDOW_TOO_LONG", "The window is at most 31 days.");
        }
        return new Instant[] {start, end};
    }

    static boolean pseudonym(String s) {
        if (s.length() != 14 || !s.startsWith("USR-")) {
            return false;
        }
        for (int i = 4; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                return false;
            }
        }
        return true;
    }
}
