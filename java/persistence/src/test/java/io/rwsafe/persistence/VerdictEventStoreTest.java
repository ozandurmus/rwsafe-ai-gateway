package io.rwsafe.persistence;

import static io.rwsafe.persistence.Events.event;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.platform.verdict.Verdict;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class VerdictEventStoreTest {

    private Database db;
    private final Instant base = Instant.parse("2026-10-30T09:00:00Z");

    @BeforeEach
    void open() {
        db = Database.migrateAndOpen(TestDatabase.fresh());
    }

    @Test
    void ingestionIsIdempotentOnTheEventId() {
        StoredVerdictEvent e = event(base, "claude", Verdict.REDACT, List.of(new FindingCount("TCKN", 2)));
        assertEquals(1, db.verdictEvents().insert(List.of(e)));
        assertEquals(0, db.verdictEvents().insert(List.of(e)));
        StoredVerdictEvent stored = db.verdictQueries().event(e.eventId()).orElseThrow();
        assertEquals(List.of(new FindingCount("TCKN", 2)), stored.findings());
        assertEquals("USR-0123456789", stored.userPseudonym());
        assertEquals(e.receivedAt(), stored.receivedAt());
    }

    @Test
    void aRawClaimCannotBeStoredAsAPseudonym() {
        StoredVerdictEvent e = event(base, "claude", Verdict.ALLOW, List.of());
        StoredVerdictEvent raw = new StoredVerdictEvent(e.eventId(), e.receivedAt(), e.service(), e.platform(),
            e.surface(), e.step(), e.verdict(), e.reason(), e.findings(), e.bodyBytes(), e.decisionMicros(),
            "synthetic.user", e.clientSubnet(), e.transport(), e.snapshotVersion(), e.correlationId(),
            e.pseudonymKeyId());
        assertThrows(RuntimeException.class, () -> db.verdictEvents().insert(List.of(raw)));
    }

    @Test
    void aRawAddressOrAFreeTextReasonCannotBeStored() {
        StoredVerdictEvent e = event(base, "claude", Verdict.ALLOW, List.of());
        for (String subnet : new String[] {"192.0.2.10", "2001:db8::1", "240.1.2.7/24"}) {
            StoredVerdictEvent raw = new StoredVerdictEvent(UUID.randomUUID(), e.receivedAt(), e.service(), e.platform(),
                e.surface(), e.step(), e.verdict(), e.reason(), e.findings(), e.bodyBytes(), e.decisionMicros(),
                e.userPseudonym(), subnet, e.transport(), e.snapshotVersion(), e.correlationId(), e.pseudonymKeyId());
            assertThrows(RuntimeException.class, () -> db.verdictEvents().insert(List.of(raw)), subnet);
        }
        StoredVerdictEvent dotted = new StoredVerdictEvent(UUID.randomUUID(), e.receivedAt(), e.service(), e.platform(),
            e.surface(), e.step(), Verdict.BLOCK, "host.example.test", e.findings(), e.bodyBytes(), e.decisionMicros(),
            e.userPseudonym(), e.clientSubnet(), e.transport(), e.snapshotVersion(), e.correlationId(), e.pseudonymKeyId());
        assertThrows(RuntimeException.class, () -> db.verdictEvents().insert(List.of(dotted)));
    }

    @Test
    void overviewCountsVerdictsPlatformsHoursAndFindingClasses() {
        db.verdictEvents().insert(List.of(
            event(base, "claude", Verdict.ALLOW, List.of()),
            event(base.plusSeconds(60), "claude", Verdict.REDACT, List.of(new FindingCount("TCKN", 1))),
            event(base.plusSeconds(3700), "openai", Verdict.BLOCK, List.of(new FindingCount("SECRET", 3))),
            event(base.plusSeconds(3800), "openai", Verdict.MALFORMED, List.of()),
            event(base.minusSeconds(7200), "openai", Verdict.ALLOW, List.of())));
        VerdictQueries.Overview o = db.verdictQueries().overview(base, base.plus(Duration.ofDays(1)));
        assertEquals(4, o.total());
        assertEquals(4, o.verdicts().size());
        VerdictQueries.PlatformCount openai = o.platforms().stream().filter(p -> p.platform().equals("openai"))
            .findFirst().orElseThrow();
        assertEquals(2, openai.total());
        assertEquals(1, openai.blocked());
        assertEquals(1, openai.nonVerdicts());
        assertEquals(2, o.hours().size());
        assertEquals(base, o.hours().get(0).hour());
        assertEquals(1L, o.hours().get(1).byVerdict().get(Verdict.BLOCK));
        assertEquals(List.of(new VerdictQueries.FindingClassCount("SECRET", 1, 3),
            new VerdictQueries.FindingClassCount("TCKN", 1, 1)), o.findings());
    }

    @Test
    void trafficPagesThroughEveryEventOnceInTimeOrder() {
        List<StoredVerdictEvent> all = new ArrayList<>();
        for (int i = 0; i < 25; i++) {
            // Pairs share a timestamp, so the event id breaks the tie in the keyset.
            all.add(event(base.plusSeconds(i / 2), i % 3 == 0 ? "gemini" : "copilot", Verdict.ALLOW, List.of()));
        }
        db.verdictEvents().insert(all);
        Set<UUID> seen = new HashSet<>();
        String cursor = null;
        Instant previous = Instant.MAX;
        int pages = 0;
        do {
            VerdictQueries.TrafficPage page = db.verdictQueries().traffic(
                new VerdictQueries.TrafficFilter(null, null, null, null, null, null, 10, cursor));
            for (StoredVerdictEvent e : page.items()) {
                assertTrue(seen.add(e.eventId()));
                assertTrue(!e.receivedAt().isAfter(previous));
                previous = e.receivedAt();
            }
            cursor = page.nextCursor();
            pages++;
        } while (cursor != null);
        assertEquals(25, seen.size());
        assertEquals(3, pages);
    }

    @Test
    void trafficFiltersByPlatformVerdictAndPseudonym() {
        db.verdictEvents().insert(List.of(
            event(base, "gemini", Verdict.BLOCK, List.of(new FindingCount("SECRET", 1))),
            event(base, "gemini", Verdict.ALLOW, List.of()),
            event(base, "claude", Verdict.BLOCK, List.of())));
        VerdictQueries.TrafficPage page = db.verdictQueries().traffic(new VerdictQueries.TrafficFilter(
            base.minus(1, ChronoUnit.HOURS), base.plus(1, ChronoUnit.HOURS), "gemini", Verdict.BLOCK, "reqmod",
            "USR-0123456789", 50, null));
        assertEquals(1, page.items().size());
        assertEquals(List.of(new FindingCount("SECRET", 1)), page.items().get(0).findings());
        assertNull(page.nextCursor());
        assertEquals(0, db.verdictQueries().traffic(new VerdictQueries.TrafficFilter(null, null, null, null, null,
            "USR-ffffffffff", 50, null)).items().size());
    }

    @Test
    void aForgedCursorIsRefused() {
        assertThrows(IllegalArgumentException.class, () -> db.verdictQueries().traffic(
            new VerdictQueries.TrafficFilter(null, null, null, null, null, null, 10, "bm90LWEtY3Vyc29y")));
    }

    @Test
    void ingestStatsReportTheLatestEvent() {
        db.verdictEvents().insert(List.of(event(base, "claude", Verdict.ALLOW, List.of())));
        VerdictQueries.IngestStats stats = db.verdictQueries().ingestStats(Instant.now().minusSeconds(60));
        assertEquals(1, stats.eventsSince());
        assertEquals(1, stats.totalEvents());
        assertNotNull(stats.latestReceivedAt());
        assertTrue(db.reachable());
    }
}
