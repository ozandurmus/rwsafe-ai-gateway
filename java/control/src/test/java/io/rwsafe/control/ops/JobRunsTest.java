package io.rwsafe.control.ops;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.control.support.Synthetic;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

/** The in-memory job-run recorder (PO decision Q-47 decision 1.3): bounded, counts only, failures by class name. */
class JobRunsTest {

    /** A clock the test moves. */
    private static final class Moving extends Clock {
        private final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-11-02T09:00:00Z"));

        void advance(Duration d) {
            now.updateAndGet(i -> i.plus(d));
        }

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now.get();
        }
    }

    @Test
    void aRunIsRecordedWithItsTimesOutcomeAndCounts() {
        Moving clock = new Moving();
        JobRuns runs = new JobRuns(clock);
        runs.run("synthetic.job", () -> {
            clock.advance(Duration.ofSeconds(3));
            return JobResult.ok(Map.of("rows", 7L));
        });
        JobRuns.Log log = runs.log("synthetic.job");
        assertEquals(1, log.total());
        assertEquals(0, log.failed());
        assertNull(log.runningSince());
        JobRuns.Run last = log.last();
        assertTrue(last.ok());
        assertEquals(Duration.ofSeconds(3), Duration.between(last.startedAt(), last.endedAt()));
        assertEquals(Map.of("rows", 7L), last.counts());
        assertEquals(0, runs.log("never.ran").total());
        assertNull(runs.log("never.ran").last());
    }

    @Test
    void theRingKeepsTheLastRunsNewestFirstAndTheTotalsSinceStart() {
        JobRuns runs = new JobRuns(new Moving());
        for (long i = 0; i < JobRuns.KEPT + 5; i++) {
            long n = i;
            runs.run("synthetic.job", () -> JobResult.ok(Map.of("index", n)));
        }
        JobRuns.Log log = runs.log("synthetic.job");
        assertEquals(JobRuns.KEPT, log.runs().size());
        assertEquals(JobRuns.KEPT + 5, log.total());
        assertEquals((long) JobRuns.KEPT + 4, log.last().counts().get("index"));
        assertEquals(5L, log.runs().get(JobRuns.KEPT - 1).counts().get("index"));
    }

    @Test
    void aFailureKeepsTheExceptionClassNeverItsMessage() {
        JobRuns runs = new JobRuns(new Moving());
        String secretish = "synthetic person " + Synthetic.tckn(7);
        runs.run("synthetic.job", () -> {
            throw new IllegalStateException(secretish);
        });
        runs.run("synthetic.job", () -> JobResult.failed("SNAPSHOT_SIGNING_UNAVAILABLE", Map.of()));
        runs.run("synthetic.job", () -> JobResult.failed("a value: " + secretish, Map.of()));
        runs.run("synthetic.job", () -> null);
        JobRuns.Log log = runs.log("synthetic.job");
        assertEquals(4, log.failed());
        assertEquals("NO_RESULT", log.runs().get(0).failure());
        assertEquals("FAILED", log.runs().get(1).failure(), "free text is not a failure code");
        assertEquals("SNAPSHOT_SIGNING_UNAVAILABLE", log.runs().get(2).failure());
        assertEquals("IllegalStateException", log.runs().get(3).failure());
        assertFalse(log.toString().contains(Synthetic.tckn(7)));
    }

    /** PR 51 review D-03: an Error ends the run as a failure under its class, is rethrown, and leaves no "running". */
    @Test
    void anErrorIsRecordedRethrownAndTheJobIsNoLongerRunning() {
        JobRuns runs = new JobRuns(new Moving());
        org.junit.jupiter.api.Assertions.assertThrows(AssertionError.class, () -> runs.run("synthetic.job", () -> {
            throw new AssertionError("synthetic " + Synthetic.tckn(9));
        }));
        JobRuns.Log log = runs.log("synthetic.job");
        assertNull(log.runningSince(), "not left running");
        assertEquals(1, log.total());
        assertEquals(1, log.failed());
        assertEquals("AssertionError", log.last().failure());
        assertFalse(log.toString().contains(Synthetic.tckn(9)));
        runs.run("synthetic.job", () -> JobResult.ok(Map.of()));
        assertTrue(runs.log("synthetic.job").last().ok(), "the next run is recorded as usual");
    }

    @Test
    void onlyCountsUnderFixedKeysSurvive() {
        JobRuns runs = new JobRuns(new Moving());
        Map<String, Long> counts = new LinkedHashMap<>();
        counts.put("rows", 1L);
        counts.put("syslog.delivered", 2L);
        counts.put("Upper", 3L);
        counts.put("synthetic" + "@" + "example.test", 4L);
        counts.put("has space", 5L);
        counts.put("nullValue", null);
        runs.run("synthetic.job", () -> JobResult.ok(counts));
        assertEquals(Map.of("rows", 1L, "syslog.delivered", 2L), runs.log("synthetic.job").last().counts());
    }

    @Test
    void theNextRunFollowsTheSchedule() {
        Moving clock = new Moving();
        JobRuns runs = new JobRuns(clock);
        Instant start = runs.since();
        JobCatalog.Job watermark = JobCatalog.JOBS.stream().filter(j -> j.id().equals(JobCatalog.CAPTURE_WATERMARK))
            .findFirst().orElseThrow();
        assertEquals(start.plusSeconds(30), JobCatalog.nextRun(watermark, start, runs.log(watermark.id()),
            clock.instant()), "before the first run: the initial delay after the start");
        clock.advance(Duration.ofSeconds(40));
        runs.run(watermark.id(), () -> JobResult.ok(Map.of()));
        assertEquals(clock.instant().plusSeconds(30), JobCatalog.nextRun(watermark, start, runs.log(watermark.id()),
            clock.instant()));

        JobCatalog.Job retention = JobCatalog.JOBS.stream().filter(j -> j.id().equals(JobCatalog.CAPTURE_RETENTION))
            .findFirst().orElseThrow();
        // 09:00 UTC is 12:00 in Istanbul (UTC+3): the next protected-window run is 12:20 Istanbul, 09:20 UTC.
        assertEquals(Instant.parse("2026-11-02T09:20:00Z"), JobCatalog.nextRun(retention, start,
            runs.log(retention.id()), Instant.parse("2026-11-02T09:00:00Z")));
        assertEquals(Instant.parse("2026-11-02T15:20:00Z"), JobCatalog.nextRun(retention, start,
            runs.log(retention.id()), Instant.parse("2026-11-02T09:20:00Z")));

        JobCatalog.Job siem = JobCatalog.JOBS.stream().filter(j -> j.kind() == JobCatalog.Kind.CONTINUOUS)
            .findFirst().orElseThrow();
        assertNull(JobCatalog.nextRun(siem, start, runs.log(siem.id()), clock.instant()));
    }
}
