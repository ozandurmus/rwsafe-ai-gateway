package io.rwsafe.control.ops;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * The runs of the control plane's scheduled jobs (Administration -> Records -> Job log, PO decision Q-47 decision 1.3),
 * kept in memory per instance: the last {@value #KEPT} runs of each job in a bounded ring, and the run and failure
 * totals since this instance started. Nothing is written to the database (no table, no migration); a restart starts the
 * log afresh, and the screen says "since last start". A run records its start, end, ok or failed, a fixed failure code
 * and counts under fixed keys; a value never enters it.
 */
@Component
public class JobRuns {

    /** Runs kept per job. */
    public static final int KEPT = 20;
    private static final Logger LOG = LoggerFactory.getLogger(JobRuns.class);

    /** One finished run. */
    public record Run(Instant startedAt, Instant endedAt, boolean ok, String failure, Map<String, Long> counts) {
    }

    /** One job's log: the newest run first, the totals since the instance started, and the start of a running run. */
    public record Log(List<Run> runs, long total, long failed, Instant runningSince) {

        public Run last() {
            return runs.isEmpty() ? null : runs.get(0);
        }
    }

    private static final class Track {
        private final Deque<Run> runs = new ArrayDeque<>(KEPT);
        private long total;
        private long failed;
        private Instant runningSince;
    }

    private final Clock clock;
    private final Instant since;
    private final Map<String, Track> tracks = new ConcurrentHashMap<>();

    @Autowired
    public JobRuns() {
        this(Clock.systemUTC());
    }

    public JobRuns(Clock clock) {
        this.clock = clock;
        this.since = clock.instant();
    }

    /** When this log began: the instance's start. */
    public Instant since() {
        return since;
    }

    /**
     * Runs {@code body} as one run of {@code job} and records it. An exception is recorded as a failure under its class
     * name and is not rethrown (the scheduler would log its message); the log line names the job and the class only.
     */
    public void run(String job, Supplier<JobResult> body) {
        Instant started = clock.instant();
        Track track = tracks.computeIfAbsent(job, j -> new Track());
        synchronized (track) {
            track.runningSince = started;
        }
        JobResult result;
        try {
            result = body.get();
            if (result == null) {
                result = JobResult.failed("NO_RESULT", Map.of());
            }
        } catch (RuntimeException e) {
            LOG.warn("scheduled job {} failed: {}", job, e.getClass().getSimpleName());
            result = JobResult.failed(e);
        }
        record(track, started, clock.instant(), result);
    }

    private static void record(Track track, Instant started, Instant ended, JobResult result) {
        Run run = new Run(started, ended, result.ok(), result.ok() ? null : failureCode(result.failure()),
            fixedCounts(result.counts()));
        synchronized (track) {
            if (track.runs.size() == KEPT) {
                track.runs.removeLast();
            }
            track.runs.addFirst(run);
            track.total++;
            if (!run.ok()) {
                track.failed++;
            }
            track.runningSince = null;
        }
    }

    /** The job's log; empty when it has not run since the instance started. */
    public Log log(String job) {
        Track track = tracks.get(job);
        if (track == null) {
            return new Log(List.of(), 0, 0, null);
        }
        synchronized (track) {
            return new Log(List.copyOf(new ArrayList<>(track.runs)), track.total, track.failed, track.runningSince);
        }
    }

    /** A class name or an upper-case code: letters, digits and {@code _}, at most 64; anything else is {@code FAILED}. */
    static String failureCode(String s) {
        if (s == null || s.isEmpty() || s.length() > 64) {
            return "FAILED";
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_')) {
                return "FAILED";
            }
        }
        return s;
    }

    /** Only keys of fixed vocabulary ({@code [a-z][A-Za-z0-9.]{0,63}}) with a number survive. */
    static Map<String, Long> fixedCounts(Map<String, Long> counts) {
        Map<String, Long> out = new LinkedHashMap<>();
        counts.forEach((k, v) -> {
            if (v != null && countKey(k) && out.size() < 16) {
                out.put(k, v);
            }
        });
        return java.util.Collections.unmodifiableMap(out);
    }

    static boolean countKey(String k) {
        if (k == null || k.isEmpty() || k.length() > 64 || k.charAt(0) < 'a' || k.charAt(0) > 'z') {
            return false;
        }
        for (int i = 1; i < k.length(); i++) {
            char c = k.charAt(i);
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.')) {
                return false;
            }
        }
        return true;
    }
}
