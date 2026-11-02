package io.rwsafe.control.ops;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.List;
import org.springframework.scheduling.support.CronExpression;

/**
 * The control plane's scheduled and continuous jobs, in one list: {@link ScheduledJobs} takes its {@code @Scheduled}
 * values from these constants, and {@code JobCatalogTest} proves that no other scheduled method exists and that the
 * annotations match this list, so the Job log cannot describe a schedule the server does not run.
 */
public final class JobCatalog {

    /** The scheduled re-sign of the active policy snapshot (POLICY_SNAPSHOT_CONTRACT: at least every 6 hours). */
    public static final String SNAPSHOT_RESIGN = "policy.snapshot_resign";
    public static final String SNAPSHOT_RESIGN_INITIAL = "PT1M";
    public static final String SNAPSHOT_RESIGN_DELAY = "PT5M";

    /** Capture retention, crypto-shredding, rotation, the byte cap and the file sweep (ADR-009 §3-§4). */
    public static final String CAPTURE_RETENTION = "capture.retention";
    /** The protected windows (AGENTS.md section 14): 00, 06, 12, 18 Europe/Istanbul, at 20 past. */
    public static final String CAPTURE_RETENTION_CRON = "0 20 0,6,12,18 * * *";
    public static final String ZONE = "Europe/Istanbul";

    /** The re-read of the capture-key Secret (rotation and shredding without a restart). */
    public static final String CAPTURE_KEY_RELOAD = "capture.key_reload";
    public static final String CAPTURE_KEY_RELOAD_INITIAL = "PT5M";
    public static final String CAPTURE_KEY_RELOAD_DELAY = "PT5M";

    /** The disk-free watermark breaker's reading (CAPACITY §2). */
    public static final String CAPTURE_WATERMARK = "capture.watermark";
    public static final String CAPTURE_WATERMARK_INITIAL = "PT30S";
    public static final String CAPTURE_WATERMARK_DELAY = "PT30S";

    /** The SIEM export: one reader and one sender per destination, polling continuously (ADR-009 C8). */
    public static final String SIEM_EXPORT = "siem.export";

    public enum Kind { FIXED_DELAY, CRON, CONTINUOUS }

    /**
     * One job.
     *
     * @param initialDelay after the instance starts (fixed-delay jobs)
     * @param delay        between the end of one run and the start of the next (fixed-delay jobs)
     * @param cron         the Spring cron expression (cron jobs), evaluated in {@code zone}
     */
    public record Job(String id, Kind kind, Duration initialDelay, Duration delay, String cron, String zone) {

        static Job fixedDelay(String id, String initial, String delay) {
            return new Job(id, Kind.FIXED_DELAY, Duration.parse(initial), Duration.parse(delay), null, null);
        }

        static Job cron(String id, String cron, String zone) {
            return new Job(id, Kind.CRON, null, null, cron, zone);
        }

        static Job continuous(String id) {
            return new Job(id, Kind.CONTINUOUS, null, null, null, null);
        }
    }

    public static final List<Job> JOBS = List.of(
        Job.fixedDelay(SNAPSHOT_RESIGN, SNAPSHOT_RESIGN_INITIAL, SNAPSHOT_RESIGN_DELAY),
        Job.cron(CAPTURE_RETENTION, CAPTURE_RETENTION_CRON, ZONE),
        Job.fixedDelay(CAPTURE_KEY_RELOAD, CAPTURE_KEY_RELOAD_INITIAL, CAPTURE_KEY_RELOAD_DELAY),
        Job.fixedDelay(CAPTURE_WATERMARK, CAPTURE_WATERMARK_INITIAL, CAPTURE_WATERMARK_DELAY),
        Job.continuous(SIEM_EXPORT));

    private JobCatalog() {
    }

    /**
     * When the job runs next: a fixed-delay job one delay after its last run ended (or its initial delay after the
     * instance started; a run in progress: unknown, null); a cron job at the expression's next time after {@code now};
     * a continuous job never "next" (null).
     */
    public static Instant nextRun(Job job, Instant instanceStart, JobRuns.Log log, Instant now) {
        return switch (job.kind()) {
            case FIXED_DELAY -> log.runningSince() != null ? null
                : log.last() == null ? instanceStart.plus(job.initialDelay()) : log.last().endedAt().plus(job.delay());
            case CRON -> {
                ZonedDateTime next = CronExpression.parse(job.cron()).next(now.atZone(ZoneId.of(job.zone())));
                yield next == null ? null : next.toInstant();
            }
            case CONTINUOUS -> null;
        };
    }
}
