package io.rwsafe.control.ops;

import io.rwsafe.control.capture.CaptureKeyring;
import io.rwsafe.control.capture.CaptureRetentionJob;
import io.rwsafe.control.capture.CaptureWatermark;
import io.rwsafe.control.policy.PolicyRegistryService;
import io.rwsafe.platform.capacity.WatermarkBreaker;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Every scheduled method of the control plane, in one class (PO decision Q-47 decision 1.3): each one runs its job
 * through {@link JobRuns}, so the Job log sees every run, its outcome and its counts. The schedules are the constants of
 * {@link JobCatalog}; the jobs' own classes hold the work and no {@code @Scheduled} of their own.
 */
@Component
public class ScheduledJobs {

    private final JobRuns runs;
    private final PolicyRegistryService registry;
    private final CaptureRetentionJob retention;
    private final CaptureKeyring keys;
    private final CaptureWatermark watermark;

    public ScheduledJobs(JobRuns runs, PolicyRegistryService registry, CaptureRetentionJob retention,
                         CaptureKeyring keys, CaptureWatermark watermark) {
        this.runs = runs;
        this.registry = registry;
        this.retention = retention;
        this.keys = keys;
        this.watermark = watermark;
    }

    /** POLICY_SNAPSHOT_CONTRACT: checked every 5 minutes, re-issued one interval early (PolicyRegistryService). */
    @Scheduled(initialDelayString = JobCatalog.SNAPSHOT_RESIGN_INITIAL,
        fixedDelayString = JobCatalog.SNAPSHOT_RESIGN_DELAY)
    public void snapshotResign() {
        runs.run(JobCatalog.SNAPSHOT_RESIGN, registry::reissueWhenDue);
    }

    @Scheduled(cron = JobCatalog.CAPTURE_RETENTION_CRON, zone = JobCatalog.ZONE)
    public void captureRetention() {
        runs.run(JobCatalog.CAPTURE_RETENTION, retention::scheduled);
    }

    @Scheduled(initialDelayString = JobCatalog.CAPTURE_KEY_RELOAD_INITIAL,
        fixedDelayString = JobCatalog.CAPTURE_KEY_RELOAD_DELAY)
    public void captureKeyReload() {
        runs.run(JobCatalog.CAPTURE_KEY_RELOAD, () -> {
            keys.reload();
            Map<String, Long> counts = new LinkedHashMap<>();
            counts.put("keys", (long) keys.ids().size());
            counts.put("shredded", (long) keys.shredded().size());
            counts.put("available", keys.available() ? 1L : 0L);
            return JobResult.ok(counts);
        });
    }

    @Scheduled(initialDelayString = JobCatalog.CAPTURE_WATERMARK_INITIAL,
        fixedDelayString = JobCatalog.CAPTURE_WATERMARK_DELAY)
    public void captureWatermark() {
        runs.run(JobCatalog.CAPTURE_WATERMARK, () -> {
            watermark.check();
            WatermarkBreaker.State state = watermark.state();
            Map<String, Long> counts = new LinkedHashMap<>();
            counts.put("paths", (long) watermark.pathCount());
            counts.put("stale", watermark.stale() ? 1L : 0L);
            counts.put("rawOff", state.allowsRaw() ? 0L : 1L);
            counts.put("redactedOff", state.allowsRedacted() ? 0L : 1L);
            return JobResult.ok(counts);
        });
    }
}
