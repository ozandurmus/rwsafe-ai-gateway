package io.rwsafe.control.capture;

import io.rwsafe.control.config.ControlProperties;
import io.rwsafe.platform.capacity.WatermarkBreaker;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * The control plane's disk-free watermark breaker (PO decision Q-3, SR-HOST-2, CAPACITY §2): every 30 s the configured
 * paths (the database volume's filesystem) are read; the highest used fraction drives {@link WatermarkBreaker}. Above
 * 85 % redacted content is not persisted (and above 75 % raw content would not be, once it exists); metadata and
 * verdicts keep flowing in every state; with no reading for 5 minutes persistence of content stops (fail closed).
 */
@Component
public final class CaptureWatermark {

    private static final Logger LOG = LoggerFactory.getLogger(CaptureWatermark.class);

    private final List<Path> paths;
    private final DiskUsageProbe probe;
    private final Clock clock;
    private final WatermarkBreaker breaker = new WatermarkBreaker();
    private volatile String lastLogged;

    @Autowired
    public CaptureWatermark(ControlProperties properties, DiskUsageProbe probe) {
        this(properties.capture().watchedPaths(), probe, Clock.systemUTC());
    }

    CaptureWatermark(List<Path> paths, DiskUsageProbe probe, Clock clock) {
        this.paths = List.copyOf(paths);
        this.probe = probe;
        this.clock = clock;
        check();
    }

    /** Reads every path now; the highest used fraction counts, an unreadable path is no reading. */
    @Scheduled(initialDelayString = "PT30S", fixedDelayString = "PT30S")
    public void check() {
        double highest = Double.NaN;
        for (Path p : paths) {
            double used = probe.usedFraction(p);
            if (Double.isNaN(used)) {
                highest = Double.NaN;
                break;
            }
            highest = Double.isNaN(highest) ? used : Math.max(highest, used);
        }
        Instant now = clock.instant();
        breaker.record(highest, now);
        WatermarkBreaker.State state = breaker.state(now);
        boolean stale = breaker.stale(now);
        String logged = state + (stale ? "/stale" : "");
        if (!logged.equals(lastLogged)) {
            lastLogged = logged;
            // A state and a percentage only: no path, no host. A stale breaker has no current reading (D-06).
            if (stale) {
                LOG.warn("capture watermark: {} (no disk reading for 5 minutes: content is not persisted)", state);
            } else {
                LOG.info("capture watermark: {} ({} used)", state, percent(breaker.lastUsed()));
            }
        }
    }

    public WatermarkBreaker.State state() {
        return breaker.state(clock.instant());
    }

    public boolean stale() {
        return breaker.stale(clock.instant());
    }

    public double lastUsed() {
        return breaker.lastUsed();
    }

    public int pathCount() {
        return paths.size();
    }

    static String percent(double used) {
        return Double.isNaN(used) ? "unknown" : String.format(java.util.Locale.ROOT, "%.1f %%", used * 100);
    }
}
