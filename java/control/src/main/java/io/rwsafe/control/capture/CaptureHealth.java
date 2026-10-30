package io.rwsafe.control.capture;

import io.rwsafe.control.api.Views.ComponentView;
import io.rwsafe.persistence.CaptureStore;
import io.rwsafe.persistence.Database;
import io.rwsafe.platform.capacity.WatermarkBreaker;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * The Health screen's capture components (SR-HOST-2: the breaker's state and what it skipped): the capture store (mode,
 * key, stored records and the counts of every reason content was not stored) and the watermark. Counts only.
 */
@Component
public class CaptureHealth {

    private final CaptureSink sink;
    private final CaptureWatermark watermark;
    private final CaptureKeyring keys;
    private final Database database;

    public CaptureHealth(CaptureSink sink, CaptureWatermark watermark, CaptureKeyring keys, Database database) {
        this.sink = sink;
        this.watermark = watermark;
        this.keys = keys;
        this.database = database;
    }

    public List<ComponentView> components(boolean databaseUp) {
        return List.of(store(databaseUp), watermark());
    }

    private ComponentView store(boolean databaseUp) {
        Map<CaptureSink.Outcome, Long> c = sink.counts();
        String skipped = "since start: stored " + c.get(CaptureSink.Outcome.STORED)
            + ", without acknowledgement " + c.get(CaptureSink.Outcome.NO_ACKNOWLEDGEMENT)
            + ", above the watermark " + c.get(CaptureSink.Outcome.WATERMARK)
            + ", detector hit refused " + c.get(CaptureSink.Outcome.DETECTOR_HIT)
            + ", other " + (c.get(CaptureSink.Outcome.NO_USER) + c.get(CaptureSink.Outcome.NOT_REDACT_VERDICT)
                + c.get(CaptureSink.Outcome.MASKING_UNAVAILABLE) + c.get(CaptureSink.Outcome.KEY_UNAVAILABLE)
                + c.get(CaptureSink.Outcome.FAILED));
        if (!sink.enabled()) {
            return new ComponentView("capture", "UNKNOWN", "capture is off: metadata and verdicts only");
        }
        if (!keys.available()) {
            return new ComponentView("capture", "DOWN", keys.unavailableReason() + ": content is not stored; "
                + skipped);
        }
        String totals = "";
        if (databaseUp) {
            CaptureStore.Totals t = database.captures().totals();
            totals = t.records() + " records (" + t.ciphertextBytes() + " bytes) under key " + keys.activeId().orElse("")
                + "; ";
        }
        boolean degraded = c.get(CaptureSink.Outcome.DETECTOR_HIT) > 0 || c.get(CaptureSink.Outcome.FAILED) > 0;
        return new ComponentView("capture", degraded ? "DEGRADED" : "UP", "redacted mode; " + totals + skipped);
    }

    private ComponentView watermark() {
        WatermarkBreaker.State s = watermark.state();
        String used = CaptureWatermark.percent(watermark.lastUsed()) + " used";
        String skipped = sink.counts().get(CaptureSink.Outcome.WATERMARK) + " captures skipped since start";
        if (watermark.stale()) {
            return new ComponentView("capture-watermark", "DOWN",
                "no disk reading for 5 minutes: content is not persisted (fail closed); " + skipped);
        }
        return switch (s) {
            case NORMAL -> new ComponentView("capture-watermark", "UP", used + "; content may persist; " + skipped);
            case RAW_OFF -> new ComponentView("capture-watermark", "DEGRADED",
                used + "; above 75 %: raw off, redacted persists; " + skipped);
            case REDACTED_OFF -> new ComponentView("capture-watermark", "DOWN",
                used + "; above 85 %: redacted off, metadata and verdicts only; " + skipped);
        };
    }
}
