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
 * key, records, chunks, bytes against MAX_STORE_BYTES, what a rotation has not re-wrapped yet, and the counts of every
 * reason content was not stored) and the watermark. Counts only.
 */
@Component
public class CaptureHealth {

    private final CaptureSink sink;
    private final CaptureWatermark watermark;
    private final CaptureKeyring keys;
    private final ChunkFiles files;
    private final StoreCap cap;
    private final Database database;

    public CaptureHealth(CaptureSink sink, CaptureWatermark watermark, CaptureKeyring keys, ChunkFiles files,
                         StoreCap cap, Database database) {
        this.sink = sink;
        this.watermark = watermark;
        this.keys = keys;
        this.files = files;
        this.cap = cap;
        this.database = database;
    }

    public List<ComponentView> components(boolean databaseUp) {
        return List.of(store(databaseUp), watermark());
    }

    private ComponentView store(boolean databaseUp) {
        Map<CaptureSink.Outcome, Long> c = sink.counts();
        long other = c.entrySet().stream().filter(e -> switch (e.getKey()) {
            case STORED, NO_ACKNOWLEDGEMENT, WATERMARK, DETECTOR_HIT, CAPTURE_OFF -> false;
            default -> true;
        }).mapToLong(Map.Entry::getValue).sum();
        String skipped = "since start: stored " + c.get(CaptureSink.Outcome.STORED)
            + ", without acknowledgement " + c.get(CaptureSink.Outcome.NO_ACKNOWLEDGEMENT)
            + ", above the watermark " + c.get(CaptureSink.Outcome.WATERMARK)
            + ", detector hit refused " + c.get(CaptureSink.Outcome.DETECTOR_HIT)
            + ", evicted for the cap " + cap.evicted() + ", other " + other;
        if (!sink.enabled()) {
            return new ComponentView("capture", "UNKNOWN", "capture is off: metadata and verdicts only");
        }
        if (!keys.available()) {
            return new ComponentView("capture", "DOWN", keys.unavailableReason() + ": content is not stored; "
                + skipped);
        }
        if (!files.available()) {
            return new ComponentView("capture", "DOWN", "capture store volume not writable: content is not stored; "
                + skipped);
        }
        String totals = "";
        boolean rotationPending = false;
        if (databaseUp) {
            CaptureStore.Totals t = database.captures().totals(keys.activeId().orElse(null));
            rotationPending = t.recordsUnderOtherKeys() + t.chunksUnderOtherKeys() > 0;
            totals = t.records() + " records, " + t.chunks() + " chunks, " + t.storedBytes() + " of " + cap.maxBytes()
                + " bytes, " + t.heldRecords() + " on hold; under older keys: " + t.recordsUnderOtherKeys()
                + " records and " + t.chunksUnderOtherKeys() + " chunks; ";
        }
        boolean degraded = c.get(CaptureSink.Outcome.DETECTOR_HIT) > 0 || c.get(CaptureSink.Outcome.FAILED) > 0
            || c.get(CaptureSink.Outcome.STORE_FULL) > 0 || rotationPending;
        return new ComponentView("capture", degraded ? "DEGRADED" : "UP", "redacted mode, active key "
            + keys.activeId().orElse("") + "; " + totals + skipped);
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
