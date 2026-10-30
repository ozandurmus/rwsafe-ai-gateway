package io.rwsafe.control.capture;

import io.rwsafe.control.api.Views.ComponentView;
import io.rwsafe.persistence.CaptureStore;
import io.rwsafe.persistence.Database;
import io.rwsafe.platform.capacity.WatermarkBreaker;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * The Health screen's capture components (SR-HOST-2: the breaker's state and what it skipped): the capture store (mode,
 * key, records, chunks, bytes against MAX_STORE_BYTES, what a rotation has not re-wrapped yet, and the counts of every
 * reason content was not stored) and the watermark. Counts only. The same numbers travel as {@code counts} under fixed
 * keys (PR 28 review D-03), which the admin UI reads:
 * <ul>
 *   <li>{@code capture}: {@code captureOn}, {@code keyAvailable}, {@code storeWritable} (0/1); {@code stored},
 *       {@code noAcknowledgement}, {@code aboveWatermark}, {@code detectorHit}, {@code evicted}, {@code other} (since
 *       start); with the database up {@code records}, {@code chunks}, {@code storedBytes}, {@code maxBytes},
 *       {@code heldRecords}, {@code rewrapRecords}, {@code rewrapChunks}, {@code shreddedKeyRecords},
 *       {@code missingKeyRecords};</li>
 *   <li>{@code capture-watermark}: {@code stale} (0/1), {@code usedPerMille} (absent without a reading),
 *       {@code skipped}.</li>
 * </ul>
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

    private static long count(Map<CaptureSink.Outcome, Long> c, CaptureSink.Outcome o) {
        Long v = c.get(o);
        return v == null ? 0 : v;
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
        Map<String, Long> counts = new LinkedHashMap<>();
        counts.put("captureOn", sink.enabled() ? 1L : 0L);
        if (!sink.enabled()) {
            return new ComponentView("capture", "UNKNOWN", "capture is off: metadata and verdicts only", counts);
        }
        counts.put("keyAvailable", keys.available() ? 1L : 0L);
        counts.put("storeWritable", files.available() ? 1L : 0L);
        counts.put("stored", count(c, CaptureSink.Outcome.STORED));
        counts.put("noAcknowledgement", count(c, CaptureSink.Outcome.NO_ACKNOWLEDGEMENT));
        counts.put("aboveWatermark", count(c, CaptureSink.Outcome.WATERMARK));
        counts.put("detectorHit", count(c, CaptureSink.Outcome.DETECTOR_HIT));
        counts.put("evicted", cap.evicted());
        counts.put("other", other);
        if (!keys.available()) {
            return new ComponentView("capture", "DOWN", keys.unavailableReason() + ": content is not stored; "
                + skipped, counts);
        }
        if (!files.available()) {
            return new ComponentView("capture", "DOWN", "capture store volume not writable: content is not stored; "
                + skipped, counts);
        }
        String totals = "";
        boolean rotationPending = false;
        boolean keyMissing = false;
        if (databaseUp) {
            CaptureStore.Totals t = database.captures().totals(keys.activeId().orElse(null), keys.ids(),
                keys.shredded());
            rotationPending = t.recordsUnderOtherKeys() + t.chunksUnderOtherKeys() > 0;
            keyMissing = t.recordsUnderMissingKeys() > 0;
            // D-09: a rotation still to re-wrap, held records an emergency shred left (expected, unreadable), and
            // records under a key that is merely missing (a fault) are reported apart.
            totals = t.records() + " records, " + t.chunks() + " chunks, " + t.storedBytes() + " of " + cap.maxBytes()
                + " bytes, " + t.heldRecords() + " on hold; to re-wrap from older mounted keys: "
                + t.recordsUnderOtherKeys() + " records and " + t.chunksUnderOtherKeys() + " chunks; held under "
                + "shredded keys: " + t.recordsUnderShreddedKeys() + "; under missing keys: "
                + t.recordsUnderMissingKeys() + "; ";
            counts.put("records", t.records());
            counts.put("chunks", t.chunks());
            counts.put("storedBytes", t.storedBytes());
            counts.put("maxBytes", cap.maxBytes());
            counts.put("heldRecords", t.heldRecords());
            counts.put("rewrapRecords", t.recordsUnderOtherKeys());
            counts.put("rewrapChunks", t.chunksUnderOtherKeys());
            counts.put("shreddedKeyRecords", t.recordsUnderShreddedKeys());
            counts.put("missingKeyRecords", t.recordsUnderMissingKeys());
        }
        boolean degraded = c.get(CaptureSink.Outcome.DETECTOR_HIT) > 0 || c.get(CaptureSink.Outcome.FAILED) > 0
            || c.get(CaptureSink.Outcome.STORE_FULL) > 0 || rotationPending || keyMissing;
        return new ComponentView("capture", degraded ? "DEGRADED" : "UP", "redacted mode, active key "
            + keys.activeId().orElse("") + "; " + totals + skipped, counts);
    }

    private ComponentView watermark() {
        WatermarkBreaker.State s = watermark.state();
        String used = CaptureWatermark.percent(watermark.lastUsed()) + " used";
        long skippedCount = count(sink.counts(), CaptureSink.Outcome.WATERMARK);
        String skipped = sink.counts().get(CaptureSink.Outcome.WATERMARK) + " captures skipped since start";
        Map<String, Long> counts = new LinkedHashMap<>();
        counts.put("stale", watermark.stale() ? 1L : 0L);
        counts.put("skipped", skippedCount);
        if (watermark.stale()) {
            return new ComponentView("capture-watermark", "DOWN",
                "no disk reading for 5 minutes: content is not persisted (fail closed); " + skipped, counts);
        }
        double fraction = watermark.lastUsed();
        if (!Double.isNaN(fraction)) {
            counts.put("usedPerMille", Math.round(fraction * 1000));
        }
        return switch (s) {
            case NORMAL -> new ComponentView("capture-watermark", "UP", used + "; content may persist; " + skipped,
                counts);
            case RAW_OFF -> new ComponentView("capture-watermark", "DEGRADED",
                used + "; above 75 %: raw off, redacted persists; " + skipped, counts);
            case REDACTED_OFF -> new ComponentView("capture-watermark", "DOWN",
                used + "; above 85 %: redacted off, metadata and verdicts only; " + skipped, counts);
        };
    }
}
