package io.rwsafe.control.capture;

import io.rwsafe.control.config.ControlProperties;
import io.rwsafe.control.notice.NoticeAcknowledgementService;
import io.rwsafe.control.privacy.Masking;
import io.rwsafe.control.privacy.MaskingUnavailableException;
import io.rwsafe.control.privacy.TextMasker;
import io.rwsafe.detect.DetectorSet;
import io.rwsafe.detect.Normaliser;
import io.rwsafe.persistence.StoredVerdictEvent;
import io.rwsafe.platform.verdict.Verdict;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * The capture sink (ARCHITECTURE.md §4.5, ADR-009 §2): decides whether one ingested event's redacted text is stored, and
 * stores it in the capture store. In order, content is dropped (the event's metadata and verdict are stored regardless)
 * when capture is off; the verdict is not REDACT (C3 exists only for a rewrite); the event has no user; the user has no
 * acknowledgement of the current notice (SR-PRIV-10); the store's volume is above the redacted watermark (Q-3,
 * SR-HOST-2); a Tier-1 detector still hits the text (SR-PRIV-11: the sink re-runs the detectors and rejects); masking at
 * persistence is unavailable; no capture key or no store volume is usable; the masked text is empty or larger than a
 * record may be; the record would already be past its retention; or the byte cap cannot be met even after evicting the
 * oldest records. Each outcome is counted for the Health screen; nothing here logs, since it reads content (AGENTS.md
 * 4.14).
 */
@Service
public class CaptureSink {

    private static final DetectorSet DETECTORS = DetectorSet.standard();

    /** What happened to one event's captured content. */
    public enum Outcome {
        STORED, DUPLICATE, CAPTURE_OFF, NOT_REDACT_VERDICT, NO_USER, NO_ACKNOWLEDGEMENT, WATERMARK, DETECTOR_HIT,
        MASKING_UNAVAILABLE, KEY_UNAVAILABLE, STORE_UNAVAILABLE, EMPTY, TOO_LARGE, EXPIRED, STORE_FULL, FAILED
    }

    private final ControlProperties.Capture config;
    private final NoticeAcknowledgementService notices;
    private final CaptureWatermark watermark;
    private final CaptureKeyring keys;
    private final ChunkFiles files;
    private final CaptureVault vault;
    private final StoreCap cap;
    private final Masking masking;
    private final Clock clock;
    private final Map<Outcome, AtomicLong> counts = new EnumMap<>(Outcome.class);

    @Autowired
    public CaptureSink(ControlProperties properties, NoticeAcknowledgementService notices, CaptureWatermark watermark,
                       CaptureKeyring keys, ChunkFiles files, CaptureVault vault, StoreCap cap, Masking masking) {
        this(properties.capture(), notices, watermark, keys, files, vault, cap, masking, Clock.systemUTC());
    }

    CaptureSink(ControlProperties.Capture config, NoticeAcknowledgementService notices, CaptureWatermark watermark,
                CaptureKeyring keys, ChunkFiles files, CaptureVault vault, StoreCap cap, Masking masking, Clock clock) {
        this.config = config;
        this.notices = notices;
        this.watermark = watermark;
        this.keys = keys;
        this.files = files;
        this.vault = vault;
        this.cap = cap;
        this.masking = masking;
        this.clock = clock;
        for (Outcome o : Outcome.values()) {
            counts.put(o, new AtomicLong());
        }
    }

    /** Decides and stores; never throws, so the batch's metadata is never refused because of its content. */
    public Outcome accept(StoredVerdictEvent event, CapturedContent capture) {
        Outcome outcome;
        try {
            outcome = decideAndStore(event, capture);
        } catch (MaskingUnavailableException e) {
            outcome = Outcome.MASKING_UNAVAILABLE;
        } catch (RuntimeException e) {
            outcome = Outcome.FAILED;
        }
        counts.get(outcome).incrementAndGet();
        return outcome;
    }

    private Outcome decideAndStore(StoredVerdictEvent event, CapturedContent capture) {
        if (!config.redacted()) {
            return Outcome.CAPTURE_OFF;
        }
        if (event.verdict() != Verdict.REDACT) {
            return Outcome.NOT_REDACT_VERDICT;
        }
        if (event.userPseudonym() == null) {
            return Outcome.NO_USER;
        }
        if (!notices.contentCaptureAllowed(event.userPseudonym())) {
            return Outcome.NO_ACKNOWLEDGEMENT;
        }
        if (!watermark.state().allowsRedacted()) {
            return Outcome.WATERMARK;
        }
        String text = capture.text();
        if (!DETECTORS.scan(text).isEmpty() || !DETECTORS.scan(Normaliser.normalise(text)).isEmpty()) {
            return Outcome.DETECTOR_HIT;
        }
        if (!masking.available()) {
            return Outcome.MASKING_UNAVAILABLE;
        }
        if (!keys.available()) {
            return Outcome.KEY_UNAVAILABLE;
        }
        if (!files.available()) {
            return Outcome.STORE_UNAVAILABLE;
        }
        // D-06: expiry counts from the event's own time (a spooled event is not kept longer), bounded by 90 days.
        Instant now = CaptureVault.micros(clock.instant());
        Instant from = event.receivedAt().isBefore(now) ? event.receivedAt() : now;
        Instant expiresAt = CaptureVault.micros(from.plus(config.retention()));
        if (!expiresAt.isAfter(now)) {
            return Outcome.EXPIRED;
        }
        // ADR-009 §2: the masking layers run at persistence as well as at view; captured text is free text, so the
        // free-text layers 4 and 5 run too (SR-PRIV-15, PC-7).
        byte[] plain = masking.masker().maskFreeText(text).getBytes(StandardCharsets.UTF_8);
        try {
            if (plain.length == 0) {
                return Outcome.EMPTY;
            }
            if (plain.length > CaptureVault.MAX_PLAIN_BYTES) {
                return Outcome.TOO_LARGE;
            }
            CaptureVault.Prepared prepared = vault.prepare(plain, plain.length);
            try {
                if (!cap.makeRoom(prepared.newBytes())) {
                    return Outcome.STORE_FULL;
                }
                boolean stored = prepared.store(event.eventId(), event.userPseudonym(), now, expiresAt, plain.length,
                    Boolean.TRUE.equals(capture.truncated()), TextMasker.RULE_SET);
                return stored ? Outcome.STORED : Outcome.DUPLICATE;
            } finally {
                prepared.discard();
            }
        } finally {
            Arrays.fill(plain, (byte) 0);
        }
    }

    /** Counts since start, per outcome (Health). */
    public Map<Outcome, Long> counts() {
        Map<Outcome, Long> out = new EnumMap<>(Outcome.class);
        counts.forEach((k, v) -> out.put(k, v.get()));
        return out;
    }

    public boolean enabled() {
        return config.redacted();
    }
}
