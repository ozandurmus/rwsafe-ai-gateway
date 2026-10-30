package io.rwsafe.control.capture;

import io.rwsafe.control.config.ControlProperties;
import io.rwsafe.control.notice.NoticeAcknowledgementService;
import io.rwsafe.control.privacy.Masking;
import io.rwsafe.control.privacy.MaskingUnavailableException;
import io.rwsafe.control.privacy.TextMasker;
import io.rwsafe.detect.DetectorSet;
import io.rwsafe.detect.Normaliser;
import io.rwsafe.persistence.Database;
import io.rwsafe.persistence.SealedCapture;
import io.rwsafe.persistence.StoredVerdictEvent;
import io.rwsafe.platform.verdict.Verdict;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.EnumMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * The capture sink (ARCHITECTURE.md §4.5, ADR-009 §2): decides whether one ingested event's redacted text is stored, and
 * stores it sealed. In order, content is dropped (the event's metadata and verdict are stored regardless) when capture
 * is off; the verdict is not REDACT (C3 exists only for a rewrite); the event has no user; the user has no
 * acknowledgement of the current notice (SR-PRIV-10); the database volume is above the redacted watermark (Q-3,
 * SR-HOST-2); a Tier-1 detector still hits the text (SR-PRIV-11: the sink re-runs the detectors and rejects); masking
 * at persistence is unavailable; or no capture key is mounted. Each outcome is counted for the Health screen; nothing
 * here logs, since it reads content (AGENTS.md 4.14).
 */
@Service
public class CaptureSink {

    /** The associated data that binds a sealed text to its event. */
    static final String AAD_PREFIX = "rwsafe-c3-v1|";
    private static final DetectorSet DETECTORS = DetectorSet.standard();

    /** What happened to one event's captured content. */
    public enum Outcome {
        STORED, DUPLICATE, CAPTURE_OFF, NOT_REDACT_VERDICT, NO_USER, NO_ACKNOWLEDGEMENT, WATERMARK, DETECTOR_HIT,
        MASKING_UNAVAILABLE, KEY_UNAVAILABLE, FAILED
    }

    private final ControlProperties.Capture config;
    private final NoticeAcknowledgementService notices;
    private final CaptureWatermark watermark;
    private final CaptureKeyring keys;
    private final Masking masking;
    private final Database database;
    private final Clock clock;
    private final Map<Outcome, AtomicLong> counts = new EnumMap<>(Outcome.class);

    @Autowired
    public CaptureSink(ControlProperties properties, NoticeAcknowledgementService notices, CaptureWatermark watermark,
                       CaptureKeyring keys, Masking masking, Database database) {
        this(properties.capture(), notices, watermark, keys, masking, database, Clock.systemUTC());
    }

    CaptureSink(ControlProperties.Capture config, NoticeAcknowledgementService notices, CaptureWatermark watermark,
                CaptureKeyring keys, Masking masking, Database database, Clock clock) {
        this.config = config;
        this.notices = notices;
        this.watermark = watermark;
        this.keys = keys;
        this.masking = masking;
        this.database = database;
        this.clock = clock;
        for (Outcome o : Outcome.values()) {
            counts.put(o, new AtomicLong());
        }
    }

    /** Decides and stores; never throws for a content reason, so the batch's metadata is never refused because of it. */
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
        // ADR-009 §2: the masking layers run at persistence as well as at view.
        byte[] plain = masking.masker().mask(text).getBytes(StandardCharsets.UTF_8);
        Instant now = clock.instant().truncatedTo(ChronoUnit.MICROS);
        CaptureKeyring.Sealed sealed = keys.seal(plain, aad(event.eventId()));
        Duration retention = config.retention();
        boolean stored = database.captures().insert(new SealedCapture(event.eventId(), now, now.plus(retention),
            event.userPseudonym(), sealed.keyId(), sealed.wrappedKey(), sealed.nonce(), sealed.ciphertext(), plain.length,
            Boolean.TRUE.equals(capture.truncated()), TextMasker.RULE_SET, false));
        return stored ? Outcome.STORED : Outcome.DUPLICATE;
    }

    static byte[] aad(UUID eventId) {
        return (AAD_PREFIX + eventId).getBytes(StandardCharsets.US_ASCII);
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
