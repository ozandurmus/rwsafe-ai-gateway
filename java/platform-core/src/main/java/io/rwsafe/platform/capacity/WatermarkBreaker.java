package io.rwsafe.platform.capacity;

import java.time.Duration;
import java.time.Instant;

/**
 * The disk-free watermark circuit breaker (PO decision Q-3, CAPACITY_AND_SLO_MODEL §2, SR-HOST-2): above 75 % used, raw
 * content stops persisting; above 85 %, redacted content stops too; metadata, verdicts and enforcement continue in every
 * state. A tripped level resumes only below its threshold minus {@link #HYSTERESIS}, so a filesystem hovering at a
 * threshold does not flap. Without a reading for {@link #MAX_READING_AGE} the breaker reports {@link State#REDACTED_OFF}
 * (fail closed for persistence, CAPACITY §2).
 *
 * <p>Pure logic, no I/O: the caller takes the readings (control plane: the database volume; data plane: the spool) and
 * feeds the highest used fraction. Thread-safe.
 */
public final class WatermarkBreaker {

    /** Q-3: raw content off at 75 % used. */
    public static final double RAW_OFF_AT = 0.75;
    /** Q-3: redacted content off at 85 % used. */
    public static final double REDACTED_OFF_AT = 0.85;
    /**
     * Resume below the threshold minus this. Five points is this lane's choice (Q-3 names the thresholds, not the
     * hysteresis); it is a constant so it changes only with a reviewed commit.
     */
    public static final double HYSTERESIS = 0.05;
    /** CAPACITY §2: with no reading for 5 minutes the breaker trips. */
    public static final Duration MAX_READING_AGE = Duration.ofMinutes(5);

    /** What may be persisted. */
    public enum State {
        /** Raw (when ever allowed) and redacted content may persist. */
        NORMAL,
        /** Raw content off; redacted content may persist. */
        RAW_OFF,
        /** Raw and redacted content off: metadata and verdicts only. */
        REDACTED_OFF;

        public boolean allowsRedacted() {
            return this != REDACTED_OFF;
        }

        public boolean allowsRaw() {
            return this == NORMAL;
        }
    }

    private boolean rawOff;
    private boolean redactedOff;
    private double lastUsed = Double.NaN;
    private Instant lastReadingAt;

    /**
     * Feeds one reading. A value outside {@code [0, 1]} (NaN included) is no reading: the age of the previous one keeps
     * counting, so a broken probe ends in the fail-closed state.
     *
     * @param usedFraction the highest used fraction of the watched filesystems, {@code 0..1}
     */
    public synchronized void record(double usedFraction, Instant at) {
        if (!(usedFraction >= 0.0 && usedFraction <= 1.0)) {
            return;
        }
        lastUsed = usedFraction;
        lastReadingAt = at;
        rawOff = rawOff ? usedFraction >= RAW_OFF_AT - HYSTERESIS : usedFraction >= RAW_OFF_AT;
        redactedOff = redactedOff ? usedFraction >= REDACTED_OFF_AT - HYSTERESIS : usedFraction >= REDACTED_OFF_AT;
    }

    /** The state at {@code now}: {@link State#REDACTED_OFF} when no reading is younger than {@link #MAX_READING_AGE}. */
    public synchronized State state(Instant now) {
        if (stale(now)) {
            return State.REDACTED_OFF;
        }
        if (redactedOff) {
            return State.REDACTED_OFF;
        }
        return rawOff ? State.RAW_OFF : State.NORMAL;
    }

    /** True when there is no reading, or the last one is older than {@link #MAX_READING_AGE}. */
    public synchronized boolean stale(Instant now) {
        return lastReadingAt == null || Duration.between(lastReadingAt, now).compareTo(MAX_READING_AGE) > 0;
    }

    /** The last accepted reading, or NaN before the first. */
    public synchronized double lastUsed() {
        return lastUsed;
    }

    /** When the last accepted reading was taken, or null before the first. */
    public synchronized Instant lastReadingAt() {
        return lastReadingAt;
    }
}
