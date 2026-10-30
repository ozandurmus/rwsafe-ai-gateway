package io.rwsafe.platform.capacity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.platform.capacity.WatermarkBreaker.State;
import java.time.Instant;
import org.junit.jupiter.api.Test;

/** SR-HOST-2, PO decision Q-3: raw off at 75 %, redacted off at 85 %, hysteresis on the way back, stale trips. */
class WatermarkBreakerTest {

    private static final Instant T0 = Instant.parse("2026-10-31T09:00:00Z");

    @Test
    void thresholdsAndHysteresis() {
        WatermarkBreaker b = new WatermarkBreaker();
        b.record(0.50, T0);
        assertEquals(State.NORMAL, b.state(T0));
        b.record(0.75, T0);
        assertEquals(State.RAW_OFF, b.state(T0), "raw stops first");
        assertTrue(b.state(T0).allowsRedacted());
        assertFalse(b.state(T0).allowsRaw());
        b.record(0.85, T0);
        assertEquals(State.REDACTED_OFF, b.state(T0), "then redacted");
        b.record(0.82, T0);
        assertEquals(State.REDACTED_OFF, b.state(T0), "no resume above 80 %");
        b.record(0.799, T0);
        assertEquals(State.RAW_OFF, b.state(T0), "redacted resumes below 80 %");
        b.record(0.72, T0);
        assertEquals(State.RAW_OFF, b.state(T0), "raw does not resume above 70 %");
        b.record(0.69, T0);
        assertEquals(State.NORMAL, b.state(T0));
        b.record(0.84, T0);
        assertEquals(State.RAW_OFF, b.state(T0), "below 85 % from below stays redacted-on");
    }

    @Test
    void noReadingOrAStaleOneFailsClosed() {
        WatermarkBreaker b = new WatermarkBreaker();
        assertEquals(State.REDACTED_OFF, b.state(T0), "no reading yet");
        b.record(0.10, T0);
        assertEquals(State.NORMAL, b.state(T0.plusSeconds(299)));
        assertEquals(State.REDACTED_OFF, b.state(T0.plusSeconds(301)), "five minutes without a reading");
        b.record(Double.NaN, T0.plusSeconds(400));
        b.record(1.5, T0.plusSeconds(400));
        assertEquals(State.REDACTED_OFF, b.state(T0.plusSeconds(400)), "a broken probe is no reading");
        assertEquals(0.10, b.lastUsed());
    }
}
