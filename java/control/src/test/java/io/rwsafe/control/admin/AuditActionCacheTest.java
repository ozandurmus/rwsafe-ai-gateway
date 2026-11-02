package io.rwsafe.control.admin;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

/** PR 51 review D-04: the distinct-action query runs at most once per TTL, whatever the request rate. */
class AuditActionCacheTest {

    @Test
    void theLedgerIsAskedOncePerTtl() {
        AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-11-02T09:00:00Z"));
        Clock clock = new Clock() {
            @Override
            public ZoneId getZone() {
                return ZoneOffset.UTC;
            }

            @Override
            public Clock withZone(ZoneId zone) {
                return this;
            }

            @Override
            public Instant instant() {
                return now.get();
            }
        };
        AtomicInteger loads = new AtomicInteger();
        AuditActionCache cache = new AuditActionCache(() -> List.of("synthetic.action" + loads.incrementAndGet()),
            clock);
        for (int i = 0; i < 100; i++) {
            assertEquals(List.of("synthetic.action1"), cache.actions());
        }
        now.set(now.get().plus(AuditActionCache.TTL).minusSeconds(1));
        assertEquals(List.of("synthetic.action1"), cache.actions());
        assertEquals(1, loads.get());
        now.set(now.get().plusSeconds(1));
        assertEquals(List.of("synthetic.action2"), cache.actions(), "reloaded once the TTL has passed");
        assertEquals(2, loads.get());
    }
}
