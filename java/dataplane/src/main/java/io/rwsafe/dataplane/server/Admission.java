package io.rwsafe.dataplane.server;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;

/**
 * Admission control for the ICAP engine (ICAP spec §3, OFF2-10, PLAT-F1): transactions in flight per engine and per
 * identity, and the pod-wide budget of captured body bytes. Lock-free and non-blocking, so request threads only ever try
 * and never wait. Identity keys are the proxy's claims as received; they stay in memory and never leave this class.
 */
public final class Admission {

    /** Why admission refused a transaction. */
    public enum Refusal { ENGINE_FULL, IDENTITY_LIMIT }

    /** An admitted transaction; {@link #exit} releases it exactly once. */
    public static final class Ticket {
        private final String key;
        private boolean released;

        private Ticket(String key) {
            this.key = key;
        }
    }

    private final EngineConfig config;
    private final AtomicInteger inflight = new AtomicInteger();
    private final ConcurrentHashMap<String, Integer> perIdentity = new ConcurrentHashMap<>();
    private final AtomicLong bodyBytes = new AtomicLong();
    private final LongAdder identityCapped = new LongAdder();
    private final LongAdder engineFull = new LongAdder();
    private final LongAdder bodyBudgetRejections = new LongAdder();

    public Admission(EngineConfig config) {
        this.config = config;
    }

    /** Admits a transaction or returns the refusal; {@code ticketOut[0]} receives the ticket when admitted. */
    public Refusal tryEnter(String userClaim, String clientAddress, Ticket[] ticketOut) {
        if (inflight.incrementAndGet() > config.maxInflight()) {
            inflight.decrementAndGet();
            engineFull.increment();
            return Refusal.ENGINE_FULL;
        }
        // Claims are attacker-influenced: bounded before they become a key (PR 14 review D-05).
        String user = bounded(userClaim, 256);
        String address = bounded(clientAddress, 64);
        String key;
        int limit;
        if (user != null && !user.isBlank()) {
            key = "u:" + user;
            limit = config.perIdentityInflight();
        } else if (address != null && shared(address)) {
            key = "s:" + address;
            limit = config.perSharedAddress();
        } else {
            key = "a:" + (address == null ? "" : address);
            limit = config.perIdentityInflight();
        }
        boolean[] admitted = new boolean[1];
        // Check and increment in one atomic step per key, so a concurrent exit cannot orphan a counter (D-05).
        perIdentity.compute(key, (k, n) -> {
            int current = n == null ? 0 : n;
            if (current >= limit) {
                return n;
            }
            admitted[0] = true;
            return current + 1;
        });
        if (!admitted[0]) {
            inflight.decrementAndGet();
            identityCapped.increment();
            return Refusal.IDENTITY_LIMIT;
        }
        ticketOut[0] = new Ticket(key);
        return null;
    }

    public void exit(Ticket t) {
        if (t == null || t.released) {
            return;
        }
        t.released = true;
        inflight.decrementAndGet();
        perIdentity.computeIfPresent(t.key, (k, n) -> n <= 1 ? null : n - 1);
    }

    /** Reserves body bytes against the pod-wide budget; false means the transaction gets 503 (PLAT-F1). */
    public boolean reserveBody(long bytes) {
        long after = bodyBytes.addAndGet(bytes);
        if (after > config.bodyBudgetBytes()) {
            bodyBytes.addAndGet(-bytes);
            bodyBudgetRejections.increment();
            return false;
        }
        return true;
    }

    public void releaseBody(long bytes) {
        if (bytes > 0) {
            bodyBytes.addAndGet(-bytes);
        }
    }

    private static String bounded(String v, int max) {
        return v == null || v.length() <= max ? v : v.substring(0, max);
    }

    private boolean shared(String address) {
        for (String prefix : config.sharedAddressPrefixes()) {
            if (address.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    public int inflight() {
        return inflight.get();
    }

    public long bodyBytesHeld() {
        return bodyBytes.get();
    }

    public long identityCapped() {
        return identityCapped.sum();
    }

    public long engineFull() {
        return engineFull.sum();
    }

    public long bodyBudgetRejections() {
        return bodyBudgetRejections.sum();
    }
}
