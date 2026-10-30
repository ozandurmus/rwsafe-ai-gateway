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
    private final ConcurrentHashMap<String, AtomicInteger> perIdentity = new ConcurrentHashMap<>();
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
        String key;
        int limit;
        if (userClaim != null && !userClaim.isBlank()) {
            key = "u:" + userClaim;
            limit = config.perIdentityInflight();
        } else if (clientAddress != null && shared(clientAddress)) {
            key = "s:" + clientAddress;
            limit = config.perSharedAddress();
        } else {
            key = "a:" + (clientAddress == null ? "" : clientAddress);
            limit = config.perIdentityInflight();
        }
        AtomicInteger n = perIdentity.computeIfAbsent(key, k -> new AtomicInteger());
        if (n.incrementAndGet() > limit) {
            n.decrementAndGet();
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
        AtomicInteger n = perIdentity.get(t.key);
        if (n != null && n.decrementAndGet() <= 0) {
            perIdentity.remove(t.key, n);
        }
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
