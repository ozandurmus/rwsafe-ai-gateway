package io.rwsafe.dataplane.events;

import java.util.Collection;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The bounded hand-off between request threads and the control-plane client thread (AGENTS.md section 5): {@code offer}
 * only, so a request thread never waits; an event that does not fit is counted in {@link #dropped()}.
 *
 * <p>ADR-010 §3 requires verdict events to be spooled to an emptyDir ring file rather than dropped; the spool arrives with
 * the deploy slice, and until then the drop counter makes every loss visible.
 */
public final class BoundedEventQueue implements EventSink {

    private final ArrayBlockingQueue<VerdictEvent> queue;
    private final AtomicLong dropped = new AtomicLong();

    public BoundedEventQueue(int capacity) {
        this.queue = new ArrayBlockingQueue<>(capacity);
    }

    @Override
    public void emit(VerdictEvent event) {
        if (!queue.offer(event)) {
            dropped.incrementAndGet();
        }
    }

    @Override
    public boolean saturated() {
        return queue.remainingCapacity() == 0;
    }

    /** Moves up to {@code max} queued events into {@code into}; never waits. */
    public int drainTo(Collection<VerdictEvent> into, int max) {
        return queue.drainTo(into, max);
    }

    public int size() {
        return queue.size();
    }

    public long dropped() {
        return dropped.get();
    }
}
