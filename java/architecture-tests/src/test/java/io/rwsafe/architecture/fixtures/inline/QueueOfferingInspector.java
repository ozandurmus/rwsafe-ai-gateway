package io.rwsafe.architecture.fixtures.inline;

import java.util.concurrent.BlockingQueue;

/** Compliant: a full queue drops or counts, it never blocks the request thread. */
public final class QueueOfferingInspector {

    public boolean inspect(BlockingQueue<String> events, String event) {
        return events.offer(event);
    }
}
