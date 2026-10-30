package io.rwsafe.architecture.fixtures.inline;

import java.util.concurrent.BlockingQueue;

public final class QueuePuttingInspector {

    public void inspect(BlockingQueue<String> events, String event) throws InterruptedException {
        events.put(event);
    }
}
