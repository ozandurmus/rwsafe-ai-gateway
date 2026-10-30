package io.rwsafe.architecture.fixtures.inline;

public final class MonitorWaitingInspector {

    private final Object lock = new Object();

    public void inspect() throws InterruptedException {
        synchronized (lock) {
            lock.wait(10L);
        }
    }
}
