package io.rwsafe.architecture.fixtures.inline;

public final class SleepingInspector {

    public void inspect() throws InterruptedException {
        Thread.sleep(10L);
    }
}
