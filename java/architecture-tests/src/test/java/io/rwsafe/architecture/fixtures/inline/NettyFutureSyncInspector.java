package io.rwsafe.architecture.fixtures.inline;

import io.netty.util.concurrent.Future;

/** Violates the request-thread fence: waits on a Netty future (PR 11 review D-11). */
public final class NettyFutureSyncInspector {

    public void inspect(Future<?> pending) throws InterruptedException {
        pending.sync();
    }
}
