package io.rwsafe.architecture.fixtures.inline;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

public final class FutureWaitingInspector {

    public String inspect(Future<String> verdict) throws InterruptedException, ExecutionException {
        return verdict.get();
    }
}
