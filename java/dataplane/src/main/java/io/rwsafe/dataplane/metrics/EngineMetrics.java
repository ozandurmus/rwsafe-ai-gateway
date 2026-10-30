package io.rwsafe.dataplane.metrics;

import io.rwsafe.platform.verdict.Verdict;
import java.util.concurrent.atomic.LongAdder;

/**
 * Counters of the ICAP engine (ICAP spec §8). Labels come from fixed vocabularies only (method, verdict); no label ever
 * carries a user, tenant, host, prompt or URL string (AGENTS.md 4.14).
 */
public final class EngineMetrics {

    public enum Method { REQMOD, RESPMOD }

    private final LongAdder[][] transactions = new LongAdder[Method.values().length][Verdict.values().length];

    public EngineMetrics() {
        for (LongAdder[] row : transactions) {
            for (int i = 0; i < row.length; i++) {
                row[i] = new LongAdder();
            }
        }
    }

    public void transaction(Method method, Verdict verdict) {
        transactions[method.ordinal()][verdict.ordinal()].increment();
    }

    public long transactions(Method method, Verdict verdict) {
        return transactions[method.ordinal()][verdict.ordinal()].sum();
    }
}
