package io.rwsafe.dataplane.server;

import io.rwsafe.dataplane.events.EventSink;
import io.rwsafe.dataplane.inspect.BodyInspector;
import io.rwsafe.dataplane.metrics.EngineMetrics;
import io.rwsafe.detect.DetectorSet;
import io.rwsafe.policy.FlowClassifier;
import io.rwsafe.policy.PolicyEvaluator;
import io.rwsafe.policy.PolicySnapshot;
import java.time.Clock;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The shared parts of the ICAP engine: the active policy (swapped atomically, never downgraded), inspector, event sink,
 * limits and the admission controls. One instance serves every connection; per-connection state lives in
 * {@link IcapConnectionHandler}, which takes the active policy once per transaction so a swap never changes a decision
 * halfway.
 */
public final class IcapEngine {

    public static final String REQMOD_PATH = "/reqmod-ai";
    public static final String RESPMOD_PATH = "/respmod-ai";

    /** The policy a transaction decides with: the snapshot and what is compiled from it. */
    public record Policy(PolicySnapshot snapshot, FlowClassifier classifier, PolicyEvaluator evaluator) {
        static Policy of(PolicySnapshot s) {
            return new Policy(s, new FlowClassifier(s), new PolicyEvaluator(s));
        }
    }

    /** Result of offering a new snapshot. */
    public enum Activation { ACTIVATED, NOT_NEWER }

    private final AtomicReference<Policy> active = new AtomicReference<>();
    private final BodyInspector inspector;
    private final EventSink events;
    private final EngineConfig config;
    private final Admission admission;
    private final EngineMetrics metrics = new EngineMetrics();
    private volatile long drainingSinceNanos = -1;
    private final Clock clock;

    /** @param initial the starting snapshot, or null to start not ready until {@link #activate} succeeds */
    public IcapEngine(PolicySnapshot initial, DetectorSet detectors, EventSink events, EngineConfig config) {
        this(initial, detectors, events, config, new Admission(config));
    }

    public IcapEngine(PolicySnapshot initial, DetectorSet detectors, EventSink events, EngineConfig config,
                      Admission admission) {
        this(initial, detectors, events, config, admission, Clock.systemUTC());
    }

    public IcapEngine(PolicySnapshot initial, DetectorSet detectors, EventSink events, EngineConfig config,
                      Admission admission, Clock clock) {
        this.clock = clock;
        if (initial != null) {
            active.set(Policy.of(initial));
        }
        this.inspector = new BodyInspector(detectors);
        this.events = events;
        this.config = config;
        this.admission = admission;
    }

    /**
     * Activates {@code next} only when its version is higher than the active one (OFF2-11): a replayed or older snapshot
     * never loads, whatever its signature.
     */
    public Activation activate(PolicySnapshot next) {
        while (true) {
            Policy current = active.get();
            if (current != null && next.version() <= current.snapshot().version()) {
                return Activation.NOT_NEWER;
            }
            if (active.compareAndSet(current, Policy.of(next))) {
                return Activation.ACTIVATED;
            }
        }
    }

    /** The active policy, or null before the first snapshot. */
    public Policy policy() {
        return active.get();
    }

    BodyInspector inspector() {
        return inspector;
    }

    EventSink events() {
        return events;
    }

    EngineConfig config() {
        return config;
    }

    public EngineMetrics metrics() {
        return metrics;
    }

    public Admission admission() {
        return admission;
    }

    /** OPTIONS answers 503 from now on, so ProxySG deselects the engine (ICAP spec §7). */
    public void startDraining() {
        if (drainingSinceNanos < 0) {
            drainingSinceNanos = System.nanoTime();
        }
    }

    public boolean draining() {
        return drainingSinceNanos >= 0;
    }

    /** During the first 15 s of a drain transactions are served with Connection: close; afterwards they are refused. */
    boolean refusingNewTransactions() {
        return draining() && System.nanoTime() - drainingSinceNanos > config.drainServeNanos();
    }

    /**
     * The active policy if it can still be used: an expired one (signed more than 24 hours ago and not renewed, because
     * the control plane is unreachable or keeps answering 304) is not (SR-DP-8, PR 14 review D-03).
     */
    public Policy usablePolicy() {
        Policy p = active.get();
        return p == null || p.snapshot().isStale(clock.instant()) ? null : p;
    }

    /** Ready: a usable policy, not draining, and the event path is not saturated. */
    public boolean available() {
        return usablePolicy() != null && !draining() && !events.saturated();
    }
}
