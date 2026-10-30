package io.rwsafe.dataplane.server;

import io.rwsafe.dataplane.events.EventSink;
import io.rwsafe.dataplane.inspect.BodyInspector;
import io.rwsafe.detect.DetectorSet;
import io.rwsafe.policy.FlowClassifier;
import io.rwsafe.policy.PolicyEvaluator;
import io.rwsafe.policy.PolicySnapshot;

/**
 * The shared, immutable parts of the ICAP engine: snapshot, classifier, evaluator, inspector, event sink and limits. One
 * instance serves every connection; per-connection state lives in {@link IcapConnectionHandler}.
 */
public final class IcapEngine {

    public static final String REQMOD_PATH = "/reqmod-ai";
    public static final String RESPMOD_PATH = "/respmod-ai";

    private final PolicySnapshot snapshot;
    private final FlowClassifier classifier;
    private final PolicyEvaluator evaluator;
    private final BodyInspector inspector;
    private final EventSink events;
    private final EngineConfig config;
    private volatile boolean draining;

    public IcapEngine(PolicySnapshot snapshot, DetectorSet detectors, EventSink events, EngineConfig config) {
        this.snapshot = snapshot;
        this.classifier = new FlowClassifier(snapshot);
        this.evaluator = new PolicyEvaluator(snapshot);
        this.inspector = new BodyInspector(detectors);
        this.events = events;
        this.config = config;
    }

    PolicySnapshot snapshot() {
        return snapshot;
    }

    FlowClassifier classifier() {
        return classifier;
    }

    PolicyEvaluator evaluator() {
        return evaluator;
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

    /** OPTIONS answers 503 while draining, so ProxySG deselects the engine (ICAP spec §7). */
    public void startDraining() {
        draining = true;
    }

    boolean available() {
        return !draining;
    }
}
