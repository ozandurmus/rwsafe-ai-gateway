package io.rwsafe.control.siem;

import io.rwsafe.control.siem.SiemDeliveryException.Reason;
import io.rwsafe.control.siem.SiemField.SiemStream;
import java.time.Instant;
import java.util.EnumMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.LongAdder;
import java.util.function.IntSupplier;

/**
 * Counters of one exporter. Every label comes from a fixed vocabulary (destination {@code syslog}/{@code hec}, stream,
 * failure reason); no label or value ever carries a host, a user, a field value or a server answer (AGENTS.md 4.14).
 * {@link #prometheus()} renders them for the control plane's metrics listener (PORTS_AND_RESOURCES 9400, not yet served).
 */
public final class SiemMetrics {

    private final String destination;
    private final int queueCapacity;
    private final Map<SiemStream, LongAdder> exported = new EnumMap<>(SiemStream.class);
    private final Map<Reason, LongAdder> failures = new EnumMap<>(Reason.class);
    private final LongAdder deferredReads = new LongAdder();
    private final LongAdder batches = new LongAdder();
    private final AtomicReference<Instant> lastDelivery = new AtomicReference<>();
    private final AtomicReference<Reason> lastFailure = new AtomicReference<>();
    private volatile IntSupplier queueDepth = () -> 0;

    public SiemMetrics(String destination, int queueCapacity) {
        if (!destination.equals("syslog") && !destination.equals("hec")) {
            throw new IllegalArgumentException("destination is syslog or hec");
        }
        this.destination = destination;
        this.queueCapacity = queueCapacity;
        exported.put(SiemStream.VERDICT, new LongAdder());
        exported.put(SiemStream.AUDIT, new LongAdder());
        for (Reason r : Reason.values()) {
            failures.put(r, new LongAdder());
        }
    }

    void queueDepth(IntSupplier depth) {
        this.queueDepth = depth;
    }

    void delivered(SiemStream stream, long count) {
        exported.get(stream).add(count);
    }

    void batchDelivered(Instant at) {
        batches.increment();
        lastDelivery.set(at);
        lastFailure.set(null);
    }

    void failure(Reason reason) {
        failures.get(reason).increment();
        lastFailure.set(reason);
    }

    void deferredRead() {
        deferredReads.increment();
    }

    public String destination() {
        return destination;
    }

    public long exported(SiemStream stream) {
        return exported.get(stream).sum();
    }

    public long failures(Reason reason) {
        return failures.get(reason).sum();
    }

    public long deferredReads() {
        return deferredReads.sum();
    }

    public long batches() {
        return batches.sum();
    }

    public int queueDepth() {
        return queueDepth.getAsInt();
    }

    public int queueCapacity() {
        return queueCapacity;
    }

    public Instant lastDelivery() {
        return lastDelivery.get();
    }

    /** The failure class of the latest attempt, or null when the latest attempt succeeded. */
    public Reason lastFailure() {
        return lastFailure.get();
    }

    /** Prometheus text exposition, labels from the fixed vocabularies only. */
    public String prometheus() {
        StringBuilder s = new StringBuilder();
        s.append("# TYPE rwsafe_siem_events_exported_total counter\n");
        for (Map.Entry<SiemStream, LongAdder> e : exported.entrySet()) {
            s.append("rwsafe_siem_events_exported_total{destination=\"").append(destination).append("\",stream=\"")
                .append(e.getKey().name().toLowerCase(java.util.Locale.ROOT)).append("\"} ").append(e.getValue().sum())
                .append('\n');
        }
        s.append("# TYPE rwsafe_siem_delivery_failures_total counter\n");
        for (Map.Entry<Reason, LongAdder> e : failures.entrySet()) {
            s.append("rwsafe_siem_delivery_failures_total{destination=\"").append(destination).append("\",reason=\"")
                .append(e.getKey().name().toLowerCase(java.util.Locale.ROOT)).append("\"} ").append(e.getValue().sum())
                .append('\n');
        }
        s.append("# TYPE rwsafe_siem_reads_deferred_total counter\n");
        s.append("rwsafe_siem_reads_deferred_total{destination=\"").append(destination).append("\"} ")
            .append(deferredReads.sum()).append('\n');
        s.append("# TYPE rwsafe_siem_queue_depth gauge\n");
        s.append("rwsafe_siem_queue_depth{destination=\"").append(destination).append("\"} ").append(queueDepth())
            .append('\n');
        s.append("# TYPE rwsafe_siem_queue_capacity gauge\n");
        s.append("rwsafe_siem_queue_capacity{destination=\"").append(destination).append("\"} ").append(queueCapacity)
            .append('\n');
        return s.toString();
    }
}
