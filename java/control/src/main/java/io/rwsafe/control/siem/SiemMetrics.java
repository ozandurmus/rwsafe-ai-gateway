package io.rwsafe.control.siem;

import io.rwsafe.control.siem.SiemDeliveryException.Reason;
import io.rwsafe.control.siem.SiemField.SiemStream;
import java.time.Instant;
import java.util.EnumMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.LongAdder;
import java.util.function.IntSupplier;
import java.util.function.LongSupplier;

/**
 * Counters and gauges of one exporter. Every label comes from a fixed vocabulary (destination {@code syslog}/{@code hec},
 * stream, failure reason); no label or value ever carries a host, a user, a field value or a server answer (AGENTS.md
 * 4.14). The reader's and the sender's failure states are kept apart (PR 23 review D-4): a delivered batch never hides a
 * failing database read, and the other way round. {@link #prometheus()} renders them for the control plane's metrics
 * listener (PORTS_AND_RESOURCES 9400, not yet served); Health shows the same numbers.
 */
public final class SiemMetrics {

    private final String destination;
    private final int queueCapacity;
    private final Map<SiemStream, LongAdder> exported = new EnumMap<>(SiemStream.class);
    private final Map<Reason, LongAdder> failures = new EnumMap<>(Reason.class);
    private final LongAdder deferredReads = new LongAdder();
    private final LongAdder batches = new LongAdder();
    private final AtomicLong backlog = new AtomicLong(-1);
    private final AtomicLong held = new AtomicLong();
    private volatile boolean stalled;
    private final AtomicLong skippedAtStart = new AtomicLong();
    private final AtomicReference<Instant> lastDelivery = new AtomicReference<>();
    private final AtomicReference<Reason> readFailure = new AtomicReference<>();
    private final AtomicReference<Reason> sendFailure = new AtomicReference<>();
    private volatile IntSupplier queueDepth = () -> 0;
    private volatile LongSupplier possiblyLost = () -> 0;

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

    void possiblyLost(LongSupplier lost) {
        this.possiblyLost = lost;
    }

    void delivered(SiemStream stream, long count) {
        exported.get(stream).add(count);
    }

    /** A batch delivered and its watermark saved: the sender's failure state clears. */
    void sendSucceeded(Instant at) {
        batches.increment();
        lastDelivery.set(at);
        sendFailure.set(null);
    }

    void sendFailed(Reason reason) {
        failures.get(reason).increment();
        sendFailure.set(reason);
    }

    void readSucceeded() {
        readFailure.set(null);
    }

    void readFailed(Reason reason) {
        failures.get(reason).increment();
        readFailure.set(reason);
    }

    void deferredRead() {
        deferredReads.increment();
    }

    /** @param rows all committed rows beyond the watermark; {@code heldRows} of them behind an open transaction */
    void backlog(long rows, long heldRows) {
        backlog.set(rows);
        held.set(heldRows);
    }

    void stalled(boolean value) {
        stalled = value;
    }

    void skippedAtStart(long rows) {
        skippedAtStart.set(rows);
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

    /** Committed rows beyond the watermark at the last count; -1 before the first count. */
    public long backlog() {
        return backlog.get();
    }

    /** Committed rows beyond the watermark that a still-open transaction holds behind the visibility barrier. */
    public long heldBehindOpenTransaction() {
        return held.get();
    }

    /** True when a backlog has not moved the watermark for the configured stall time (D-11). */
    public boolean stalled() {
        return stalled;
    }

    /** Verdict events a {@code latest} start skipped (also a ledger row). */
    public long skippedAtStart() {
        return skippedAtStart.get();
    }

    /** Syslog batches flushed on a connection the receiver then closed (Q-SIEM-2). */
    public long possiblyLostBatches() {
        return possiblyLost.getAsLong();
    }

    public Instant lastDelivery() {
        return lastDelivery.get();
    }

    /** The failure class of the reader's latest attempt, or null when it succeeded. */
    public Reason readFailure() {
        return readFailure.get();
    }

    /** The failure class of the sender's latest attempt, or null when it succeeded. */
    public Reason sendFailure() {
        return sendFailure.get();
    }

    /** Prometheus text exposition, labels from the fixed vocabularies only. */
    public String prometheus() {
        StringBuilder s = new StringBuilder();
        String d = "destination=\"" + destination + "\"";
        s.append("# TYPE rwsafe_siem_events_exported_total counter\n");
        for (Map.Entry<SiemStream, LongAdder> e : exported.entrySet()) {
            s.append("rwsafe_siem_events_exported_total{").append(d).append(",stream=\"").append(lower(e.getKey()))
                .append("\"} ").append(e.getValue().sum()).append('\n');
        }
        s.append("# TYPE rwsafe_siem_delivery_failures_total counter\n");
        for (Map.Entry<Reason, LongAdder> e : failures.entrySet()) {
            s.append("rwsafe_siem_delivery_failures_total{").append(d).append(",reason=\"").append(lower(e.getKey()))
                .append("\"} ").append(e.getValue().sum()).append('\n');
        }
        gauge(s, "rwsafe_siem_reads_deferred_total", "counter", d, deferredReads.sum());
        gauge(s, "rwsafe_siem_batches_possibly_lost_total", "counter", d, possiblyLostBatches());
        gauge(s, "rwsafe_siem_events_skipped_at_start_total", "counter", d, skippedAtStart());
        gauge(s, "rwsafe_siem_backlog_rows", "gauge", d, Math.max(0, backlog()));
        gauge(s, "rwsafe_siem_backlog_held_rows", "gauge", d, heldBehindOpenTransaction());
        gauge(s, "rwsafe_siem_stalled", "gauge", d, stalled ? 1 : 0);
        gauge(s, "rwsafe_siem_queue_depth", "gauge", d, queueDepth());
        gauge(s, "rwsafe_siem_queue_capacity", "gauge", d, queueCapacity);
        s.append("# TYPE rwsafe_siem_failing gauge\n");
        s.append("rwsafe_siem_failing{").append(d).append(",thread=\"reader\"} ").append(readFailure() == null ? 0 : 1)
            .append('\n');
        s.append("rwsafe_siem_failing{").append(d).append(",thread=\"sender\"} ").append(sendFailure() == null ? 0 : 1)
            .append('\n');
        return s.toString();
    }

    private static void gauge(StringBuilder s, String name, String type, String labels, long value) {
        s.append("# TYPE ").append(name).append(' ').append(type).append('\n');
        s.append(name).append('{').append(labels).append("} ").append(value).append('\n');
    }

    private static String lower(Enum<?> e) {
        return e.name().toLowerCase(Locale.ROOT);
    }
}
