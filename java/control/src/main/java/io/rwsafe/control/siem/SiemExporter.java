package io.rwsafe.control.siem;

import io.rwsafe.control.siem.SiemDeliveryException.Reason;
import io.rwsafe.control.siem.SiemField.SiemStream;
import io.rwsafe.persistence.SiemExportStore;
import io.rwsafe.persistence.SiemExportStore.ExportVerdict;
import io.rwsafe.persistence.SiemExportStore.LedgerRow;
import io.rwsafe.persistence.SiemExportStore.VerdictPosition;
import io.rwsafe.persistence.SiemExportStore.Watermark;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Exports verdict events and audit-ledger rows from PostgreSQL to one SIEM destination, at least once, in order per
 * stream, on two threads of its own:
 *
 * <ul>
 *   <li>the <b>reader</b> reads settled rows after its read position (ledger rows first, then verdict events, a page
 *       each), maps them through {@link SiemRecords} and offers them to a bounded queue;</li>
 *   <li>the <b>sender</b> takes up to a batch from the queue, delivers it, and only then moves the destination's persisted
 *       watermark ({@code siem_watermark}) past it.</li>
 * </ul>
 *
 * <p><b>Overflow policy</b> (explicit and tested): the queue holds at most {@code queueCapacity} records. The reader reads
 * only when the queue has room for a whole page; otherwise it does not read, counts a deferred read and waits. Nothing is
 * ever dropped: an event that is not in the queue is still in PostgreSQL behind the watermark, and the reader reaches it
 * when the sender has drained. Ingestion never calls the exporter, so a slow or absent SIEM cannot block or slow it
 * (AGENTS.md section 5: the inline path never waits on the control plane, and the control plane's ingestion never waits on
 * the SIEM).
 *
 * <p><b>Back-off</b>: a failed delivery is retried with the same batch after {@code backoffInitial}, doubling up to
 * {@code backoffMax}, and reset by a success; a database error in the reader backs off the same way.
 *
 * <p><b>Restart</b>: queued records are discarded at stop; the next start reads from the persisted watermark, so a batch
 * that was delivered but whose watermark was not yet saved is sent again (at least once; the event id in every line
 * lets the SIEM de-duplicate).
 */
public final class SiemExporter {

    private static final Logger LOG = LoggerFactory.getLogger(SiemExporter.class);

    /**
     * @param pollInterval   how long the reader waits when nothing new was found or the queue was full
     * @param settle         rows younger than this (database clock) are not read yet (SiemExportStore: commit order)
     * @param queueCapacity  the bounded queue's size in records
     * @param pageSize       rows per read and stream; at most {@code queueCapacity}
     * @param batchSize      records per delivery
     * @param startAtLatest  a destination without a watermark starts at the newest settled row instead of the oldest
     */
    public record Settings(Duration pollInterval, Duration settle, int queueCapacity, int pageSize, int batchSize,
                           Duration backoffInitial, Duration backoffMax, boolean startAtLatest) {

        public Settings {
            if (queueCapacity < 1 || pageSize < 1 || pageSize > queueCapacity || batchSize < 1
                || pollInterval.isNegative() || pollInterval.isZero() || settle.isNegative()
                || backoffInitial.isNegative() || backoffInitial.isZero() || backoffMax.compareTo(backoffInitial) < 0) {
                throw new IllegalArgumentException("SIEM exporter settings out of range");
            }
        }
    }

    private final SiemSink sink;
    private final SiemExportStore store;
    private final SiemRecords records;
    private final Settings settings;
    private final SiemMetrics metrics;
    private final ArrayBlockingQueue<SiemRecord> queue;
    private final Object wake = new Object();
    private volatile boolean running;
    private Thread reader;
    private Thread sender;

    // Reader thread only.
    private boolean initialised;
    private VerdictPosition readVerdict;
    private long readAudit;

    // Set by the reader before its first offer, then owned by the sender (the queue orders the hand-over).
    private volatile Watermark delivered;

    public SiemExporter(SiemSink sink, SiemExportStore store, SiemRecords records, Settings settings,
                        SiemMetrics metrics) {
        this.sink = sink;
        this.store = store;
        this.records = records;
        this.settings = settings;
        this.metrics = metrics;
        this.queue = new ArrayBlockingQueue<>(settings.queueCapacity());
        metrics.queueDepth(queue::size);
    }

    public String destination() {
        return sink.destination();
    }

    public SiemMetrics metrics() {
        return metrics;
    }

    public boolean running() {
        return running;
    }

    public synchronized void start() {
        if (running) {
            return;
        }
        running = true;
        reader = new Thread(this::readLoop, "rwsafe-siem-" + destination() + "-reader");
        sender = new Thread(this::sendLoop, "rwsafe-siem-" + destination() + "-sender");
        reader.setDaemon(true);
        sender.setDaemon(true);
        reader.start();
        sender.start();
    }

    /** Stops both threads, discards the queue (the watermark holds the position) and closes the connection. */
    public synchronized void stop() {
        if (!running) {
            return;
        }
        running = false;
        reader.interrupt();
        sender.interrupt();
        try {
            reader.join(5_000);
            sender.join(5_000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        queue.clear();
        sink.close();
    }

    // ---- reader ----

    private void readLoop() {
        Duration backoff = settings.backoffInitial();
        while (running) {
            try {
                if (!initialised) {
                    initialise();
                }
                boolean more = readOnce();
                backoff = settings.backoffInitial();
                if (!more) {
                    pause(settings.pollInterval());
                }
            } catch (RuntimeException e) {
                if (!running) {
                    return;
                }
                metrics.failure(Reason.DATABASE);
                LOG.warn("SIEM export to {}: reading the database failed ({}); retrying after back-off", destination(),
                    e.getClass().getSimpleName());
                pause(backoff);
                backoff = doubled(backoff);
            }
        }
    }

    private void initialise() {
        Watermark w = store.watermark(destination()).orElse(null);
        if (w == null) {
            w = settings.startAtLatest() ? store.latest(settings.settle()) : Watermark.START;
            store.saveWatermark(destination(), w);
        }
        readVerdict = w.verdict();
        readAudit = w.auditId();
        delivered = w;
        initialised = true;
    }

    /** One read of each stream within the queue's free room; true when a page came back full (read again at once). */
    boolean readOnce() {
        int room = queue.remainingCapacity();
        if (room < settings.pageSize()) {
            metrics.deferredRead();
            return false;
        }
        int auditLimit = Math.min(settings.pageSize(), room);
        List<LedgerRow> ledger = store.ledgerAfter(readAudit, settings.settle(), auditLimit);
        for (LedgerRow row : ledger) {
            enqueue(records.ledger(row));
            readAudit = row.auditId();
        }
        int verdictLimit = Math.min(settings.pageSize(), room - ledger.size());
        List<ExportVerdict> verdicts = verdictLimit <= 0 ? List.of()
            : store.verdictsAfter(readVerdict, settings.settle(), verdictLimit);
        for (ExportVerdict row : verdicts) {
            enqueue(records.verdict(row));
            readVerdict = row.position();
        }
        return ledger.size() == auditLimit || (verdictLimit > 0 && verdicts.size() == verdictLimit);
    }

    private void enqueue(SiemRecord r) {
        // The reader is the only producer and checked the room first, so the offer cannot fail.
        if (!queue.offer(r)) {
            throw new IllegalStateException("SIEM queue overflow despite the room check");
        }
    }

    // ---- sender ----

    private void sendLoop() {
        List<SiemRecord> batch = new ArrayList<>(settings.batchSize());
        Duration backoff = settings.backoffInitial();
        while (running) {
            try {
                if (batch.isEmpty()) {
                    SiemRecord first = queue.poll(settings.pollInterval().toMillis(), TimeUnit.MILLISECONDS);
                    if (first == null) {
                        continue;
                    }
                    batch.add(first);
                    queue.drainTo(batch, settings.batchSize() - 1);
                }
                try {
                    sink.deliver(batch);
                } catch (SiemDeliveryException e) {
                    metrics.failure(e.reason());
                    LOG.warn("SIEM export to {}: delivery failed ({}); the batch is retried after back-off",
                        destination(), e.reason());
                    sleep(backoff);
                    backoff = doubled(backoff);
                    continue;
                }
                backoff = settings.backoffInitial();
                acknowledge(batch);
                batch.clear();
                synchronized (wake) {
                    wake.notifyAll();
                }
            } catch (InterruptedException e) {
                return;
            }
        }
    }

    private void acknowledge(List<SiemRecord> batch) {
        Watermark w = delivered;
        VerdictPosition verdict = w.verdict();
        long audit = w.auditId();
        long verdicts = 0;
        for (SiemRecord r : batch) {
            if (r.stream() == SiemStream.VERDICT) {
                verdict = r.verdictPosition();
                verdicts++;
            } else {
                audit = r.auditId();
            }
        }
        metrics.delivered(SiemStream.VERDICT, verdicts);
        metrics.delivered(SiemStream.AUDIT, batch.size() - verdicts);
        metrics.batchDelivered(Instant.now());
        delivered = new Watermark(verdict, audit);
        try {
            store.saveWatermark(destination(), delivered);
        } catch (RuntimeException e) {
            // Delivered but not recorded: the next save carries it, or a restart sends it again (at least once).
            metrics.failure(Reason.DATABASE);
            LOG.warn("SIEM export to {}: saving the watermark failed ({})", destination(), e.getClass().getSimpleName());
        }
    }

    /** The acknowledged position (tests and the health screen). */
    public Watermark delivered() {
        return delivered;
    }

    private Duration doubled(Duration d) {
        Duration next = d.multipliedBy(2);
        return next.compareTo(settings.backoffMax()) > 0 ? settings.backoffMax() : next;
    }

    private void pause(Duration d) {
        synchronized (wake) {
            try {
                wake.wait(Math.max(1, d.toMillis()));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                running = false;
            }
        }
    }

    private static void sleep(Duration d) throws InterruptedException {
        Thread.sleep(Math.max(1, d.toMillis()));
    }
}
