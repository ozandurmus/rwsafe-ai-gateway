package io.rwsafe.control.siem;

import io.rwsafe.control.siem.SiemDeliveryException.Reason;
import io.rwsafe.control.siem.SiemField.SiemStream;
import io.rwsafe.persistence.AuditContext;
import io.rwsafe.persistence.SiemExportStore;
import io.rwsafe.persistence.SiemExportStore.AuditPosition;
import io.rwsafe.persistence.SiemExportStore.ExportVerdict;
import io.rwsafe.persistence.SiemExportStore.LedgerRow;
import io.rwsafe.persistence.SiemExportStore.Start;
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
 * Exports verdict events and audit-ledger rows from PostgreSQL to one SIEM destination, at least once, in commit-safe
 * order per stream ({@link SiemExportStore}), on two threads of its own:
 *
 * <ul>
 *   <li>the <b>reader</b> reads visible rows after its read position, one page of ledger rows and one page of verdict
 *       events per round (fair: each stream has a page of room whenever the reader reads), maps them through
 *       {@link SiemRecords} and offers them to a bounded queue;</li>
 *   <li>the <b>sender</b> takes up to a batch from the queue, delivers it, and only then moves the destination's persisted
 *       watermark ({@code siem_watermark}) past it.</li>
 * </ul>
 *
 * <p><b>Overflow policy</b> (explicit and tested): the queue holds at most {@code queueCapacity} records. The reader reads
 * only when the queue has room for a page of each stream; otherwise it does not read, counts a deferred read and waits.
 * Nothing is ever dropped: an event that is not in the queue is still in PostgreSQL behind the watermark, and the reader
 * reaches it when the sender has drained. Ingestion never calls the exporter, so a slow or absent SIEM cannot block or
 * slow it (AGENTS.md section 5).
 *
 * <p><b>Back-off</b>: a failed delivery is retried with the same batch after {@code backoffInitial}, doubling up to
 * {@code backoffMax}, and reset by a success; a database error in the reader backs off the same way. The reader's and
 * the sender's failure states are separate (Health, metrics).
 *
 * <p><b>Start</b>: a destination without a watermark creates one under the audit ledger (actor
 * {@value #ACTOR}); ledger rows always export from the first one, and a {@code latest} start skips only verdict events,
 * counts them and records the count with the watermark (PO decision Q-SIEM-1).
 *
 * <p><b>Restart</b>: queued records are discarded at stop; the next start reads from the persisted watermark, so a batch
 * that was delivered but whose watermark was not yet saved is sent again (at least once; the event id in every line
 * lets the SIEM de-duplicate).
 */
public final class SiemExporter {

    static final String ACTOR = "system:siem-export";
    private static final Logger LOG = LoggerFactory.getLogger(SiemExporter.class);

    /**
     * @param pollInterval       how long the reader waits when nothing new was found or the queue was full
     * @param queueCapacity      the bounded queue's size in records, at least two pages
     * @param pageSize           rows per read and stream
     * @param batchSize          records per delivery
     * @param verdictsFromLatest a destination without a watermark skips the stored verdict events (never ledger rows)
     * @param backlogInterval    how often the reader counts the backlog behind the watermark while it drains
     * @param stallAfter         a backlog that makes no progress for this long marks the export stalled (DEGRADED)
     */
    public record Settings(Duration pollInterval, int queueCapacity, int pageSize, int batchSize,
                           Duration backoffInitial, Duration backoffMax, boolean verdictsFromLatest,
                           Duration backlogInterval, Duration stallAfter) {

        public Settings {
            if (pageSize < 1 || queueCapacity < 2 * pageSize || batchSize < 1
                || pollInterval.isNegative() || pollInterval.isZero() || backoffInitial.isNegative()
                || backoffInitial.isZero() || backoffMax.compareTo(backoffInitial) < 0 || backlogInterval.isNegative()
                || stallAfter.isNegative()) {
                throw new IllegalArgumentException("SIEM exporter settings out of range (the queue holds two pages)");
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
    private AuditPosition readAudit;
    private long backlogCountedAt;

    // Set by the reader before its first offer, then moved by the sender only after the watermark is saved (D-10; the
    // queue orders the hand-over).
    private volatile Watermark delivered;
    /** When the persisted watermark last moved, or the backlog was last seen empty (stall detection, D-11). */
    private volatile long progressAt = System.nanoTime();

    /** What one read round found. */
    enum Round { MORE, CAUGHT_UP, DEFERRED }

    public SiemExporter(SiemSink sink, SiemExportStore store, SiemRecords records, Settings settings,
                        SiemMetrics metrics) {
        this.sink = sink;
        this.store = store;
        this.records = records;
        this.settings = settings;
        this.metrics = metrics;
        this.queue = new ArrayBlockingQueue<>(settings.queueCapacity());
        metrics.queueDepth(queue::size);
        metrics.possiblyLost(sink::possiblyLostBatches);
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
        while (running && !Thread.currentThread().isInterrupted()) {
            try {
                if (!initialised) {
                    initialise();
                }
                Round round = readOnce();
                countBacklog(round == Round.CAUGHT_UP);
                metrics.readSucceeded();
                backoff = settings.backoffInitial();
                if (round != Round.MORE) {
                    pause(settings.pollInterval());
                }
            } catch (RuntimeException e) {
                if (!running || Thread.currentThread().isInterrupted()) {
                    return;
                }
                metrics.readFailed(Reason.DATABASE);
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
            boolean latest = settings.verdictsFromLatest();
            Start start = latest ? store.latestVerdicts() : new Start(Watermark.START, 0);
            boolean created = store.createWatermark(destination(), start, latest ? "latest" : "earliest",
                new AuditContext(ACTOR, "siem_export.start", latest ? "START_FROM_LATEST" : "START_FROM_EARLIEST", null));
            if (created && start.skippedVerdicts() > 0) {
                LOG.warn("SIEM export to {} starts at the latest verdict event: {} stored verdict events are not "
                    + "exported (ledger rows are)", destination(), start.skippedVerdicts());
            }
            w = store.watermark(destination()).orElseThrow();
        }
        metrics.skippedAtStart(store.skippedAtStart(destination()));
        readVerdict = w.verdict();
        readAudit = w.audit();
        delivered = w;
        initialised = true;
    }

    /**
     * One read of each stream, a page each: {@code MORE} when a page came back full (read again at once),
     * {@code CAUGHT_UP} when both came back short, {@code DEFERRED} when the queue had no room (nothing read).
     */
    Round readOnce() {
        if (queue.remainingCapacity() < 2 * settings.pageSize()) {
            metrics.deferredRead();
            return Round.DEFERRED;
        }
        List<LedgerRow> ledger = store.ledgerAfter(readAudit, settings.pageSize());
        for (LedgerRow row : ledger) {
            enqueue(records.ledger(row));
            readAudit = row.position();
        }
        List<ExportVerdict> verdicts = store.verdictsAfter(readVerdict, settings.pageSize());
        for (ExportVerdict row : verdicts) {
            enqueue(records.verdict(row));
            readVerdict = row.position();
        }
        return ledger.size() == settings.pageSize() || verdicts.size() == settings.pageSize() ? Round.MORE
            : Round.CAUGHT_UP;
    }

    /**
     * The backlog is the committed rows beyond the persisted watermark, split by the same visibility barrier the reads use
     * (D-11): exportable now, and held behind a transaction that is still open. It is an index range over (tx_id, id),
     * cheap when the export has caught up, so it is counted on every caught-up round, and at most once per
     * {@code backlogInterval} while a backlog drains or the queue is full (never a count per poll during an outage).
     *
     * <p>Stall: a backlog that has not moved the watermark for {@code stallAfter} marks the export stalled (Health
     * DEGRADED, {@code rwsafe_siem_stalled}), whatever the cause, typically a transaction held open behind the barrier.
     */
    private void countBacklog(boolean caughtUp) {
        long now = System.nanoTime();
        if (caughtUp || metrics.backlog() < 0 || now - backlogCountedAt >= settings.backlogInterval().toNanos()) {
            SiemExportStore.Backlog b = store.backlog(delivered);
            metrics.backlog(b.visible() + b.held(), b.held());
            backlogCountedAt = now;
            if (b.visible() + b.held() == 0) {
                progressAt = now;
            }
        }
        metrics.stalled(metrics.backlog() > 0 && now - progressAt > settings.stallAfter().toNanos());
    }

    private void enqueue(SiemRecord r) {
        // The reader is the only producer and checked the room first, so the offer cannot fail.
        if (!queue.offer(r)) {
            throw new IllegalStateException("SIEM queue overflow despite the room check");
        }
    }

    // ---- sender ----

    /**
     * Takes a batch, delivers it, then saves the watermark past it. The batch is kept until both have succeeded (D-10):
     * a failed delivery is retried with the same batch; a failed watermark save is retried on its own, with the same
     * back-off and without sending the batch again, and the in-memory watermark moves only after the save.
     */
    private void sendLoop() {
        List<SiemRecord> batch = new ArrayList<>(settings.batchSize());
        boolean sent = false;
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
                if (!sent) {
                    try {
                        sink.deliver(batch);
                    } catch (SiemDeliveryException e) {
                        if (!running || Thread.currentThread().isInterrupted()) {
                            return; // a stop, not a failure (D-9)
                        }
                        metrics.sendFailed(e.reason());
                        LOG.warn("SIEM export to {}: delivery failed ({}); the batch is retried after back-off",
                            destination(), e.reason());
                        sleep(backoff);
                        backoff = doubled(backoff);
                        continue;
                    }
                    sent = true;
                    countDelivered(batch);
                }
                if (!saveWatermark(batch)) {
                    if (!running) {
                        return;
                    }
                    sleep(backoff);
                    backoff = doubled(backoff);
                    continue;
                }
                sent = false;
                backoff = settings.backoffInitial();
                batch.clear();
                synchronized (wake) {
                    wake.notifyAll();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    private void countDelivered(List<SiemRecord> batch) {
        long verdicts = batch.stream().filter(r -> r.stream() == SiemStream.VERDICT).count();
        metrics.delivered(SiemStream.VERDICT, verdicts);
        metrics.delivered(SiemStream.AUDIT, batch.size() - verdicts);
    }

    /** Saves the watermark past a delivered batch; true when saved (then, and only then, the cursor moves). */
    private boolean saveWatermark(List<SiemRecord> batch) {
        Watermark w = delivered;
        VerdictPosition verdict = w.verdict();
        AuditPosition audit = w.audit();
        for (SiemRecord r : batch) {
            if (r.stream() == SiemStream.VERDICT) {
                verdict = r.verdictPosition();
            } else {
                audit = r.auditPosition();
            }
        }
        Watermark next = new Watermark(verdict, audit);
        try {
            store.saveWatermark(destination(), next);
        } catch (RuntimeException e) {
            // Delivered but not recorded: retried on its own; a restart before it succeeds sends the batch again.
            metrics.sendFailed(Reason.DATABASE);
            LOG.warn("SIEM export to {}: saving the watermark failed ({}); retrying after back-off", destination(),
                e.getClass().getSimpleName());
            return false;
        }
        delivered = next;
        progressAt = System.nanoTime();
        metrics.sendSucceeded(Instant.now());
        return true;
    }

    /** The acknowledged position (tests and the health screen). */
    public Watermark delivered() {
        return delivered;
    }

    private Duration doubled(Duration d) {
        Duration next = d.multipliedBy(2);
        return next.compareTo(settings.backoffMax()) > 0 ? settings.backoffMax() : next;
    }

    /** Waits on the sender's wake-up; an interrupt (a stop) keeps the thread's interrupt flag. */
    private void pause(Duration d) {
        synchronized (wake) {
            try {
                wake.wait(Math.max(1, d.toMillis()));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private static void sleep(Duration d) throws InterruptedException {
        Thread.sleep(Math.max(1, d.toMillis()));
    }
}
