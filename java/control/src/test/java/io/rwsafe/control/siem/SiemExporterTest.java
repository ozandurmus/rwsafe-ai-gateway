package io.rwsafe.control.siem;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.control.siem.SiemDeliveryException.Reason;
import io.rwsafe.control.siem.SiemField.SiemStream;
import io.rwsafe.persistence.AuditContext;
import io.rwsafe.persistence.LocalAccount;
import io.rwsafe.persistence.SiemExportStore.VerdictPosition;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** The exporter against the real store: bounded queue and its overflow policy, back-off, ordering, restart, start. */
class SiemExporterTest {

    private SiemFixture fx;
    private final List<SiemExporter> started = new ArrayList<>();

    /** Records every delivered record; can hold deliveries at a gate and fail a number of attempts first. */
    static final class RecordingSink implements SiemSink {
        final List<SiemRecord> delivered = new ArrayList<>();
        final List<Long> attempts = new ArrayList<>();
        final AtomicInteger failures = new AtomicInteger();
        volatile CountDownLatch gate = new CountDownLatch(0);

        @Override
        public String destination() {
            return "hec";
        }

        @Override
        public void deliver(List<SiemRecord> batch) throws SiemDeliveryException {
            try {
                if (!gate.await(30, TimeUnit.SECONDS)) {
                    throw new SiemDeliveryException(Reason.TIMEOUT, "gate");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new SiemDeliveryException(Reason.IO, "interrupted");
            }
            synchronized (this) {
                attempts.add(System.nanoTime());
            }
            if (failures.getAndUpdate(f -> f > 0 ? f - 1 : 0) > 0) {
                throw new SiemDeliveryException(Reason.UNAVAILABLE, "scripted");
            }
            synchronized (this) {
                delivered.addAll(batch);
            }
        }

        synchronized List<SiemRecord> of(SiemStream stream) {
            return delivered.stream().filter(r -> r.stream() == stream).toList();
        }

        int count() {
            return of(SiemStream.VERDICT).size();
        }

        List<String> ids() {
            return of(SiemStream.VERDICT).stream().map(r -> r.value(SiemField.EVENT_ID)).toList();
        }

        @Override
        public void close() {
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        fx = new SiemFixture();
    }

    @AfterEach
    void tearDown() {
        started.forEach(SiemExporter::stop);
    }

    private SiemExporter exporter(RecordingSink sink, SiemExporter.Settings settings) {
        SiemExporter e = new SiemExporter(sink, fx.db.siemExport(), fx.records, settings,
            new SiemMetrics(sink.destination(), settings.queueCapacity()));
        started.add(e);
        return e;
    }

    @Test
    void aStalledDestinationDefersReadingDropsNothingAndNeverBlocksIngestion() throws Exception {
        RecordingSink sink = new RecordingSink();
        sink.gate = new CountDownLatch(1);
        List<String> ids = new ArrayList<>(fx.ingest(40));
        SiemExporter exporter = exporter(sink, SiemFixture.settings(10, 5, 5, false));
        exporter.start();

        SiemFixture.await("a deferred read", 5_000, () -> exporter.metrics().deferredReads() > 0);
        assertTrue(exporter.metrics().queueDepth() <= 10, "the queue never exceeds its capacity");
        SiemFixture.await("the backlog is counted", 5_000, () -> exporter.metrics().backlog() >= 40);

        long t0 = System.nanoTime();
        ids.addAll(fx.ingest(40));
        long ingestMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0);
        assertTrue(ingestMillis < 5_000, "ingestion is independent of the stalled destination: " + ingestMillis + " ms");
        assertTrue(exporter.metrics().queueDepth() <= 10);

        sink.gate.countDown();
        SiemFixture.await("all events delivered", 15_000, () -> sink.count() == 80);
        assertEquals(new HashSet<>(ids), new HashSet<>(sink.ids()), "nothing was dropped");
        assertEquals(80, new HashSet<>(sink.ids()).size(), "nothing was sent twice");
        assertEquals(new HashSet<>(ids.subList(0, 40)), new HashSet<>(sink.ids().subList(0, 40)),
            "the events ingested first are delivered first");
        List<SiemRecord> verdicts = sink.of(SiemStream.VERDICT);
        for (int i = 1; i < verdicts.size(); i++) {
            VerdictPosition prev = verdicts.get(i - 1).verdictPosition();
            VerdictPosition next = verdicts.get(i).verdictPosition();
            // PostgreSQL orders uuid by unsigned bytes, which is the order of the canonical lower-case text.
            assertTrue(prev.txId() < next.txId() || (prev.txId() == next.txId()
                && prev.eventId().toString().compareTo(next.eventId().toString()) < 0), "delivered in watermark order");
        }
        SiemFixture.await("watermark at the last event", 5_000, () -> fx.db.siemExport().watermark("hec")
            .map(w -> verdicts.get(79).verdictPosition().equals(w.verdict())).orElse(false));
        assertEquals(80, exporter.metrics().exported(SiemStream.VERDICT));
        SiemFixture.await("the backlog drains", 5_000, () -> exporter.metrics().backlog() == 0);
    }

    @Test
    void failedDeliveriesBackOffExponentiallyAndRetryTheSameBatch() throws Exception {
        RecordingSink sink = new RecordingSink();
        sink.failures.set(4);
        List<String> ids = fx.ingest(3);
        SiemExporter exporter = exporter(sink, SiemFixture.settings(100, 50, 50, false));
        exporter.start();
        SiemFixture.await("a sender failure is visible", 5_000,
            () -> exporter.metrics().sendFailure() == Reason.UNAVAILABLE);
        assertNull(exporter.metrics().readFailure(), "the reader's state is its own");
        SiemFixture.await("delivered after the failures", 10_000, () -> sink.count() == 3);

        assertEquals(sorted(ids), sink.ids(), "delivered once each, in order");
        assertEquals(4, exporter.metrics().failures(Reason.UNAVAILABLE));
        // The first batch fails four times and then succeeds; the sender may have taken the rest as a second batch.
        List<Long> t = sink.attempts;
        assertTrue(t.size() >= 5, t.size() + " attempts");
        long[] expected = {20, 40, 80, 160};
        for (int i = 0; i < expected.length; i++) {
            long gap = TimeUnit.NANOSECONDS.toMillis(t.get(i + 1) - t.get(i));
            assertTrue(gap >= expected[i], "attempt " + (i + 2) + " waited " + gap + " ms, expected " + expected[i]);
        }
        assertNull(exporter.metrics().sendFailure(), "a success clears the sender's failure state");
    }

    @Test
    void aRestartResumesFromThePersistedWatermark() throws Exception {
        RecordingSink first = new RecordingSink();
        fx.ingest(5);
        SiemExporter a = exporter(first, SiemFixture.settings(100, 50, 50, false));
        a.start();
        SiemFixture.await("first run delivered", 5_000, () -> first.count() == 5);
        SiemFixture.await("first run watermark", 5_000, () -> fx.db.siemExport().watermark("hec")
            .map(w -> w.verdict() != null && w.verdict().equals(first.of(SiemStream.VERDICT).get(4).verdictPosition()))
            .orElse(false));
        a.stop();

        List<String> later = fx.ingest(3);
        RecordingSink second = new RecordingSink();
        SiemExporter b = exporter(second, SiemFixture.settings(100, 50, 50, false));
        b.start();
        SiemFixture.await("second run delivered", 5_000, () -> second.count() == 3);
        Thread.sleep(200);
        assertEquals(sorted(later), second.ids(), "only the events after the watermark, each once");
        assertEquals(0, second.of(SiemStream.AUDIT).size(), "the start ledger row went out in the first run");
    }

    /** PO decision Q-SIEM-1: latest skips stored verdict events only, counts them and ledgers the start. */
    @Test
    void aLatestStartSkipsVerdictEventsOnlyAndRecordsTheSkip() throws Exception {
        fx.db.loginRecords().record("USR-0123456789", "ldap", false);
        fx.ingest(4);
        RecordingSink sink = new RecordingSink();
        SiemExporter e = exporter(sink, SiemFixture.settings(100, 50, 50, true));
        e.start();
        SiemFixture.await("initial watermark", 5_000, () -> fx.db.siemExport().watermark("hec").isPresent());
        List<String> later = fx.ingest(2);
        SiemFixture.await("new events delivered", 5_000, () -> sink.count() == 2);
        Thread.sleep(100);
        assertEquals(sorted(later), sink.ids());
        assertEquals(4, e.metrics().skippedAtStart());
        assertEquals(4, fx.db.siemExport().skippedAtStart("hec"));

        List<SiemRecord> audit = sink.of(SiemStream.AUDIT);
        assertEquals(2, audit.size(), "the earlier ledger row is exported, and the start itself");
        assertEquals("login_record", audit.get(0).value(SiemField.AUDITED_TABLE));
        SiemRecord startRow = audit.get(1);
        assertEquals("siem_watermark", startRow.value(SiemField.AUDITED_TABLE));
        assertEquals("hec", startRow.value(SiemField.ROW_KEY));
        assertEquals("START_FROM_LATEST", startRow.value(SiemField.REASON));
        assertEquals(SiemExporter.ACTOR, startRow.value(SiemField.USER));
    }

    @Test
    void ledgerRowsAreExportedInCommitOrderWithAPseudonymousKey() throws Exception {
        fx.db.localAccounts().createIfAbsent(new LocalAccount("synthetic-glass", "$2a$12$" + "y".repeat(53),
            List.of("security_admin"), true), new AuditContext("system:bootstrap", "local_account.create", "FIRST_START",
            null));
        fx.db.loginRecords().record(fx.pseudonymiser.user("synthetic-glass"), "local", false);
        fx.ingest(1);
        RecordingSink sink = new RecordingSink();
        exporter(sink, SiemFixture.settings(100, 50, 50, false)).start();
        SiemFixture.await("three ledger rows and one event", 5_000,
            () -> sink.count() == 1 && sink.of(SiemStream.AUDIT).size() == 3);

        List<SiemRecord> audit = sink.of(SiemStream.AUDIT);
        assertTrue(audit.get(0).auditPosition().txId() < audit.get(1).auditPosition().txId());
        assertEquals(fx.pseudonymiser.user("synthetic-glass"), audit.get(0).value(SiemField.ROW_KEY));
        assertEquals("system:bootstrap", audit.get(0).value(SiemField.USER));
        assertEquals("START_FROM_EARLIEST", audit.get(2).value(SiemField.REASON));
        SiemFixture.await("audit watermark", 5_000, () -> fx.db.siemExport().watermark("hec")
            .map(w -> audit.get(2).auditPosition().equals(w.audit())).orElse(false));
    }

    @Test
    void theQueueHoldsAPageOfEachStream() {
        assertThrows(IllegalArgumentException.class, () -> new SiemExporter.Settings(Duration.ofMillis(20), 9, 5, 5,
            Duration.ofMillis(20), Duration.ofMillis(160), false, Duration.ZERO), "fair paging needs two pages of room");
    }

    /** One ingestion batch is one transaction and is exported in event-id order. */
    private static List<String> sorted(List<String> ids) {
        return ids.stream().sorted().toList();
    }
}
