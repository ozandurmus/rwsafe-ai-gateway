package io.rwsafe.dataplane.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import io.rwsafe.dataplane.boot.IcapServer;
import io.rwsafe.dataplane.controlplane.EventShipper;
import io.rwsafe.dataplane.events.BoundedEventQueue;
import io.rwsafe.dataplane.events.VerdictEvent;
import io.rwsafe.detect.DetectorSet;
import io.rwsafe.platform.verdict.DataClass;
import io.rwsafe.platform.verdict.Verdict;
import io.rwsafe.policy.Action;
import io.rwsafe.policy.PolicySnapshot;
import io.rwsafe.policy.Snapshots;
import java.io.File;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** One test per finding of the PR 14 second review (docs/reviews/PR14_2026_10_30_ARGON_DATAPLANE_SLICE2.md). */
class Pr14ReviewTest {

    @TempDir
    Path tmp;

    private static final EngineConfig BASE = EngineConfig.defaults().withBodyLimits(64 * 1024, 256L * 1024 * 1024)
        .withTimeouts(400, 3_000);

    /** A clock the test moves. */
    private static final class MovableClock extends Clock {
        final AtomicReference<Instant> now;

        MovableClock(Instant start) {
            now = new AtomicReference<>(start);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now.get();
        }
    }

    /** D-03: a snapshot that expires while active stops being served. */
    @Test
    void expiredActiveSnapshotIsNotServed() throws Exception {
        Instant start = Instant.parse("2026-10-30T18:00:00Z");
        MovableClock clock = new MovableClock(start);
        PolicySnapshot signed = new PolicySnapshot(7, "registry-synthetic", Map.of(DataClass.SECRET, Action.BLOCK,
            DataClass.TCKN, Action.REDACT, DataClass.TR_IBAN, Action.REDACT, DataClass.PAYMENT_CARD, Action.REDACT),
            true, Snapshots.builtinDevelopment().platforms(), start.minusSeconds(3600));
        IcapEngine engine = new IcapEngine(signed, DetectorSet.standard(), e -> { }, BASE, new Admission(BASE), clock);
        try (IcapServer server = new IcapServer(engine, 0)) {
            int port = server.start("127.0.0.1", 0);
            try (IcapTestClient c = new IcapTestClient(port)) {
                c.write(Frames.options("/reqmod-ai"));
                assertEquals(200, c.read().status());
            }
            clock.now.set(start.plus(Duration.ofHours(24)));
            try (IcapTestClient c = new IcapTestClient(port)) {
                c.write(Frames.options("/reqmod-ai"));
                assertEquals(503, c.read().status());
            }
            try (IcapTestClient c = new IcapTestClient(port)) {
                c.write(Frames.reqmod(Frames.fixture("openai/web/chat.http", "synthetic hi"), -1, true));
                assertEquals(503, c.read().status());
            }
        }
    }

    /** D-05: concurrent enter and exit for one identity never orphan a counter or exceed the cap. */
    @Test
    void identityCountersStayConsistentUnderConcurrency() throws Exception {
        Admission a = new Admission(BASE.withAdmission(10_000, 3, 3, List.of()));
        AtomicInteger concurrent = new AtomicInteger();
        AtomicInteger maxSeen = new AtomicInteger();
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch done = new CountDownLatch(8);
        for (int t = 0; t < 8; t++) {
            pool.execute(() -> {
                for (int i = 0; i < 5_000; i++) {
                    Admission.Ticket[] out = new Admission.Ticket[1];
                    if (a.tryEnter("U1lOVEhFVElD", "192.0.2.10", out) == null) {
                        int c = concurrent.incrementAndGet();
                        maxSeen.accumulateAndGet(c, Math::max);
                        concurrent.decrementAndGet();
                        a.exit(out[0]);
                    }
                }
                done.countDown();
            });
        }
        assertTrue(done.await(30, TimeUnit.SECONDS));
        pool.shutdown();
        assertTrue(maxSeen.get() <= 3, "never more than the cap at once");
        assertEquals(0, a.inflight());
        Admission.Ticket[] out = new Admission.Ticket[1];
        for (int i = 0; i < 3; i++) {
            assertEquals(null, a.tryEnter("U1lOVEhFVElD", "192.0.2.10", out), "no leaked slot after the storm");
        }
        assertEquals(Admission.Refusal.IDENTITY_LIMIT, a.tryEnter("U1lOVEhFVElD", "192.0.2.10", out));
    }

    /** D-06: a pipelined second transaction gets its own deadline. */
    @Test
    void pipelinedSlowBodyTimesOut() throws Exception {
        IcapEngine engine = new IcapEngine(Snapshots.builtinDevelopment(), DetectorSet.standard(), e -> { }, BASE);
        try (IcapServer server = new IcapServer(engine, 0)) {
            int port = server.start("127.0.0.1", 0);
            byte[] first = Frames.reqmod(Frames.fixture("openai/web/chat.http", "synthetic one"), -1, true);
            byte[] second = Frames.reqmod(Frames.fixture("claude/api/messages.http", "synthetic two"), -1, true);
            byte[] both = new byte[first.length + second.length - 15];
            System.arraycopy(first, 0, both, 0, first.length);
            System.arraycopy(second, 0, both, first.length, second.length - 15);
            try (IcapTestClient c = new IcapTestClient(port)) {
                c.write(both);
                assertEquals(204, c.read().status());
                assertTrue(c.read().httpHead().startsWith("HTTP/1.1 403"), "the second, stalled transaction times out");
                assertTrue(c.closedByServer());
            }
            assertEquals(0, engine.admission().inflight());
        }
    }

    /** D-07: an echoed answer during the drain also carries Connection: close. */
    @Test
    void echoDuringDrainCarriesConnectionClose() throws Exception {
        IcapEngine engine = new IcapEngine(Snapshots.builtinDevelopment(), DetectorSet.standard(), e -> { },
            BASE.withDrainServeMillis(5_000));
        try (IcapServer server = new IcapServer(engine, 0)) {
            int port = server.start("127.0.0.1", 0);
            engine.startDraining();
            try (IcapTestClient c = new IcapTestClient(port)) {
                c.write(Frames.reqmod(Frames.fixture("openai/web/chat.http", "synthetic hi"), -1, false));
                IcapTestClient.Response r = c.read();
                assertEquals(200, r.status());
                assertEquals("close", r.header("Connection"));
            }
        }
    }

    /** D-09: Secure ICAP refuses to start without its client CA. */
    @Test
    void secureListenerNeedsAllThreeFiles() throws Exception {
        IcapEngine engine = new IcapEngine(Snapshots.builtinDevelopment(), DetectorSet.standard(), e -> { }, BASE);
        try (IcapServer server = new IcapServer(engine, 0)) {
            File missing = tmp.resolve("missing.pem").toFile();
            assertThrows(IllegalArgumentException.class, () -> server.startSecure("127.0.0.1", 0, missing, missing, null));
        }
    }

    /** D-02: backpressure starts at the high-water mark, so the backpressure verdict's own event still fits. */
    @Test
    void queueSaturatesBeforeItIsFull() {
        BoundedEventQueue q = new BoundedEventQueue(10);
        for (int i = 0; i < 8; i++) {
            q.emit(event("e" + i));
        }
        assertFalse(q.saturated());
        q.emit(event("e8"));
        assertTrue(q.saturated());
        q.emit(event("e9"));
        assertEquals(0, q.dropped(), "the event written while saturated is kept");
    }

    /** D-01, D-02: a shutdown during an outage spools what is queued; a partial replay compacts the spool in order. */
    @Test
    void shutdownSpoolsAndPartialReplayCompacts() throws Exception {
        AtomicInteger accept = new AtomicInteger(0);
        StringBuffer received = new StringBuffer();
        HttpServer http = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 4);
        http.createContext("/internal/v1/verdict-events", ex -> {
            byte[] b = ex.getRequestBody().readAllBytes();
            boolean ok = accept.getAndDecrement() > 0;
            if (ok) {
                received.append(new String(b, StandardCharsets.UTF_8)).append('\n');
            }
            ex.sendResponseHeaders(ok ? 200 : 503, -1);
            ex.close();
        });
        http.start();
        try {
            URI uri = URI.create("http://127.0.0.1:" + http.getAddress().getPort() + "/internal/v1/verdict-events");
            Path spool = tmp.resolve("spool");
            BoundedEventQueue queue = new BoundedEventQueue(1000);
            EventShipper shipper = new EventShipper(queue, uri, spool, 1024 * 1024, Duration.ofMillis(20));
            Thread t = new Thread(shipper);
            t.start();
            queue.emit(event("batch-a"));
            waitFor(() -> shipper.spoolBytes() > 0);
            queue.emit(event("batch-b"));
            waitFor(() -> queue.size() == 0);
            queue.emit(event("batch-c"));
            shipper.stop();
            t.join(10_000);
            assertFalse(t.isAlive(), "the shipper returns after draining");
            assertEquals(0, queue.size(), "nothing is left in memory at shutdown");
            assertEquals(0, shipper.lost());
            long lines = Files.readAllLines(spool.resolve("verdict-spool.jsonl")).size();
            assertEquals(3, lines, "every batch of the outage is in the spool");

            accept.set(1);
            EventShipper replay = new EventShipper(new BoundedEventQueue(10), uri, spool, 1024 * 1024,
                Duration.ofMillis(20));
            Thread r = new Thread(replay);
            r.start();
            waitFor(() -> received.indexOf("batch-a") >= 0);
            waitFor(() -> {
                try {
                    return Files.readAllLines(spool.resolve("verdict-spool.jsonl")).size() == 2;
                } catch (java.io.IOException e) {
                    return false;
                }
            });
            List<String> rest = Files.readAllLines(spool.resolve("verdict-spool.jsonl"));
            assertTrue(rest.get(0).contains("batch-b") && rest.get(1).contains("batch-c"), "the rest keeps its order");
            replay.stop();
            r.join(10_000);
        } finally {
            http.stop(0);
        }
    }

    /** PR 14 recheck N-01: at shutdown with a spool, queued events go straight to disk without any HTTP attempt. */
    @Test
    void shutdownSpillsToSpoolWithoutNetworkAttempts() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        HttpServer http = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 4);
        http.createContext("/internal/v1/verdict-events", ex -> {
            requests.incrementAndGet();
            ex.getRequestBody().readAllBytes();
            ex.sendResponseHeaders(503, -1);
            ex.close();
        });
        http.start();
        try {
            URI uri = URI.create("http://127.0.0.1:" + http.getAddress().getPort() + "/internal/v1/verdict-events");
            Path spool = tmp.resolve("spool-shutdown");
            BoundedEventQueue queue = new BoundedEventQueue(1000);
            for (int i = 0; i < 450; i++) {
                queue.emit(event("late-" + i));
            }
            EventShipper shipper = new EventShipper(queue, uri, spool, 1024 * 1024, Duration.ofMillis(20));
            shipper.stop();
            Thread t = new Thread(shipper);
            t.start();
            t.join(10_000);
            assertFalse(t.isAlive());
            assertEquals(0, queue.size());
            assertEquals(0, requests.get(), "no HTTP attempt during the shutdown spill");
            assertEquals(3, Files.readAllLines(spool.resolve("verdict-spool.jsonl")).size());
        } finally {
            http.stop(0);
        }
    }

    private static void waitFor(java.util.function.BooleanSupplier condition) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 10_000;
        while (!condition.getAsBoolean()) {
            if (System.currentTimeMillis() > deadline) {
                throw new AssertionError("condition not reached in time");
            }
            Thread.sleep(20);
        }
    }

    private static VerdictEvent event(String correlation) {
        return new VerdictEvent(UUID.randomUUID(), Instant.now(), "reqmod", "claude", "api", "chat", Verdict.ALLOW, null,
            Map.of(), 10, 5, null, null, "plain_allowlisted", 1, correlation, List.of(), List.of());
    }
}
