package io.rwsafe.dataplane.boot;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import io.rwsafe.dataplane.controlplane.EventShipper;
import io.rwsafe.dataplane.events.BoundedEventQueue;
import io.rwsafe.dataplane.events.VerdictEvent;
import io.rwsafe.dataplane.server.EngineConfig;
import io.rwsafe.dataplane.server.IcapEngine;
import io.rwsafe.detect.DetectorSet;
import io.rwsafe.platform.verdict.Verdict;
import io.rwsafe.policy.Snapshots;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** PR 18 second review D-02: the preStop drain and the termination bound of the data plane. */
class ShutdownSequenceTest {

    @TempDir
    Path tmp;

    private final HttpClient http = HttpClient.newHttpClient();

    @Test
    void theBudgetFitsTheGracePeriodOfTheManifest() throws Exception {
        assertTrue(IcapServer.DRAIN_TOTAL_MILLIS + IcapServer.CLOSE_MILLIS + ShutdownSequence.EVENT_FLUSH_MILLIS
            + ShutdownSequence.MARGIN_MILLIS <= ShutdownSequence.GRACE_MILLIS);
        assertTrue(EngineConfig.defaults().drainServeMillis() < IcapServer.DRAIN_TOTAL_MILLIS);
        String manifest = Files.readString(repositoryFile("deploy/rwsafe/base/30-dataplane.yaml"));
        assertTrue(manifest.contains("terminationGracePeriodSeconds: " + ShutdownSequence.GRACE_MILLIS / 1000),
            "the Deployment's grace period is the one the sequence is budgeted for");
        assertTrue(manifest.contains("path: " + MetricsEndpoint.DRAIN_PATH), "the preStop hook calls the drain");
    }

    @Test
    void preStopDrainAnswersAfterTheServeWindowWhileReadyAnswers503AndSigtermDoesNotServeTwice() throws Exception {
        long serve = 1_500;
        BoundedEventQueue queue = new BoundedEventQueue(100);
        IcapEngine engine = new IcapEngine(Snapshots.builtinDevelopment(), DetectorSet.standard(), queue,
            EngineConfig.defaults());
        EventShipper shipper = new EventShipper(queue, null);
        IcapServer server = new IcapServer(engine, serve);
        server.start("127.0.0.1", 0);
        MetricsEndpoint metrics = new MetricsEndpoint("127.0.0.1", 0, engine, queue, shipper, null, serve);
        try {
            assertEquals(200, status("GET", metrics.port(), "/ready"));
            assertEquals(405, status("PUT", metrics.port(), MetricsEndpoint.DRAIN_PATH));
            assertFalse(engine.draining(), "only GET and POST drain");

            long start = System.nanoTime();
            CompletableFuture<HttpResponse<Void>> drain = http.sendAsync(request("GET", metrics.port(),
                MetricsEndpoint.DRAIN_PATH), HttpResponse.BodyHandlers.discarding());
            long deadline = System.currentTimeMillis() + 1_000;
            while (!engine.draining() && System.currentTimeMillis() < deadline) {
                Thread.sleep(10);
            }
            assertTrue(engine.draining(), "the drain starts when the hook is called, not at SIGTERM");
            assertEquals(503, status("GET", metrics.port(), "/ready"), "readiness answers while the hook is held");
            assertFalse(drain.isDone(), "the hook is held for the serve window");
            assertEquals(200, drain.get(5, TimeUnit.SECONDS).statusCode());
            assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) >= serve - 50);

            long closeStart = System.nanoTime();
            server.close();
            assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - closeStart) < serve,
                "SIGTERM after the hook does not serve a second window");
        } finally {
            metrics.close();
        }
    }

    @Test
    void theFlushPostsTheDrainsEventsToARunningControlPlane() throws Exception {
        AtomicInteger received = new AtomicInteger();
        HttpServer cp = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 4);
        cp.createContext("/internal/v1/verdict-events", ex -> {
            String body = new String(ex.getRequestBody().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            received.addAndGet(body.split("\"eventId\":", -1).length - 1);
            ex.sendResponseHeaders(202, -1);
            ex.close();
        });
        cp.start();
        try {
            BoundedEventQueue queue = new BoundedEventQueue(1000);
            Path spool = tmp.resolve("spool");
            EventShipper shipper = new EventShipper(queue, endpoint(cp), spool, 1024 * 1024, Duration.ofSeconds(1));
            Thread t = new Thread(shipper);
            t.start();
            for (int i = 0; i < 250; i++) {
                queue.emit(event());
            }
            ShutdownSequence.flushEvents(queue, shipper, t, Duration.ofSeconds(4));
            assertFalse(t.isAlive());
            assertEquals(250, received.get(), "posted to the control plane, not left on the pod's emptyDir");
            assertEquals(250, shipper.shipped());
            assertEquals(0, shipper.lost());
            assertTrue(EventShipper.spoolSegments(spool).isEmpty(), "nothing spooled");
        } finally {
            cp.stop(0);
        }
    }

    @Test
    void theFlushEndsWithinItsBoundWhenTheControlPlaneHangs() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        HttpServer cp = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 4);
        cp.setExecutor(java.util.concurrent.Executors.newCachedThreadPool(r -> {
            Thread th = new Thread(r);
            th.setDaemon(true);
            return th;
        }));
        cp.createContext("/internal/v1/verdict-events", ex -> {
            try {
                release.await(30, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            ex.sendResponseHeaders(503, -1);
            ex.close();
        });
        cp.start();
        try {
            BoundedEventQueue queue = new BoundedEventQueue(1000);
            // No spool: the shipper can only post, and every post hangs.
            EventShipper shipper = new EventShipper(queue, endpoint(cp), null, 0, Duration.ofMillis(20));
            Thread t = new Thread(shipper);
            t.start();
            for (int i = 0; i < 450; i++) {
                queue.emit(event());
            }
            long start = System.nanoTime();
            ShutdownSequence.flushEvents(queue, shipper, t, Duration.ofMillis(1_500));
            long took = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
            assertTrue(took < 2_500, "the flush returned after " + took + " ms");
            t.join(1_000);
            assertFalse(t.isAlive(), "the shipper itself honours the bound");
            assertEquals(0, queue.size());
            assertEquals(450, shipper.lost() + shipper.shipped(), "every event is accounted for");
            assertTrue(shipper.lost() > 0);
        } finally {
            release.countDown();
            cp.stop(0);
        }
    }

    private static URI endpoint(HttpServer cp) {
        return URI.create("http://127.0.0.1:" + cp.getAddress().getPort() + "/internal/v1/verdict-events");
    }

    private int status(String method, int port, String path) throws Exception {
        return http.send(request(method, port, path), HttpResponse.BodyHandlers.discarding()).statusCode();
    }

    private static HttpRequest request(String method, int port, String path) {
        return HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
            .method(method, HttpRequest.BodyPublishers.noBody()).timeout(Duration.ofSeconds(10)).build();
    }

    private static VerdictEvent event() {
        return new VerdictEvent(UUID.randomUUID(), Instant.now(), "reqmod", "claude", "api", "chat", Verdict.ALLOW, null,
            Map.of(), 10, 5, null, null, "plain_allowlisted", 1, "synthetic");
    }

    private static Path repositoryFile(String relative) {
        for (Path p = Path.of("").toAbsolutePath(); p != null; p = p.getParent()) {
            Path candidate = p.resolve(relative);
            if (Files.isRegularFile(candidate) && Files.isRegularFile(p.resolve("AGENTS.md"))) {
                return candidate;
            }
        }
        throw new IllegalStateException(relative + " not found above the working directory");
    }
}
