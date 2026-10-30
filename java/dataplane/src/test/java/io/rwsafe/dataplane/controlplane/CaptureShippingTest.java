package io.rwsafe.dataplane.controlplane;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import io.rwsafe.dataplane.events.BoundedEventQueue;
import io.rwsafe.dataplane.events.CapturedText;
import io.rwsafe.dataplane.events.VerdictEvent;
import io.rwsafe.dataplane.events.VerdictEventJson;
import io.rwsafe.platform.verdict.Verdict;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Redacted content on the event path (Q-4 b, SR-HOST-2): it travels through the same queue and spool; posted arrays stay
 * under the control plane's cap; above the redacted watermark the spool keeps the events without their content and
 * counts them, and the metadata still arrives.
 */
class CaptureShippingTest {

    private static final String PATH = "/internal/v1/verdict-events";
    private static final String MARK = "synthetic-capture-marker";

    @TempDir
    Path tmp;

    private HttpServer cp;
    private final AtomicBoolean up = new AtomicBoolean(true);
    private final List<String> received = Collections.synchronizedList(new ArrayList<>());

    @BeforeEach
    void controlPlane() throws IOException {
        cp = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 4);
        cp.createContext(PATH, ex -> {
            String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            boolean ok = up.get();
            if (ok) {
                received.add(body);
            }
            ex.sendResponseHeaders(ok ? 202 : 503, -1);
            ex.close();
        });
        cp.start();
    }

    @AfterEach
    void stopControlPlane() {
        cp.stop(0);
    }

    private URI uri() {
        return URI.create("http://127.0.0.1:" + cp.getAddress().getPort() + PATH);
    }

    @Test
    void contentIsShippedInArraysUnderTheCap() throws Exception {
        BoundedEventQueue queue = new BoundedEventQueue(1_000);
        EventShipper shipper = new EventShipper(queue, uri(), null, 0, EventShipper.SEGMENT_BYTES, Duration.ofMillis(5),
            () -> 0.10);
        Thread t = new Thread(shipper);
        t.start();
        for (int i = 0; i < 80; i++) {
            queue.emit(event(MARK + " " + "x".repeat(60_000)));
        }
        waitFor(() -> shipper.shipped() == 80);
        shipper.stop();
        t.join(10_000);
        assertEquals(80, shipper.captureShipped());
        assertTrue(received.size() > 1, "a batch of captured events is split");
        for (String body : received) {
            assertTrue(body.length() <= VerdictEventJson.MAX_ARRAY_CHARS, "under the control plane's request cap");
        }
    }

    @Test
    void aboveTheRedactedWatermarkTheSpoolKeepsMetadataOnly() throws Exception {
        up.set(false);
        Path spool = tmp.resolve("spool");
        BoundedEventQueue queue = new BoundedEventQueue(1_000);
        EventShipper shipper = new EventShipper(queue, uri(), spool, 1024 * 1024, EventShipper.SEGMENT_BYTES,
            Duration.ofMillis(5), () -> 0.90);
        Thread t = new Thread(shipper);
        t.start();
        for (int i = 0; i < 5; i++) {
            queue.emit(event(MARK));
        }
        waitFor(() -> shipper.captureStripped() == 5);
        assertFalse(shipper.spoolAllowsRedacted());
        String spooled = Files.readString(EventShipper.spoolSegments(spool).get(0));
        assertFalse(spooled.contains(MARK), "no redacted content persisted above 85 %");
        assertFalse(spooled.contains("\"capture\""));
        up.set(true);
        waitFor(() -> shipper.shipped() == 5);
        shipper.stop();
        t.join(10_000);
        assertEquals(5, received.stream().mapToLong(b -> b.split("\"eventId\":", -1).length - 1).sum(),
            "metadata and verdicts keep flowing");
    }

    @Test
    void belowTheWatermarkTheSpoolKeepsTheContent() throws Exception {
        up.set(false);
        Path spool = tmp.resolve("spool");
        BoundedEventQueue queue = new BoundedEventQueue(1_000);
        EventShipper shipper = new EventShipper(queue, uri(), spool, 1024 * 1024, EventShipper.SEGMENT_BYTES,
            Duration.ofMillis(5), () -> 0.80);
        Thread t = new Thread(shipper);
        t.start();
        queue.emit(event(MARK));
        waitFor(() -> shipper.spoolBytes() > 0);
        assertTrue(shipper.spoolAllowsRedacted(), "80 % is above raw-off (75 %) but below redacted-off (85 %)");
        assertTrue(Files.readString(EventShipper.spoolSegments(spool).get(0)).contains(MARK));
        assertEquals(0, shipper.captureStripped());
        up.set(true);
        waitFor(() -> shipper.shipped() == 1);
        shipper.stop();
        t.join(10_000);
        assertTrue(String.join("", received).contains(MARK));
    }

    /** PR 25 review D-05: without a spool nothing is counted stripped; a held chunk ships with its content, counted. */
    @Test
    void withoutASpoolAHeldChunkShipsItsContentAndNothingIsCountedStripped() throws Exception {
        up.set(false);
        BoundedEventQueue queue = new BoundedEventQueue(1_000);
        EventShipper shipper = new EventShipper(queue, uri(), null, 0, EventShipper.SEGMENT_BYTES, Duration.ofMillis(5),
            () -> Double.NaN);
        Thread t = new Thread(shipper);
        t.start();
        queue.emit(event(MARK));
        Thread.sleep(100);
        up.set(true);
        waitFor(() -> shipper.shipped() == 1);
        shipper.stop();
        t.join(10_000);
        assertEquals(0, shipper.captureStripped());
        assertEquals(1, shipper.captureShipped());
        assertTrue(String.join("", received).contains(MARK));
    }

    private static void waitFor(BooleanSupplier condition) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 10_000;
        while (!condition.getAsBoolean()) {
            if (System.currentTimeMillis() > deadline) {
                throw new AssertionError("condition not reached in time");
            }
            Thread.sleep(10);
        }
    }

    private static VerdictEvent event(String redacted) {
        return new VerdictEvent(UUID.randomUUID(), Instant.now(), "reqmod", "claude", "api", "chat", Verdict.REDACT,
            "customer_data", Map.of("TCKN", 1), 10, 5, null, null, "plain_allowlisted", 1, UUID.randomUUID().toString(),
            List.of(), List.of(), CapturedText.ofRedacted(("{\"prompt\":\"" + redacted + " [REDACTED:TCKN]\"}")
                .getBytes(StandardCharsets.UTF_8), 64 * 1024));
    }
}
