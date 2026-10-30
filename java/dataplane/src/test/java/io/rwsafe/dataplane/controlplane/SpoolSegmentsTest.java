package io.rwsafe.dataplane.controlplane;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import io.rwsafe.dataplane.events.BoundedEventQueue;
import io.rwsafe.dataplane.events.VerdictEvent;
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
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BooleanSupplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The segmented verdict spool (PR 18 review D-05 follow-up): disk use peaks at the cap plus one segment, so the 256Mi
 * emptyDir holds a 240 MiB spool. Segments are written here directly where the test needs exact contents.
 */
class SpoolSegmentsTest {

    private static final String PATH = "/internal/v1/verdict-events";

    @TempDir
    Path tmp;

    private HttpServer cp;
    /** Posts the control plane accepts before it refuses with 503; negative accepts everything. */
    private final AtomicInteger accept = new AtomicInteger();
    private final List<String> received = Collections.synchronizedList(new ArrayList<>());

    @BeforeEach
    void controlPlane() throws IOException {
        cp = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 4);
        cp.createContext(PATH, ex -> {
            String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            int left = accept.get();
            boolean ok = left < 0 || left > 0 && accept.compareAndSet(left, left - 1);
            if (ok) {
                received.add(body);
            }
            ex.sendResponseHeaders(ok ? 200 : 503, -1);
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
    void anOutageRollsSegmentsAtTheSegmentSize() throws Exception {
        accept.set(0);
        Path spool = tmp.resolve("spool");
        long segmentBytes = 2 * 1024;
        BoundedEventQueue queue = new BoundedEventQueue(10_000);
        EventShipper shipper = new EventShipper(queue, uri(), spool, 1024 * 1024, segmentBytes, Duration.ofMillis(20));
        Thread t = new Thread(shipper);
        t.start();
        try {
            for (int i = 0; i < 400; i++) {
                queue.emit(event("roll-" + i));
                if (i % 10 == 9) {
                    Thread.sleep(2);
                }
            }
            waitFor(() -> {
                try {
                    return queue.size() == 0 && String.join("\n", lines(spool)).contains("roll-399\"");
                } catch (IOException e) {
                    return false;
                }
            });
        } finally {
            shipper.stop();
            t.join(5_000);
        }
        List<Path> segments = EventShipper.spoolSegments(spool);
        assertTrue(segments.size() >= 3, "segments rolled: " + segments.size());
        long total = 0;
        for (Path seg : segments) {
            long size = Files.size(seg);
            total += size;
            assertTrue(size <= segmentBytes || Files.readAllLines(seg).size() == 1,
                "a segment holds at most the segment size, or one batch larger than it");
        }
        assertEquals(total, shipper.spoolBytes());
        List<String> lines = lines(spool);
        assertTrue(lines.get(0).contains("roll-0\""), "the oldest batch is in the oldest segment");
        assertTrue(String.join("\n", lines).indexOf("roll-0\"") < String.join("\n", lines).indexOf("roll-399\""));
    }

    @Test
    void replayDeletesSentSegmentsAndCompactsOnlyTheOneItStoppedIn() throws Exception {
        Path spool = Files.createDirectories(tmp.resolve("spool"));
        Path first = segment(spool, 1, "a1", "a2");
        Path second = segment(spool, 2, "b1", "b2", "b3");
        Path third = segment(spool, 3, "c1");
        byte[] thirdBefore = Files.readAllBytes(third);
        accept.set(3);
        EventShipper shipper = new EventShipper(new BoundedEventQueue(10), uri(), spool, 1024 * 1024, 1024,
            Duration.ofSeconds(10));
        assertEquals(Files.size(first) + Files.size(second) + Files.size(third), shipper.spoolBytes());
        Thread t = new Thread(shipper);
        t.start();
        try {
            waitFor(() -> received.size() == 3 && !Files.exists(first));
            waitFor(() -> {
                try {
                    return Files.readAllLines(second).size() == 2;
                } catch (IOException e) {
                    return false;
                }
            });
        } finally {
            shipper.stop(Duration.ZERO);
            t.join(5_000);
        }
        assertEquals(List.of(batch("a1"), batch("a2"), batch("b1")), received, "oldest segment first, in order");
        assertFalse(Files.exists(first), "a fully sent segment is deleted");
        assertEquals(List.of(batch("b2"), batch("b3")), Files.readAllLines(second), "only the unsent rest remains");
        assertTrue(java.util.Arrays.equals(thirdBefore, Files.readAllBytes(third)), "later segments are not rewritten");
        assertEquals(List.of(second, third), EventShipper.spoolSegments(spool));
        assertEquals(Files.size(second) + Files.size(third), shipper.spoolBytes());
        assertEquals(3, shipper.shipped());
        try (Stream<Path> files = Files.list(spool)) {
            assertTrue(files.noneMatch(f -> f.toString().endsWith(".tmp")), "no temporary file is left");
        }
    }

    @Test
    void restartPicksUpSegmentsAndALegacySpoolFileInOrder() throws Exception {
        Path spool = Files.createDirectories(tmp.resolve("spool"));
        Files.writeString(spool.resolve("verdict-spool.jsonl"), batch("legacy-1") + "\n" + batch("legacy-2") + "\n");
        segment(spool, 5, "segment-1");
        Files.writeString(spool.resolve("verdict-spool-0000000000000000005.jsonl.tmp"), "a crashed compaction\n");
        accept.set(0);
        EventShipper shipper = new EventShipper(new BoundedEventQueue(10), uri(), spool, 1024 * 1024, 1024,
            Duration.ofMillis(20));
        List<Path> segments = EventShipper.spoolSegments(spool);
        assertEquals(2, segments.size(), "the legacy file became the oldest segment");
        assertFalse(Files.exists(spool.resolve("verdict-spool.jsonl")));
        assertFalse(Files.exists(spool.resolve("verdict-spool-0000000000000000005.jsonl.tmp")),
            "a crashed compaction's temporary file is dropped; its segment is intact");
        assertEquals(Files.size(segments.get(0)) + Files.size(segments.get(1)), shipper.spoolBytes(),
            "the restart counts every segment");

        accept.set(-1);
        Thread t = new Thread(shipper);
        t.start();
        try {
            waitFor(() -> received.size() == 3);
            waitFor(() -> shipper.spoolBytes() == 0);
        } finally {
            shipper.stop();
            t.join(5_000);
        }
        assertEquals(List.of(batch("legacy-1"), batch("legacy-2"), batch("segment-1")), received);
        assertTrue(EventShipper.spoolSegments(spool).isEmpty());
    }

    @Test
    void diskUsePeaksAtTheCapPlusOneSegment() throws Exception {
        long segmentBytes = 8 * 1024;
        long cap = 64 * 1024;
        Path spool = Files.createDirectories(tmp.resolve("spool"));
        String filler = "x".repeat(1000);
        // A full spool: eight full segments of eight 1 KiB batches each.
        for (int s = 1; s <= 8; s++) {
            String[] names = new String[8];
            for (int l = 0; l < 8; l++) {
                names[l] = s + "-" + l + "-" + filler;
            }
            segment(spool, s, names);
        }
        accept.set(0);
        BoundedEventQueue queue = new BoundedEventQueue(100);
        EventShipper shipper = new EventShipper(queue, uri(), spool, cap, segmentBytes, Duration.ofMillis(20));
        assertTrue(shipper.spoolBytes() > cap - segmentBytes, "the spool starts nearly full");

        AtomicBoolean sampling = new AtomicBoolean(true);
        AtomicLong sampledPeak = new AtomicLong();
        Thread sampler = new Thread(() -> {
            while (sampling.get()) {
                sampledPeak.accumulateAndGet(directoryBytes(spool), Math::max);
            }
        });
        sampler.start();
        Thread t = new Thread(shipper);
        try {
            // Two sent batches, then a refusal: the first segment is compacted while the rest of the spool stays.
            accept.set(2);
            t.start();
            waitFor(() -> received.size() == 2);
            waitFor(() -> {
                try {
                    return Files.readAllLines(EventShipper.spoolSegments(spool).get(0)).size() == 6;
                } catch (IOException e) {
                    return false;
                }
            });
            // An outage on a nearly full spool: new batches are refused at the cap, never past it.
            queue.emit(event("over-the-cap"));
            waitFor(() -> queue.size() == 0);
            Thread.sleep(200);
        } finally {
            shipper.stop(Duration.ZERO);
            t.join(5_000);
            sampling.set(false);
            sampler.join();
        }
        assertTrue(shipper.spoolBytes() <= cap, "the segments together never pass the cap");
        assertTrue(shipper.peakDiskBytes() > cap - segmentBytes, "the compaction ran on a nearly full spool");
        assertTrue(shipper.peakDiskBytes() <= cap + segmentBytes,
            "peak " + shipper.peakDiskBytes() + " is within the cap plus one segment");
        assertTrue(sampledPeak.get() <= cap + segmentBytes, "sampled peak " + sampledPeak.get());
    }

    private static long directoryBytes(Path dir) {
        long total = 0;
        try (Stream<Path> files = Files.list(dir)) {
            for (Path f : (Iterable<Path>) files::iterator) {
                try {
                    total += Files.size(f);
                } catch (IOException e) {
                    // Moved or deleted while listing.
                }
            }
        } catch (IOException e) {
            return 0;
        }
        return total;
    }

    private static Path segment(Path spool, long number, String... correlations) throws IOException {
        StringBuilder b = new StringBuilder();
        for (String c : correlations) {
            b.append(batch(c)).append('\n');
        }
        Path f = spool.resolve("verdict-spool-" + String.format("%019d", number) + ".jsonl");
        Files.writeString(f, b.toString());
        return f;
    }

    /** One spooled line: a JSON array of one synthetic event, as the shipper writes it. */
    private static String batch(String correlation) {
        return "[{\"eventId\":\"" + correlation + "\"}]";
    }

    private static List<String> lines(Path spool) throws IOException {
        List<String> out = new ArrayList<>();
        for (Path seg : EventShipper.spoolSegments(spool)) {
            out.addAll(Files.readAllLines(seg));
        }
        return out;
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

    private static VerdictEvent event(String correlation) {
        return new VerdictEvent(UUID.randomUUID(), Instant.now(), "reqmod", "claude", "api", "chat", Verdict.ALLOW, null,
            Map.of(), 10, 5, null, null, "plain_allowlisted", 1, correlation);
    }
}
