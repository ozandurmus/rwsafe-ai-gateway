package io.rwsafe.dataplane.controlplane;

import io.rwsafe.dataplane.events.BoundedEventQueue;
import io.rwsafe.dataplane.events.VerdictEvent;
import io.rwsafe.dataplane.events.VerdictEventJson;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Drains the verdict queue on its own thread and posts batches to the control plane
 * ({@code POST /internal/v1/verdict-events}). Verdict events are not dropped (ADR-010 §3, SR-DP-12):
 * <ul>
 *   <li>a batch the control plane does not take goes to a bounded spool on the pod's emptyDir; while the spool holds
 *       anything, new batches join it there so order is kept, and a replay is tried at most once per back-off interval, so
 *       the queue drains at disk speed during an outage (PR 14 review D-02);</li>
 *   <li>the spool is a series of numbered segment files ({@code verdict-spool-<n>.jsonl}, one batch per line): batches
 *       are appended to the newest, which rolls at {@link #SEGMENT_BYTES}; the replay streams the oldest segment first,
 *       deletes a segment once every line in it is sent, and compacts only the one segment it stopped in through a
 *       temporary file moved atomically. Disk use therefore peaks at the cap plus one segment, never twice the cap, so the
 *       emptyDir's sizeLimit holds (ADR-001 §3, PR 18 review D-05). A legacy single spool file is picked up as the oldest
 *       segment at start;</li>
 *   <li>when the spool is full the shipper holds the batch and stops draining, the queue fills past its high-water mark,
 *       and the engine blocks fail-closed flows;</li>
 *   <li>on shutdown the shipper drains the queue to the control plane or the spool before it returns (D-01), within the
 *       flush bound it is stopped with: what is left when the bound ends is counted lost, so the pod's termination
 *       stays inside its grace period (PR 18 review D-02).</li>
 * </ul>
 * Without a configured endpoint the events are counted and discarded (local runs).
 */
public final class EventShipper implements Runnable {

    private static final int BATCH = 200;
    /** The single-file spool of earlier versions; picked up as the oldest segment at start. */
    private static final String LEGACY_SPOOL = "verdict-spool.jsonl";
    private static final String SEGMENT_PREFIX = "verdict-spool-";
    private static final String SEGMENT_SUFFIX = ".jsonl";
    private static final String TMP_SUFFIX = ".tmp";
    /** The segment size: a segment rolls before a batch would take it past this (a larger batch gets its own). */
    public static final long SEGMENT_BYTES = 8L * 1024 * 1024;
    private static final int SHUTDOWN_ATTEMPTS = 3;
    private static final Duration POST_TIMEOUT = Duration.ofSeconds(5);
    /** The flush bound of {@link #stop()}. */
    public static final Duration DEFAULT_FLUSH_BOUND = Duration.ofSeconds(5);

    private final BoundedEventQueue queue;
    private final URI endpoint;
    private final HttpClient client;
    private final Path spoolDir;
    private final long spoolCap;
    private final long segmentBytes;
    private final AtomicLong peakDiskBytes = new AtomicLong();
    private final Duration retryPause;
    private final AtomicLong shipped = new AtomicLong();
    private final AtomicLong discarded = new AtomicLong();
    private final AtomicLong lost = new AtomicLong();
    private final AtomicLong spoolBytes = new AtomicLong();
    private final Object wake = new Object();
    private volatile boolean running = true;
    private volatile long stopDeadlineNanos;
    private long nextReplayAtNanos;

    public EventShipper(BoundedEventQueue queue, URI endpoint) {
        this(queue, endpoint, null, 0, Duration.ofSeconds(1));
    }

    /** @param spoolDir emptyDir path for the spool, or null for no spool (the queue alone absorbs an outage) */
    public EventShipper(BoundedEventQueue queue, URI endpoint, Path spoolDir, long spoolCap, Duration retryPause) {
        this(queue, endpoint, spoolDir, spoolCap, SEGMENT_BYTES, retryPause);
    }

    /**
     * @param spoolCap     the spool's bytes on disk at most, segments together; a compaction adds at most one segment
     * @param segmentBytes the segment size ({@link #SEGMENT_BYTES} in the product; smaller in tests)
     */
    public EventShipper(BoundedEventQueue queue, URI endpoint, Path spoolDir, long spoolCap, long segmentBytes,
                        Duration retryPause) {
        if (segmentBytes <= 0) {
            throw new IllegalArgumentException("segmentBytes must be positive");
        }
        this.segmentBytes = segmentBytes;
        this.queue = queue;
        this.endpoint = endpoint;
        this.client = endpoint == null ? null
            : HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
        this.spoolDir = spoolDir;
        this.spoolCap = spoolCap;
        this.retryPause = retryPause;
        if (spoolDir != null) {
            pickUp();
        }
    }

    /**
     * Restart pickup: drops a compaction's temporary file left by a crash (its segment is intact), moves a legacy
     * single-file spool in front of the segments, and counts what is on disk.
     */
    private void pickUp() {
        try {
            if (Files.isDirectory(spoolDir)) {
                try (var files = Files.list(spoolDir)) {
                    for (Path tmp : files.filter(f -> f.getFileName().toString().endsWith(TMP_SUFFIX)).toList()) {
                        Files.deleteIfExists(tmp);
                    }
                }
                Path legacy = spoolDir.resolve(LEGACY_SPOOL);
                if (Files.exists(legacy)) {
                    List<Long> numbers = segmentNumbers(spoolDir);
                    long first = numbers.isEmpty() ? 1 : numbers.get(0) - 1;
                    Files.move(legacy, segment(spoolDir, first), StandardCopyOption.ATOMIC_MOVE);
                }
            }
        } catch (IOException e) {
            // Counted below from whatever is there; a failed pickup never loses a segment.
        }
        recount();
    }

    /** The spool's segment files, oldest first (empty when the directory does not exist). */
    public static List<Path> spoolSegments(Path spoolDir) {
        List<Path> out = new ArrayList<>();
        for (long n : segmentNumbers(spoolDir)) {
            out.add(segment(spoolDir, n));
        }
        return out;
    }

    private static List<Long> segmentNumbers(Path spoolDir) {
        List<Long> numbers = new ArrayList<>();
        if (spoolDir == null || !Files.isDirectory(spoolDir)) {
            return numbers;
        }
        try (var files = Files.list(spoolDir)) {
            for (Path f : (Iterable<Path>) files::iterator) {
                String name = f.getFileName().toString();
                if (name.startsWith(SEGMENT_PREFIX) && name.endsWith(SEGMENT_SUFFIX)) {
                    try {
                        numbers.add(Long.parseLong(
                            name.substring(SEGMENT_PREFIX.length(), name.length() - SEGMENT_SUFFIX.length())));
                    } catch (NumberFormatException e) {
                        // Not a segment of ours.
                    }
                }
            }
        } catch (IOException e) {
            return numbers;
        }
        numbers.sort(null);
        return numbers;
    }

    private static Path segment(Path spoolDir, long number) {
        return spoolDir.resolve(SEGMENT_PREFIX + String.format("%019d", number) + SEGMENT_SUFFIX);
    }

    /** spoolBytes = the sizes of the segments on disk. */
    private void recount() {
        long total = 0;
        for (Path seg : spoolSegments(spoolDir)) {
            try {
                total += Files.size(seg);
            } catch (IOException e) {
                // Gone between the listing and the size: nothing to count.
            }
        }
        spoolBytes.set(total);
        notePeak(total);
    }

    private void notePeak(long bytesOnDisk) {
        peakDiskBytes.accumulateAndGet(bytesOnDisk, Math::max);
    }

    @Override
    public void run() {
        List<VerdictEvent> batch = new ArrayList<>(BATCH);
        while (running || queue.size() > 0) {
            if (flushBoundPassed()) {
                abandonQueued();
                return;
            }
            // On shutdown with a spool, queued batches go straight to disk: no replay and no HTTP wait (PR 14 recheck N-01).
            boolean shuttingDownToSpool = !running && spoolDir != null;
            boolean spoolPending = client != null
                && (shuttingDownToSpool || (spoolBytes.get() > 0 && !replayDue()));
            batch.clear();
            if (queue.drainTo(batch, BATCH) == 0) {
                if (running) {
                    pause();
                }
                continue;
            }
            if (client == null) {
                discarded.addAndGet(batch.size());
                continue;
            }
            String json = VerdictEventJson.array(batch);
            if (!spoolPending && post(json)) {
                shipped.addAndGet(batch.size());
            } else if (spoolAppend(json)) {
                if (!spoolPending) {
                    // The control plane just refused: wait the back-off before replaying what was spooled (N-01).
                    nextReplayAtNanos = System.nanoTime() + Math.max(retryPause.toNanos() * 5, 1_000_000L);
                }
            } else {
                hold(json, batch.size());
            }
        }
    }

    /** True when the spool is empty after a replay attempt; attempts are spaced by the back-off (D-02). */
    private boolean replayDue() {
        long now = System.nanoTime();
        if (now - nextReplayAtNanos < 0) {
            return false;
        }
        boolean empty = replaySpool();
        if (!empty) {
            nextReplayAtNanos = now + Math.max(retryPause.toNanos() * 5, 1_000_000L);
        }
        return empty;
    }

    /** Spool full or absent: keep this batch until the control plane takes it; the queue fills behind it. */
    private void hold(String json, int size) {
        int attempts = 0;
        while (!post(json)) {
            if (!running && (++attempts >= SHUTDOWN_ATTEMPTS || flushBoundPassed())) {
                lost.addAndGet(size);
                return;
            }
            pause();
        }
        shipped.addAndGet(size);
    }

    private boolean post(String json) {
        Duration timeout = POST_TIMEOUT;
        if (!running) {
            long left = stopDeadlineNanos - System.nanoTime();
            if (left <= 0) {
                return false;
            }
            timeout = Duration.ofNanos(Math.min(left, POST_TIMEOUT.toNanos()));
        }
        HttpRequest request = HttpRequest.newBuilder(endpoint)
            .timeout(timeout)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(json))
            .build();
        // Asynchronous with a short wait, so a stop's flush bound also ends a post that began while running.
        CompletableFuture<HttpResponse<Void>> response = client.sendAsync(request, HttpResponse.BodyHandlers.discarding());
        try {
            while (true) {
                try {
                    return response.get(50, TimeUnit.MILLISECONDS).statusCode() / 100 == 2;
                } catch (TimeoutException e) {
                    if (flushBoundPassed()) {
                        response.cancel(true);
                        return false;
                    }
                }
            }
        } catch (ExecutionException e) {
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            response.cancel(true);
            return false;
        }
    }

    private boolean spoolAppend(String json) {
        if (spoolDir == null) {
            return false;
        }
        byte[] line = (json + "\n").getBytes(StandardCharsets.UTF_8);
        // The cap bounds the segments together; a compaction adds at most one segment on top (replaySegment).
        if (spoolBytes.get() + line.length > spoolCap) {
            return false;
        }
        try {
            Files.createDirectories(spoolDir);
            List<Long> numbers = segmentNumbers(spoolDir);
            long newest = numbers.isEmpty() ? 1 : numbers.get(numbers.size() - 1);
            Path target = segment(spoolDir, newest);
            long size = Files.exists(target) ? Files.size(target) : 0;
            if (size > 0 && size + line.length > segmentBytes) {
                target = segment(spoolDir, newest + 1);
            }
            Files.write(target, line, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            notePeak(spoolBytes.addAndGet(line.length));
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /** Replays the segments oldest first; true when the spool is empty afterwards. Stops at the first refusal. */
    private boolean replaySpool() {
        try {
            for (Path seg : spoolSegments(spoolDir)) {
                if (!replaySegment(seg)) {
                    return false;
                }
            }
            return true;
        } finally {
            recount();
        }
    }

    /**
     * Streams one segment's batches in order and posts them; true when every line was sent and the segment deleted.
     * After a refusal the sent lines are removed by copying the rest to a temporary file that replaces the segment
     * atomically, so the extra disk is at most this one segment; nothing is rewritten when nothing was sent.
     */
    private boolean replaySegment(Path seg) {
        long sentLines = 0;
        boolean stopped = false;
        try (BufferedReader in = Files.newBufferedReader(seg, StandardCharsets.UTF_8)) {
            String line;
            while ((line = in.readLine()) != null) {
                if (!line.isBlank() && !post(line)) {
                    stopped = true;
                    break;
                }
                sentLines++;
                shipped.addAndGet(countEvents(line));
            }
        } catch (IOException e) {
            return false;
        }
        try {
            if (!stopped) {
                long size = Files.size(seg);
                Files.deleteIfExists(seg);
                spoolBytes.addAndGet(-size);
                return true;
            }
            if (sentLines == 0) {
                return false;
            }
            Path tmp = seg.resolveSibling(seg.getFileName() + TMP_SUFFIX);
            try (BufferedReader in = Files.newBufferedReader(seg, StandardCharsets.UTF_8);
                 BufferedWriter out = Files.newBufferedWriter(tmp, StandardCharsets.UTF_8)) {
                for (long i = 0; i < sentLines; i++) {
                    in.readLine();
                }
                String line;
                while ((line = in.readLine()) != null) {
                    out.write(line);
                    out.write('\n');
                }
            }
            notePeak(spoolBytes.get() + Files.size(tmp));
            Files.move(tmp, seg, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            return false;
        } catch (IOException e) {
            return false;
        }
    }

    private static long countEvents(String jsonArray) {
        long n = 0;
        int i = 0;
        while ((i = jsonArray.indexOf("\"eventId\":", i)) >= 0) {
            n++;
            i++;
        }
        return n;
    }

    private void pause() {
        synchronized (wake) {
            if (!running) {
                return;
            }
            try {
                wake.wait(Math.max(1, retryPause.toMillis()));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /** True once a stopped shipper's flush bound has ended. */
    private boolean flushBoundPassed() {
        return !running && System.nanoTime() - stopDeadlineNanos >= 0;
    }

    /** The flush bound ended: what is still queued is counted lost, never silently dropped. */
    private void abandonQueued() {
        List<VerdictEvent> rest = new ArrayList<>(BATCH);
        int n;
        while ((n = queue.drainTo(rest, BATCH)) > 0) {
            lost.addAndGet(n);
            rest.clear();
        }
    }

    /** {@link #stop(Duration)} with {@link #DEFAULT_FLUSH_BOUND}. */
    public void stop() {
        stop(DEFAULT_FLUSH_BOUND);
    }

    /**
     * Asks the shipper to finish: it drains what is queued (to the control plane or the spool) and returns, at the
     * latest when {@code flushBound} has passed; events still queued then are counted in {@link #lost()}.
     */
    public void stop(Duration flushBound) {
        stopDeadlineNanos = System.nanoTime() + Math.max(0, flushBound.toNanos());
        running = false;
        synchronized (wake) {
            wake.notifyAll();
        }
    }

    public long shipped() {
        return shipped.get();
    }

    public long discarded() {
        return discarded.get();
    }

    /** Events that could neither be sent nor spooled at shutdown (no spool, control plane down, flush bound over). */
    public long lost() {
        return lost.get();
    }

    public long spoolBytes() {
        return spoolBytes.get();
    }

    /** The most spool bytes this shipper has had on disk at once, a compaction's temporary file included. */
    public long peakDiskBytes() {
        return peakDiskBytes.get();
    }
}
