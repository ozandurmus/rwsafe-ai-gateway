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
import java.util.concurrent.atomic.AtomicLong;

/**
 * Drains the verdict queue on its own thread and posts batches to the control plane
 * ({@code POST /internal/v1/verdict-events}). Verdict events are not dropped (ADR-010 §3, SR-DP-12):
 * <ul>
 *   <li>a batch the control plane does not take goes to a bounded spool file on the pod's emptyDir; while the spool holds
 *       anything, new batches join it there so order is kept, and a replay is tried at most once per back-off interval, so
 *       the queue drains at disk speed during an outage (PR 14 review D-02);</li>
 *   <li>the replay streams the spool line by line and compacts it through a temporary file moved atomically, never
 *       rewriting the file in place;</li>
 *   <li>when the spool is full the shipper holds the batch and stops draining, the queue fills past its high-water mark,
 *       and the engine blocks fail-closed flows;</li>
 *   <li>on shutdown the shipper drains the queue to the control plane or the spool before it returns (D-01).</li>
 * </ul>
 * Without a configured endpoint the events are counted and discarded (local runs).
 */
public final class EventShipper implements Runnable {

    private static final int BATCH = 200;
    private static final String SPOOL = "verdict-spool.jsonl";
    private static final int SHUTDOWN_ATTEMPTS = 3;

    private final BoundedEventQueue queue;
    private final URI endpoint;
    private final HttpClient client;
    private final Path spoolDir;
    private final long spoolCap;
    private final Duration retryPause;
    private final AtomicLong shipped = new AtomicLong();
    private final AtomicLong discarded = new AtomicLong();
    private final AtomicLong lost = new AtomicLong();
    private final AtomicLong spoolBytes = new AtomicLong();
    private final Object wake = new Object();
    private volatile boolean running = true;
    private long nextReplayAtNanos;

    public EventShipper(BoundedEventQueue queue, URI endpoint) {
        this(queue, endpoint, null, 0, Duration.ofSeconds(1));
    }

    /** @param spoolDir emptyDir path for the spool, or null for no spool (the queue alone absorbs an outage) */
    public EventShipper(BoundedEventQueue queue, URI endpoint, Path spoolDir, long spoolCap, Duration retryPause) {
        this.queue = queue;
        this.endpoint = endpoint;
        this.client = endpoint == null ? null
            : HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
        this.spoolDir = spoolDir;
        this.spoolCap = spoolCap;
        this.retryPause = retryPause;
        if (spoolDir != null) {
            try {
                Path f = spoolDir.resolve(SPOOL);
                spoolBytes.set(Files.exists(f) ? Files.size(f) : 0);
            } catch (IOException e) {
                spoolBytes.set(0);
            }
        }
    }

    @Override
    public void run() {
        List<VerdictEvent> batch = new ArrayList<>(BATCH);
        while (running || queue.size() > 0) {
            boolean spoolPending = client != null && spoolBytes.get() > 0 && !replayDue();
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
            } else if (!spoolAppend(json)) {
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
            if (!running && ++attempts >= SHUTDOWN_ATTEMPTS) {
                lost.addAndGet(size);
                return;
            }
            pause();
        }
        shipped.addAndGet(size);
    }

    private boolean post(String json) {
        HttpRequest request = HttpRequest.newBuilder(endpoint)
            .timeout(Duration.ofSeconds(5))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(json))
            .build();
        try {
            return client.send(request, HttpResponse.BodyHandlers.discarding()).statusCode() / 100 == 2;
        } catch (IOException e) {
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private boolean spoolAppend(String json) {
        if (spoolDir == null) {
            return false;
        }
        byte[] line = (json + "\n").getBytes(StandardCharsets.UTF_8);
        // One batch of margin stays free so a compaction can always write its temporary file.
        if (spoolBytes.get() + line.length > spoolCap - line.length) {
            return false;
        }
        try {
            Files.createDirectories(spoolDir);
            Files.write(spoolDir.resolve(SPOOL), line, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            spoolBytes.addAndGet(line.length);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Streams spooled batches in order and posts them; stops at the first refusal. Sent lines are removed by copying the
     * rest to a temporary file that replaces the spool atomically; nothing is rewritten when nothing was sent.
     */
    private boolean replaySpool() {
        Path f = spoolDir.resolve(SPOOL);
        if (!Files.exists(f)) {
            spoolBytes.set(0);
            return true;
        }
        long sentLines = 0;
        boolean stopped = false;
        try (BufferedReader in = Files.newBufferedReader(f, StandardCharsets.UTF_8)) {
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
                Files.deleteIfExists(f);
                spoolBytes.set(0);
                return true;
            }
            if (sentLines == 0) {
                return false;
            }
            Path tmp = spoolDir.resolve(SPOOL + ".tmp");
            try (BufferedReader in = Files.newBufferedReader(f, StandardCharsets.UTF_8);
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
            Files.move(tmp, f, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            spoolBytes.set(Files.size(f));
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

    /** Asks the shipper to finish: it drains what is queued (to the control plane or the spool) and returns. */
    public void stop() {
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

    /** Events that could neither be sent nor spooled at shutdown (no spool, control plane down). */
    public long lost() {
        return lost.get();
    }

    public long spoolBytes() {
        return spoolBytes.get();
    }
}
