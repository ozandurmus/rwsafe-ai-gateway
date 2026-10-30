package io.rwsafe.dataplane.controlplane;

import io.rwsafe.dataplane.events.BoundedEventQueue;
import io.rwsafe.dataplane.events.VerdictEvent;
import io.rwsafe.dataplane.events.VerdictEventJson;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Drains the verdict queue on its own thread and posts batches to the control plane
 * ({@code POST /internal/v1/verdict-events}). Verdict events are never dropped (ADR-010 §3, SR-DP-12): a batch the
 * control plane does not take goes to a bounded spool file on the pod's emptyDir and is replayed first when the control
 * plane answers again; when the spool is full the shipper holds the batch and stops draining, the queue fills, and the
 * engine then blocks fail-closed flows. Without a configured endpoint the events are counted and discarded (local runs).
 */
public final class EventShipper implements Runnable {

    private static final int BATCH = 200;
    private static final String SPOOL = "verdict-spool.jsonl";

    private final BoundedEventQueue queue;
    private final URI endpoint;
    private final HttpClient client;
    private final Path spoolDir;
    private final long spoolCap;
    private final Duration retryPause;
    private final AtomicLong shipped = new AtomicLong();
    private final AtomicLong discarded = new AtomicLong();
    private final AtomicLong spoolBytes = new AtomicLong();
    private volatile boolean running = true;

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
            // Order is kept: while older batches wait in the spool, new ones join them there.
            boolean spoolPending = client != null && spoolBytes.get() > 0 && !replaySpool();
            batch.clear();
            if (queue.drainTo(batch, BATCH) == 0) {
                pause();
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
                // Spool full or absent: hold this batch until the control plane takes it; the queue fills behind it.
                while (!post(json)) {
                    if (!pause()) {
                        return;
                    }
                }
                shipped.addAndGet(batch.size());
            }
        }
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
        if (spoolBytes.get() + line.length > spoolCap) {
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

    /** Sends spooled batches in order; keeps what the control plane did not take. True when the spool is empty. */
    private boolean replaySpool() {
        Path f = spoolDir.resolve(SPOOL);
        try {
            List<String> lines = Files.readAllLines(f, StandardCharsets.UTF_8);
            int sent = 0;
            for (String line : lines) {
                if (line.isBlank()) {
                    sent++;
                    continue;
                }
                if (!post(line)) {
                    break;
                }
                sent++;
            }
            List<String> rest = lines.subList(sent, lines.size());
            if (rest.isEmpty()) {
                Files.deleteIfExists(f);
                spoolBytes.set(0);
                return true;
            }
            Files.write(f, rest, StandardCharsets.UTF_8);
            spoolBytes.set(Files.size(f));
            return false;
        } catch (IOException e) {
            return false;
        }
    }

    private boolean pause() {
        try {
            Thread.sleep(retryPause.toMillis());
            return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    public void stop() {
        running = false;
    }

    public long shipped() {
        return shipped.get();
    }

    public long discarded() {
        return discarded.get();
    }

    public long spoolBytes() {
        return spoolBytes.get();
    }
}
