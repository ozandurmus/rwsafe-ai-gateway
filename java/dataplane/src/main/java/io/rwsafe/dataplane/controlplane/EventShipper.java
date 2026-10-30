package io.rwsafe.dataplane.controlplane;

import io.rwsafe.dataplane.events.BoundedEventQueue;
import io.rwsafe.dataplane.events.VerdictEvent;
import io.rwsafe.dataplane.events.VerdictEventJson;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Drains the verdict queue on its own thread and posts batches to the control plane
 * ({@code POST /internal/v1/verdict-events}). Without a configured endpoint the events are counted and discarded, so the
 * engine runs stand-alone. A failed batch is retried twice, then counted as lost (the spool replaces this, ADR-010 §3).
 */
public final class EventShipper implements Runnable {

    private static final int BATCH = 200;

    private final BoundedEventQueue queue;
    private final URI endpoint;
    private final HttpClient client;
    private final AtomicLong shipped = new AtomicLong();
    private final AtomicLong lost = new AtomicLong();
    private volatile boolean running = true;

    public EventShipper(BoundedEventQueue queue, URI endpoint) {
        this.queue = queue;
        this.endpoint = endpoint;
        this.client = endpoint == null ? null
            : HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
    }

    @Override
    public void run() {
        List<VerdictEvent> batch = new ArrayList<>(BATCH);
        while (running || queue.size() > 0) {
            batch.clear();
            if (queue.drainTo(batch, BATCH) == 0) {
                try {
                    Thread.sleep(200);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
                continue;
            }
            ship(batch);
        }
    }

    private void ship(List<VerdictEvent> batch) {
        if (client == null) {
            shipped.addAndGet(batch.size());
            return;
        }
        HttpRequest request = HttpRequest.newBuilder(endpoint)
            .timeout(Duration.ofSeconds(5))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(VerdictEventJson.array(batch)))
            .build();
        for (int attempt = 0; attempt < 3; attempt++) {
            try {
                HttpResponse<Void> response = client.send(request, HttpResponse.BodyHandlers.discarding());
                if (response.statusCode() / 100 == 2) {
                    shipped.addAndGet(batch.size());
                    return;
                }
            } catch (java.io.IOException e) {
                // retried below
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        lost.addAndGet(batch.size());
    }

    public void stop() {
        running = false;
    }

    public long shipped() {
        return shipped.get();
    }

    public long lost() {
        return lost.get();
    }
}
