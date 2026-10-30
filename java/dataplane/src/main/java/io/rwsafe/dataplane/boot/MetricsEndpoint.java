package io.rwsafe.dataplane.boot;

import com.sun.net.httpserver.HttpServer;
import io.rwsafe.dataplane.controlplane.EventShipper;
import io.rwsafe.dataplane.controlplane.SnapshotPoller;
import io.rwsafe.dataplane.events.BoundedEventQueue;
import io.rwsafe.dataplane.metrics.PrometheusText;
import io.rwsafe.dataplane.server.IcapEngine;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * {@code GET /metrics} (Prometheus text), {@code GET /ready} (200 or 503) and the preStop hook {@code /admin/drain} on a
 * separate port; no content ever.
 *
 * <p>{@code /admin/drain} (DEPLOY_AND_SHARED_HOST_RUNBOOK §1.2, PR 18 review D-02) starts the engine's drain at once, so
 * OPTIONS and {@code /ready} answer 503 and every response carries {@code Connection: close} from the first second, and
 * answers only when the serve window has passed: the kubelet sends SIGTERM after the hook returns, and the shutdown then
 * waits only for what is still in flight. The kubelet's lifecycle {@code httpGet} can only send GET, so GET and POST both
 * drain. Draining is one-way and idempotent; the listener is reached by the kubelet and the peers the NetworkPolicies
 * admit to the metrics port, never from outside the cluster.
 */
public final class MetricsEndpoint implements AutoCloseable {

    public static final String DRAIN_PATH = "/admin/drain";

    private final HttpServer server;
    // A drain call holds its thread for the serve window; /ready and /metrics keep answering on the others.
    private final ExecutorService handlers = Executors.newFixedThreadPool(4, r -> {
        Thread t = new Thread(r, "rwsafe-metrics-http");
        t.setDaemon(true);
        return t;
    });

    public MetricsEndpoint(String host, int port, IcapEngine engine, BoundedEventQueue queue, EventShipper shipper,
                           SnapshotPoller poller, long drainServeMillis) throws IOException {
        server = HttpServer.create(new InetSocketAddress(host, port), 16);
        server.setExecutor(handlers);
        server.createContext("/metrics", exchange -> {
            IcapEngine.Policy p = engine.policy();
            String text = PrometheusText.render(engine.metrics(), new PrometheusText.Gauges(
                engine.admission().inflight(), engine.admission().bodyBytesHeld(), engine.admission().identityCapped(),
                engine.admission().engineFull(), engine.admission().bodyBudgetRejections(), queue.size(),
                queue.dropped(), shipper.spoolBytes(), p == null ? 0 : p.snapshot().version(), engine.available(),
                poller == null ? Map.of() : poller.refusals()))
                + PrometheusText.capture(shipper.captureShipped(), shipper.captureStripped(),
                    shipper.spoolAllowsRedacted());
            byte[] body = text.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/plain; version=0.0.4; charset=utf-8");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.createContext("/ready", exchange -> {
            int status = engine.available() ? 200 : 503;
            exchange.sendResponseHeaders(status, -1);
            exchange.close();
        });
        server.createContext(DRAIN_PATH, exchange -> {
            String method = exchange.getRequestMethod();
            if (!"GET".equals(method) && !"POST".equals(method)) {
                exchange.sendResponseHeaders(405, -1);
                exchange.close();
                return;
            }
            engine.startDraining();
            IcapServer.sleepUntil(engine.drainingSinceNanos(), drainServeMillis);
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        server.start();
    }

    public int port() {
        return server.getAddress().getPort();
    }

    @Override
    public void close() {
        server.stop(0);
        handlers.shutdownNow();
    }
}
