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

/** {@code GET /metrics} (Prometheus text) and {@code GET /ready} (200 or 503) on a separate port; no content ever. */
public final class MetricsEndpoint implements AutoCloseable {

    private final HttpServer server;

    public MetricsEndpoint(String host, int port, IcapEngine engine, BoundedEventQueue queue, EventShipper shipper,
                           SnapshotPoller poller) throws IOException {
        server = HttpServer.create(new InetSocketAddress(host, port), 16);
        server.createContext("/metrics", exchange -> {
            IcapEngine.Policy p = engine.policy();
            String text = PrometheusText.render(engine.metrics(), new PrometheusText.Gauges(
                engine.admission().inflight(), engine.admission().bodyBytesHeld(), engine.admission().identityCapped(),
                engine.admission().engineFull(), engine.admission().bodyBudgetRejections(), queue.size(),
                queue.dropped(), shipper.spoolBytes(), p == null ? 0 : p.snapshot().version(), engine.available(),
                poller == null ? Map.of() : poller.refusals()));
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
        server.start();
    }

    public int port() {
        return server.getAddress().getPort();
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
