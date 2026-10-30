package io.rwsafe.dataplane.boot;

import io.rwsafe.dataplane.controlplane.EventShipper;
import io.rwsafe.dataplane.controlplane.SnapshotPoller;
import io.rwsafe.dataplane.events.BoundedEventQueue;
import io.rwsafe.dataplane.server.EngineConfig;
import io.rwsafe.dataplane.server.IcapEngine;
import io.rwsafe.detect.DetectorSet;
import io.rwsafe.policy.SnapshotVerifier;
import io.rwsafe.policy.Snapshots;
import java.io.File;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Entry point of the {@code rwsafe-dataplane} image (ICAP role). Configuration from the environment (deploy manifests
 * set it; docs/operations/LOCAL_RUN.md lists it):
 * <ul>
 *   <li>{@code RWSAFE_ICAP_BIND} (default 0.0.0.0), {@code RWSAFE_ICAP_PORT} (default 1344, plain ICAP under H-2;
 *       {@code 0} disables the plain listener)</li>
 *   <li>{@code RWSAFE_ICAPS_PORT} (default 11344) with {@code RWSAFE_TLS_CERT}, {@code RWSAFE_TLS_KEY} (PKCS#8 PEM) and
 *       {@code RWSAFE_TLS_CLIENT_CA}: Secure ICAP with a required client certificate; unset, no TLS listener</li>
 *   <li>{@code RWSAFE_SNAPSHOT_URL}, {@code RWSAFE_SNAPSHOT_PUBLIC_KEYS} (comma-separated {@code <key id>.pem} files),
 *       {@code RWSAFE_SNAPSHOT_CACHE} (directory): the signed policy pull; unset, the built-in development snapshot</li>
 *   <li>{@code RWSAFE_CONTROL_EVENTS_URL} and {@code RWSAFE_SPOOL_DIR}: verdict events and their spool</li>
 *   <li>{@code RWSAFE_METRICS_PORT} (default 9401, PORTS_AND_RESOURCES §3; {@code /metrics}, {@code /ready} and the
 *       preStop drain {@code /admin/drain}), {@code RWSAFE_SHARED_ADDRESS_PREFIXES} (comma-separated)</li>
 * </ul>
 */
public final class DataPlaneApplication {

    private DataPlaneApplication() {
    }

    public static void main(String[] args) throws Exception {
        String bind = env("RWSAFE_ICAP_BIND", "0.0.0.0");
        String cert = System.getenv("RWSAFE_TLS_CERT");
        // With Secure ICAP configured, plain ICAP (H-2) runs only when RWSAFE_ICAP_PORT asks for it (D-09).
        int port = Integer.parseInt(env("RWSAFE_ICAP_PORT", blank(cert) ? "1344" : "0"));
        EngineConfig config = EngineConfig.defaults()
            .withAdmission(1000, 32, 256, list(env("RWSAFE_SHARED_ADDRESS_PREFIXES", "")));

        BoundedEventQueue queue = new BoundedEventQueue(10_000);
        String events = System.getenv("RWSAFE_CONTROL_EVENTS_URL");
        String spool = System.getenv("RWSAFE_SPOOL_DIR");
        EventShipper shipper = new EventShipper(queue, blank(events) ? null : URI.create(events),
            blank(spool) ? null : Path.of(spool), 256L * 1024 * 1024, Duration.ofSeconds(1));
        Thread shipperThread = new Thread(shipper, "rwsafe-event-shipper");
        shipperThread.start();

        String snapshotUrl = System.getenv("RWSAFE_SNAPSHOT_URL");
        IcapEngine engine = new IcapEngine(blank(snapshotUrl) ? Snapshots.builtinDevelopment() : null,
            DetectorSet.standard(), queue, config);
        SnapshotPoller poller = null;
        if (!blank(snapshotUrl)) {
            Map<String, PublicKey> keys = new HashMap<>();
            for (String file : list(env("RWSAFE_SNAPSHOT_PUBLIC_KEYS", ""))) {
                Path f = Path.of(file);
                String name = f.getFileName().toString();
                String id = name.endsWith(".pem") ? name.substring(0, name.length() - 4) : name;
                keys.put(id, SnapshotVerifier.publicKeyFromPem(Files.readString(f)));
            }
            String cache = System.getenv("RWSAFE_SNAPSHOT_CACHE");
            poller = new SnapshotPoller(engine, URI.create(snapshotUrl), new SnapshotVerifier(keys),
                blank(cache) ? null : Path.of(cache), Clock.systemUTC(), Duration.ofSeconds(30));
            poller.loadCache();
            daemon(poller, "rwsafe-snapshot-poller");
        }

        IcapServer server = new IcapServer(engine, config.drainServeMillis());
        if (port > 0) {
            server.start(bind, port);
        }
        if (!blank(cert)) {
            server.startSecure(bind, Integer.parseInt(env("RWSAFE_ICAPS_PORT", "11344")), new File(cert),
                new File(System.getenv("RWSAFE_TLS_KEY")), new File(System.getenv("RWSAFE_TLS_CLIENT_CA")));
        }
        MetricsEndpoint metrics = new MetricsEndpoint(bind, Integer.parseInt(env("RWSAFE_METRICS_PORT", "9401")), engine,
            queue, shipper, poller, config.drainServeMillis());
        SnapshotPoller pollerRef = poller;
        // D-01: the queued events of the drain reach the control plane or the spool before the JVM exits; PR 18 review
        // D-02: the whole sequence ends inside the 30 s grace period (ShutdownSequence).
        Runtime.getRuntime().addShutdownHook(new Thread(() -> ShutdownSequence.run(engine, server, metrics, queue, shipper,
            shipperThread, pollerRef), "rwsafe-shutdown"));
        server.awaitClose();
    }

    private static void daemon(Runnable r, String name) {
        Thread t = new Thread(r, name);
        t.setDaemon(true);
        t.start();
    }

    private static List<String> list(String csv) {
        List<String> out = new ArrayList<>();
        for (String s : io.rwsafe.dataplane.icap.Tokens.split(csv, ',')) {
            if (!s.isBlank()) {
                out.add(s.strip());
            }
        }
        return out;
    }

    private static boolean blank(String s) {
        return s == null || s.isBlank();
    }

    private static String env(String name, String fallback) {
        String v = System.getenv(name);
        return blank(v) ? fallback : v;
    }
}
