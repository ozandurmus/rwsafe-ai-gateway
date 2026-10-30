package io.rwsafe.dataplane.boot;

import io.rwsafe.dataplane.controlplane.EventShipper;
import io.rwsafe.dataplane.events.BoundedEventQueue;
import io.rwsafe.dataplane.server.EngineConfig;
import io.rwsafe.dataplane.server.IcapEngine;
import io.rwsafe.detect.DetectorSet;
import io.rwsafe.policy.Snapshots;
import java.net.URI;

/**
 * Entry point of the {@code rwsafe-dataplane} image (ICAP role). Configuration from the environment:
 * {@code RWSAFE_ICAP_BIND} (default {@code 0.0.0.0}), {@code RWSAFE_ICAP_PORT} (default 1344, plain ICAP under exception
 * H-2) and {@code RWSAFE_CONTROL_EVENTS_URL} (the control plane's verdict-event endpoint; unset runs stand-alone).
 *
 * <p>The policy is the built-in development snapshot until the signed snapshot pull from the control plane lands.
 */
public final class DataPlaneApplication {

    private DataPlaneApplication() {
    }

    public static void main(String[] args) throws InterruptedException {
        String bind = env("RWSAFE_ICAP_BIND", "0.0.0.0");
        int port = Integer.parseInt(env("RWSAFE_ICAP_PORT", "1344"));
        String events = System.getenv("RWSAFE_CONTROL_EVENTS_URL");

        BoundedEventQueue queue = new BoundedEventQueue(10_000);
        EventShipper shipper = new EventShipper(queue, events == null || events.isBlank() ? null : URI.create(events));
        Thread shipperThread = new Thread(shipper, "rwsafe-event-shipper");
        shipperThread.setDaemon(true);
        shipperThread.start();

        IcapEngine engine = new IcapEngine(Snapshots.builtinDevelopment(), DetectorSet.standard(), queue,
            EngineConfig.defaults());
        IcapServer server = new IcapServer(engine);
        server.start(bind, port);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            server.close();
            shipper.stop();
        }, "rwsafe-shutdown"));
        server.awaitClose();
    }

    private static String env(String name, String fallback) {
        String v = System.getenv(name);
        return v == null || v.isBlank() ? fallback : v;
    }
}
