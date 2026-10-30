package io.rwsafe.dataplane.boot;

import io.rwsafe.dataplane.controlplane.EventShipper;
import io.rwsafe.dataplane.controlplane.SnapshotPoller;
import io.rwsafe.dataplane.events.BoundedEventQueue;
import io.rwsafe.dataplane.server.IcapEngine;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * The data plane's termination inside {@code terminationGracePeriodSeconds: 30} (DEPLOY_AND_SHARED_HOST_RUNBOOK §1.2, PR 18
 * review D-02). The preStop hook ({@code /admin/drain}) starts the drain and holds for the 15 s serve window; SIGTERM then
 * runs this sequence, every bound counted from the drain's start:
 * <pre>
 *   drain: served with Connection: close, then refused; ends at zero in flight  IcapServer.DRAIN_TOTAL_MILLIS 20 s
 *   listeners closed, event loops stopped                                        IcapServer.CLOSE_MILLIS        3 s
 *   the drain's verdict events posted to the control plane (or spooled)          EVENT_FLUSH_MILLIS             5 s
 *   margin before the kubelet's SIGKILL                                          MARGIN_MILLIS                  2 s
 * </pre>
 */
final class ShutdownSequence {

    /** The Deployment's terminationGracePeriodSeconds (deploy/rwsafe/base/30-dataplane.yaml, Deployment rwsafe-icap). */
    static final long GRACE_MILLIS = 30_000;
    static final long EVENT_FLUSH_MILLIS = 5_000;
    static final long MARGIN_MILLIS = 2_000;

    private ShutdownSequence() {
    }

    static void run(IcapEngine engine, IcapServer server, MetricsEndpoint metrics, BoundedEventQueue queue,
                    EventShipper shipper, Thread shipperThread, SnapshotPoller poller) {
        server.close();
        metrics.close();
        long hardEnd = engine.drainingSinceNanos() + TimeUnit.MILLISECONDS.toNanos(GRACE_MILLIS - MARGIN_MILLIS);
        long flush = Math.min(TimeUnit.MILLISECONDS.toNanos(EVENT_FLUSH_MILLIS), Math.max(0, hardEnd - System.nanoTime()));
        flushEvents(queue, shipper, shipperThread, Duration.ofNanos(flush));
        if (poller != null) {
            poller.stop();
        }
    }

    /**
     * The drain's last verdict events: for the first half of the bound the running shipper posts them to the control
     * plane (the runbook rolls the control plane first, so it is up); then the shipper is stopped with the rest of the
     * bound (spool or one last post, then counted lost). Returns within the bound plus scheduling slack.
     */
    static void flushEvents(BoundedEventQueue queue, EventShipper shipper, Thread shipperThread, Duration bound) {
        long start = System.nanoTime();
        long end = start + bound.toNanos();
        long postUntil = start + bound.toNanos() / 2;
        while (queue.size() > 0 && System.nanoTime() - postUntil < 0) {
            IcapServer.sleepUntil(System.nanoTime(), 20);
        }
        shipper.stop(Duration.ofNanos(Math.max(0, end - System.nanoTime())));
        try {
            shipperThread.join(Math.max(1, TimeUnit.NANOSECONDS.toMillis(end - System.nanoTime())));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
