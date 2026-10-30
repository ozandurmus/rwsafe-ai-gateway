package io.rwsafe.dataplane.metrics;

import io.rwsafe.platform.verdict.Verdict;
import java.util.Locale;
import java.util.Map;

/** Renders the engine's counters and gauges in the Prometheus text format (ICAP spec §8 names). */
public final class PrometheusText {

    /** Values the renderer reads from the engine, the queue, the shipper and the snapshot poller. */
    public record Gauges(int inflight, long bodyBytesHeld, long identityCapped, long engineFull, long bodyBudgetRejections,
                         int queueDepth, long queueDropped, long spoolBytes, long snapshotVersion, boolean ready,
                         Map<String, Long> snapshotRefusals) {
    }

    private PrometheusText() {
    }

    public static String render(EngineMetrics m, Gauges g) {
        StringBuilder s = new StringBuilder(4096);
        s.append("# TYPE icap_transactions_total counter\n");
        for (EngineMetrics.Method method : EngineMetrics.Method.values()) {
            for (Verdict v : Verdict.values()) {
                s.append("icap_transactions_total{method=\"").append(method.name().toLowerCase(Locale.ROOT))
                    .append("\",verdict=\"").append(v.name()).append("\"} ").append(m.transactions(method, v)).append('\n');
            }
        }
        gauge(s, "icap_inflight", g.inflight());
        gauge(s, "icap_fullbody_bytes", g.bodyBytesHeld());
        counter(s, "icap_inflight_by_identity_capped_total", g.identityCapped());
        counter(s, "icap_engine_full_total", g.engineFull());
        counter(s, "icap_fullbody_semaphore_rejections_total", g.bodyBudgetRejections());
        gauge(s, "icap_queue_depth", g.queueDepth());
        counter(s, "icap_queue_dropped_total", g.queueDropped());
        gauge(s, "icap_spool_bytes", g.spoolBytes());
        gauge(s, "icap_snapshot_version", g.snapshotVersion());
        gauge(s, "icap_ready", g.ready() ? 1 : 0);
        s.append("# TYPE icap_snapshot_refused_total counter\n");
        for (Map.Entry<String, Long> e : g.snapshotRefusals().entrySet()) {
            s.append("icap_snapshot_refused_total{reason=\"").append(token(e.getKey())).append("\"} ")
                .append(e.getValue()).append('\n');
        }
        return s.toString();
    }

    private static void gauge(StringBuilder s, String name, long v) {
        s.append("# TYPE ").append(name).append(" gauge\n").append(name).append(' ').append(v).append('\n');
    }

    private static void counter(StringBuilder s, String name, long v) {
        s.append("# TYPE ").append(name).append(" counter\n").append(name).append(' ').append(v).append('\n');
    }

    /** Reasons are fixed tokens; anything else is reduced to letters, digits and underscores. */
    private static String token(String raw) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < raw.length() && i < 40; i++) {
            char c = raw.charAt(i);
            if (Character.isLetterOrDigit(c) || c == '_') {
                out.append(c);
            }
        }
        return out.toString();
    }
}
