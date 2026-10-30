package io.rwsafe.control.siem;

import io.rwsafe.control.config.ControlProperties;
import io.rwsafe.control.privacy.Pseudonymiser;
import io.rwsafe.control.siem.SiemDeliveryException.Reason;
import io.rwsafe.control.siem.SiemField.SiemStream;
import io.rwsafe.control.siem.SiemFormats.LineFormat;
import io.rwsafe.persistence.Database;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.SmartLifecycle;
import org.springframework.stereotype.Component;

/**
 * Starts one {@link SiemExporter} per configured destination after the context is up and stops it first at shutdown.
 * A destination whose configuration is incomplete or unsafe (no CA bundle, no token, a non-HTTPS URL, an unknown format)
 * is not started and shows on the health screen with the fixed reason: nothing is ever sent in clear or to an unverified
 * receiver (SR-SIEM-3, AGENTS.md 4.10).
 */
@Component
public class SiemExportService implements SmartLifecycle {

    private static final Logger LOG = LoggerFactory.getLogger(SiemExportService.class);

    private final ControlProperties.Siem config;
    private final Database database;
    private final Pseudonymiser pseudonymiser;
    private final List<SiemExporter> exporters = new ArrayList<>();
    private final Map<String, String> refused = new LinkedHashMap<>();
    private volatile boolean running;

    public SiemExportService(ControlProperties properties, Database database, Pseudonymiser pseudonymiser) {
        this.config = properties.siem();
        this.database = database;
        this.pseudonymiser = pseudonymiser;
    }

    @Override
    public synchronized void start() {
        running = true;
        if (!config.enabled()) {
            return;
        }
        SiemRecords records = new SiemRecords(pseudonymiser::user);
        SiemExporter.Settings settings = new SiemExporter.Settings(config.pollInterval(), config.settle(),
            config.queueCapacity(), config.pageSize(), config.batchSize(), config.backoffInitial(),
            config.backoffMax(), config.startFrom().equals("latest"));
        if (config.syslog().configured()) {
            build("syslog", () -> syslogSink(config.syslog()), records, settings);
        }
        if (config.hec().configured()) {
            build("hec", () -> hecSink(config.hec(), config.syslog().hostname()), records, settings);
        }
        if (!config.syslog().configured() && !config.hec().configured()) {
            refused.put("siem", "export is enabled but no destination is set");
        }
        exporters.forEach(SiemExporter::start);
    }

    private interface SinkFactory {
        SiemSink create();
    }

    private void build(String destination, SinkFactory factory, SiemRecords records, SiemExporter.Settings settings) {
        try {
            exporters.add(new SiemExporter(factory.create(), database.siemExport(), records, settings,
                new SiemMetrics(destination, settings.queueCapacity())));
        } catch (IllegalStateException | IllegalArgumentException e) {
            // Our own fixed sentences only (SiemTls, HecSink, this class): no value, path or host is in them.
            refused.put(destination, e.getMessage());
            LOG.warn("SIEM export to {} is not started: {}", destination, e.getMessage());
        }
    }

    static SiemSink syslogSink(ControlProperties.Syslog c) {
        LineFormat format = switch (c.format()) {
            case "cef" -> LineFormat.CEF;
            case "leef" -> LineFormat.LEEF;
            default -> throw new IllegalArgumentException("the syslog format is cef or leef");
        };
        if (c.port() < 1 || c.port() > 65_535 || c.facility() < 0 || c.facility() > 23) {
            throw new IllegalArgumentException("the syslog port or facility is out of range");
        }
        return new SyslogTlsSink(c.host().strip(), c.port(), format, SiemTls.clientContext(c.caFile()), c.hostname(),
            c.facility(), productVersion(), c.connectTimeout(), c.writeTimeout());
    }

    static SiemSink hecSink(ControlProperties.Hec c, String host) {
        String index = c.index() == null ? "" : c.index().strip();
        if (!index.isEmpty() && !SiemRecords.token(index, 80)) {
            throw new IllegalArgumentException("the HEC index is not a plain name");
        }
        return new HecSink(c.url(), c.tokenFile(), SiemTls.clientContext(c.caFile()), host, index, c.timeout());
    }

    /** The build's version, cleaned for a CEF/LEEF header; {@code dev} outside a packaged build. */
    static String productVersion() {
        String v = SiemExportService.class.getPackage().getImplementationVersion();
        String cleaned = SiemText.clean(v == null ? "dev" : v, 32);
        return SiemRecords.token(cleaned, 32) ? cleaned : "dev";
    }

    @Override
    public synchronized void stop() {
        exporters.forEach(SiemExporter::stop);
        running = false;
    }

    @Override
    public boolean isRunning() {
        return running;
    }

    /** Stops before the data source closes (the default phase stops last-started first). */
    @Override
    public int getPhase() {
        return Integer.MAX_VALUE - 100;
    }

    /**
     * One health line: {@code UP}, {@code DEGRADED} (a destination is retrying after a failure), {@code DOWN} (a
     * destination was refused at start) or {@code UNKNOWN} (export off), and a fixed-vocabulary detail.
     */
    public record Health(String state, String detail) {
    }

    public synchronized Health health() {
        if (!config.enabled()) {
            return new Health("UNKNOWN", "SIEM export is off");
        }
        List<String> details = new ArrayList<>();
        boolean down = !refused.isEmpty();
        boolean degraded = false;
        refused.forEach((destination, reason) -> details.add(destination + ": not started, " + reason));
        for (SiemExporter e : exporters) {
            SiemMetrics m = e.metrics();
            Reason failure = m.lastFailure();
            long sent = m.exported(SiemStream.VERDICT) + m.exported(SiemStream.AUDIT);
            if (failure != null) {
                degraded = true;
                details.add(e.destination() + ": retrying after a failure (" + failure.name().toLowerCase(Locale.ROOT)
                    + "), queue " + m.queueDepth() + "/" + m.queueCapacity());
            } else {
                details.add(e.destination() + ": " + sent + " events delivered, queue " + m.queueDepth() + "/"
                    + m.queueCapacity());
            }
        }
        return new Health(down ? "DOWN" : degraded ? "DEGRADED" : "UP", String.join("; ", details));
    }

    /** The exporters' metrics in Prometheus text (fixed labels). */
    public synchronized String prometheus() {
        StringBuilder s = new StringBuilder();
        exporters.forEach(e -> s.append(e.metrics().prometheus()));
        return s.toString();
    }
}
