package io.rwsafe.control.siem;

import io.rwsafe.control.config.ControlProperties;
import io.rwsafe.control.privacy.Masking;
import io.rwsafe.control.privacy.PrivacyKeys;
import io.rwsafe.control.privacy.Pseudonymiser;
import io.rwsafe.control.privacy.TextMasker;
import io.rwsafe.control.siem.SiemDeliveryException.Reason;
import io.rwsafe.control.siem.SiemField.SiemStream;
import io.rwsafe.control.siem.SiemFormats.LineFormat;
import io.rwsafe.persistence.Database;
import java.time.Duration;
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
 * Fail closed (AGENTS.md 4.10, PR 23 review D-3): without rwsafe's privacy key or the estate dictionary no exporter
 * starts, since row keys could be neither pseudonymised nor checked. A destination whose configuration is incomplete or
 * unsafe (no CA bundle, no token, a non-HTTPS URL, an unknown format, a host name that is not a plain name) is not
 * started either. Both show on the health screen as {@code DOWN} with the fixed reason: nothing is ever sent in clear,
 * unmasked or to an unverified receiver (SR-SIEM-3).
 *
 * <p>Audit durability (PO decision Q-SIEM-2): both sinks are supported; only HEC acknowledges each batch, so a deployment
 * that relies on the SIEM copy of the audit ledger uses HEC (alone or beside syslog). Syslog batches whose connection the
 * receiver closed after the flush are counted as possibly lost and shown.
 */
@Component
public class SiemExportService implements SmartLifecycle {

    static final Duration BACKLOG_INTERVAL = Duration.ofSeconds(30);
    /** A backlog that moves no watermark for this long is a stall (D-11); above the 2 min back-off ceiling. */
    static final Duration STALL_AFTER = Duration.ofMinutes(3);
    private static final Logger LOG = LoggerFactory.getLogger(SiemExportService.class);

    private final ControlProperties.Siem config;
    private final Database database;
    private final PrivacyKeys keys;
    private final Pseudonymiser pseudonymiser;
    private final List<SiemExporter> exporters = new ArrayList<>();
    private final Map<String, String> refused = new LinkedHashMap<>();
    private volatile boolean running;

    public SiemExportService(ControlProperties properties, Database database, PrivacyKeys keys,
                             Pseudonymiser pseudonymiser) {
        this.config = properties.siem();
        this.database = database;
        this.keys = keys;
        this.pseudonymiser = pseudonymiser;
    }

    @Override
    public synchronized void start() {
        running = true;
        if (!config.enabled()) {
            return;
        }
        if (!keys.keyAvailable() || !keys.maskingAvailable()) {
            refuse("siem", "the privacy key or the estate dictionary is missing; nothing is exported");
            return;
        }
        Masking masking = new Masking(keys, pseudonymiser);
        if (!masking.available()) {
            refuse("siem", "the name dictionary is missing; nothing is exported");
            return;
        }
        TextMasker masker = masking.masker();
        if (!config.syslog().configured() && !config.hec().configured()) {
            refuse("siem", "export is enabled but no destination is set");
            return;
        }
        String host = config.syslog().hostname();
        if (!plainHostLabel(host)) {
            refuse("siem", "the exporter host name is not a plain lower-case name");
            return;
        }
        SiemRecords records = new SiemRecords(pseudonymiser::user, key -> pseudonymiser.token("KEY", key),
            keys.estateTerms(), masker::maskFreeText);
        if (records.estate(host)) {
            refuse("siem", "the exporter host name contains an estate term");
            return;
        }
        SiemExporter.Settings settings = new SiemExporter.Settings(config.pollInterval(), config.queueCapacity(),
            config.pageSize(), config.batchSize(), config.backoffInitial(), config.backoffMax(),
            config.startFrom().equals("latest"), BACKLOG_INTERVAL, STALL_AFTER);
        if (config.syslog().configured()) {
            build("syslog", () -> syslogSink(config.syslog()), records, settings);
        }
        if (config.hec().configured()) {
            String index = config.hec().index();
            if (index != null && !index.isBlank() && records.estate(index)) {
                refuse("hec", "the HEC index contains an estate term");
            } else {
                build("hec", () -> hecSink(config.hec(), host), records, settings);
            }
        }
        exporters.forEach(SiemExporter::start);
    }

    private void refuse(String destination, String reason) {
        refused.put(destination, reason);
        LOG.warn("SIEM export to {} is not started: {}", destination, reason);
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
            refuse(destination, e.getMessage());
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
        if (!index.isEmpty() && !SiemRecords.plain(index, 80)) {
            throw new IllegalArgumentException("the HEC index is not a plain name");
        }
        return new HecSink(c.url(), c.tokenFile(), SiemTls.clientContext(c.caFile()), host, index, c.timeout());
    }

    /** The RFC 5424 HOSTNAME and HEC {@code host} the exporter writes: a lower-case label, a product name. */
    static boolean plainHostLabel(String s) {
        return s != null && !s.isEmpty() && s.length() <= 63 && s.charAt(0) >= 'a' && s.charAt(0) <= 'z'
            && s.chars().allMatch(c -> (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-');
    }

    /** The build's version, cleaned for a CEF/LEEF header; {@code dev} outside a packaged build. */
    static String productVersion() {
        String v = SiemExportService.class.getPackage().getImplementationVersion();
        String cleaned = SiemText.clean(v == null ? "dev" : v, 32);
        boolean plain = !cleaned.isEmpty()
            && cleaned.chars().allMatch(c -> Character.isLetterOrDigit(c) || c == '.' || c == '-' || c == '_');
        return plain ? cleaned : "dev";
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
     * One health line: {@code UP}, {@code DEGRADED} (a destination's reader or sender is retrying after a failure),
     * {@code DOWN} (export refused at start) or {@code UNKNOWN} (export off), and a fixed-vocabulary detail with the
     * backlog, the queue, possibly lost syslog batches and a {@code latest} start's skip count.
     * {@code counts} (PR 28 review D-03) carries the same facts as numbers under {@code <destination>.<name>} keys:
     * {@code notStarted}, {@code delivered}, {@code backlog} (absent until counted), {@code queueDepth},
     * {@code queueCapacity}, {@code stalled} (0/1), {@code heldBehindOpenTransaction}, {@code possiblyLostBatches},
     * {@code skippedAtStart}, and {@code readerFailure.<class>} / {@code senderFailure.<class>} set to 1 while retrying.
     */
    public record Health(String state, String detail, Map<String, Long> counts) {

        public Health(String state, String detail) {
            this(state, detail, Map.of());
        }
    }

    public synchronized Health health() {
        if (!config.enabled()) {
            return new Health("UNKNOWN", "SIEM export is off");
        }
        List<String> details = new ArrayList<>();
        Map<String, Long> counts = new LinkedHashMap<>();
        boolean down = !refused.isEmpty();
        boolean degraded = false;
        refused.forEach((destination, reason) -> {
            details.add(destination + ": not started, " + reason);
            counts.put(destination + ".notStarted", 1L);
        });
        for (SiemExporter e : exporters) {
            SiemMetrics m = e.metrics();
            String key = e.destination() + ".";
            StringBuilder d = new StringBuilder(e.destination()).append(": ");
            Reason read = m.readFailure();
            Reason send = m.sendFailure();
            counts.put(key + "delivered", m.exported(SiemStream.VERDICT) + m.exported(SiemStream.AUDIT));
            if (m.backlog() >= 0) {
                counts.put(key + "backlog", m.backlog());
            }
            counts.put(key + "queueDepth", (long) m.queueDepth());
            counts.put(key + "queueCapacity", (long) m.queueCapacity());
            counts.put(key + "stalled", m.stalled() ? 1L : 0L);
            counts.put(key + "heldBehindOpenTransaction", m.heldBehindOpenTransaction());
            counts.put(key + "possiblyLostBatches", m.possiblyLostBatches());
            counts.put(key + "skippedAtStart", m.skippedAtStart());
            if (read != null) {
                counts.put(key + "readerFailure." + read.name().toLowerCase(Locale.ROOT), 1L);
            }
            if (send != null) {
                counts.put(key + "senderFailure." + send.name().toLowerCase(Locale.ROOT), 1L);
            }
            if (m.stalled()) {
                degraded = true;
                d.append("stalled: no progress for over ").append(STALL_AFTER.toSeconds()).append(" s with ")
                    .append(m.heldBehindOpenTransaction()).append(" rows held behind an open database transaction, ");
            }
            if (read != null || send != null) {
                degraded = true;
                d.append("retrying after a failure (");
                if (read != null) {
                    d.append("reader ").append(read.name().toLowerCase(Locale.ROOT));
                }
                if (send != null) {
                    d.append(read != null ? ", " : "").append("sender ").append(send.name().toLowerCase(Locale.ROOT));
                }
                d.append("), ");
            }
            d.append(m.exported(SiemStream.VERDICT) + m.exported(SiemStream.AUDIT)).append(" events delivered, backlog ")
                .append(m.backlog() < 0 ? "not counted yet" : Long.toString(m.backlog())).append(", queue ")
                .append(m.queueDepth()).append('/').append(m.queueCapacity());
            if (m.possiblyLostBatches() > 0) {
                d.append(", ").append(m.possiblyLostBatches()).append(" batches possibly lost (connection closed after "
                    + "the flush)");
            }
            if (m.skippedAtStart() > 0) {
                d.append(", ").append(m.skippedAtStart()).append(" verdict events skipped at a latest start");
            }
            details.add(d.toString());
        }
        return new Health(down ? "DOWN" : degraded ? "DEGRADED" : "UP", String.join("; ", details), counts);
    }

    /** The exporters' metrics in Prometheus text (fixed labels). */
    public synchronized String prometheus() {
        StringBuilder s = new StringBuilder();
        exporters.forEach(e -> s.append(e.metrics().prometheus()));
        return s.toString();
    }
}
