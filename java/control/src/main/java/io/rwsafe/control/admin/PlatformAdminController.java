package io.rwsafe.control.admin;

import io.rwsafe.control.admin.PlatformViews.ChannelView;
import io.rwsafe.control.admin.PlatformViews.LogCountView;
import io.rwsafe.control.admin.PlatformViews.LogEventView;
import io.rwsafe.control.admin.PlatformViews.LogsView;
import io.rwsafe.control.admin.PlatformViews.NotificationsView;
import io.rwsafe.control.admin.PlatformViews.SwitchesView;
import io.rwsafe.control.admin.PlatformViews.SystemView;
import io.rwsafe.control.config.ControlProperties;
import io.rwsafe.control.ops.LogRing;
import io.rwsafe.control.privacy.IdentifierCheck;
import io.rwsafe.control.privacy.PrivacyKeys;
import io.rwsafe.control.siem.SiemExportService;
import io.rwsafe.persistence.Database;
import java.lang.management.ManagementFactory;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Administration -> Platform (PO decision Q-47 decision 1.4): System (version and build facts, the switches that matter),
 * System logs (classes and counts, never a message; AGENTS.md 4.14) and Notifications (the outbound channels that exist,
 * never an address). Read only; a {@code security_admin} session that is not masked (AccessRules {@code admin.access}).
 */
@RestController
@RequestMapping("/api/v1/admin")
public class PlatformAdminController {

    private final ControlProperties properties;
    private final Database database;
    private final LogRing logs;
    private final SiemExportService siem;
    private final PrivacyKeys keys;
    private final String commit;
    private final Instant buildTime;
    private final Clock clock;

    public PlatformAdminController(ControlProperties properties, Database database, LogRing logs,
                                   SiemExportService siem, PrivacyKeys keys,
                                   @Value("${rwsafe.build.commit:}") String commit,
                                   @Value("${rwsafe.build.time:}") String buildTime) {
        this.properties = properties;
        this.database = database;
        this.logs = logs;
        this.siem = siem;
        this.keys = keys;
        this.commit = commit(commit);
        this.buildTime = buildTime(buildTime);
        this.clock = Clock.systemUTC();
    }

    @GetMapping("/system")
    public SystemView system() {
        Instant started = Instant.ofEpochMilli(ManagementFactory.getRuntimeMXBean().getStartTime());
        Instant now = clock.instant();
        ControlProperties.Capture capture = properties.capture();
        return new SystemView(SiemExportService.productVersion(), commit, buildTime, Runtime.version().toString(),
            database.schemaVersion(), started, Math.max(0, Duration.between(started, now).toSeconds()),
            new SwitchesView(properties.policy().singleApproval(), properties.identity().breakGlass().enabled(),
                properties.identity().ldap().configured(), capture.redacted() ? "redacted" : "off",
                properties.siem().enabled()));
    }

    @GetMapping("/logs")
    public LogsView logs() {
        List<LogCountView> counts = logs.counts().stream().map(LogCountView::of).toList();
        // A kept template passes the identifier and estate checks once more; without the dictionary none is shown.
        List<String> terms = keys.maskingAvailable() ? keys.estateTerms() : null;
        List<LogEventView> recent = new ArrayList<>();
        for (LogRing.Event e : logs.recent()) {
            String t = e.template();
            boolean show = t != null && terms != null && !IdentifierCheck.identifierShape(t)
                && !IdentifierCheck.containsTerm(t, terms);
            recent.add(new LogEventView(e.at(), e.level(), e.logger(), e.own(), e.exceptionClass(), show ? t : null));
        }
        return new LogsView(logs.since(), LogRing.HOURS, clock.instant(), logs.capturing(), counts, recent);
    }

    @GetMapping("/notifications")
    public NotificationsView notifications() {
        ControlProperties.Siem config = properties.siem();
        String format = config.syslog().format();
        List<ChannelView> destinations = List.of(
            new ChannelView("syslog", Set.of("cef", "leef").contains(format) ? format : null,
                config.syslog().configured()),
            new ChannelView("hec", null, config.hec().configured()));
        String state = siem.health().state();
        return new NotificationsView(config.enabled(), "UNKNOWN".equals(state) ? "OFF" : state, destinations, false);
    }

    /** A hexadecimal commit id of 7 to 40 characters; anything else is not shown. */
    static String commit(String s) {
        String v = s == null ? "" : s.strip().toLowerCase(java.util.Locale.ROOT);
        return v.length() >= 7 && v.length() <= 40 && v.chars().allMatch(c -> (c >= '0' && c <= '9')
            || (c >= 'a' && c <= 'f')) ? v : null;
    }

    /** An ISO-8601 instant; anything else is not shown. */
    static Instant buildTime(String s) {
        if (s == null || s.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(s.strip());
        } catch (DateTimeParseException e) {
            return null;
        }
    }
}
