package io.rwsafe.control.admin;

import io.rwsafe.control.ops.LogRing;
import io.rwsafe.control.privacy.MaskedView;
import io.rwsafe.control.privacy.TextMasker;
import java.time.Instant;
import java.util.List;

/**
 * The bodies of Administration -> Platform (PO decision Q-47 decision 1.4): build and version facts, the control plane's
 * own log as classes and counts, and the outbound channels. Only a {@code security_admin} session reaches these routes
 * (AccessRules {@code admin.access}); none carries a name, an address or a body, so the masked projections (for the
 * funnel's coverage rule) withhold the one free value, a log template.
 */
public final class PlatformViews {

    private PlatformViews() {
    }

    /**
     * The switches that change what the product does. The directory facts come from the stored settings
     * ({@code DirectorySettingsService}, PR 50), never the deploy's values, and never a URL, a DN or a group:
     * {@code directoryConfigured} a stored version exists, {@code directoryEnabled} it is switched on,
     * {@code directoryKeyPresent} the bind-password key is mounted and usable, {@code directoryStatus} the sign-in
     * front's state ({@code ACTIVE}, {@code DISABLED}, {@code NOT_CONFIGURED}, {@code UNAVAILABLE}).
     * {@code captureMode} is {@code off} or {@code redacted}.
     */
    public record SwitchesView(boolean singleApproval, boolean breakGlassSignIn, boolean directoryConfigured,
                               boolean directoryEnabled, boolean directoryKeyPresent, String directoryStatus,
                               String captureMode, boolean siemExport) {
    }

    /**
     * Version and build facts. {@code commit} and {@code buildTime} are null when the image does not carry them
     * ({@code RWSAFE_BUILD_COMMIT}, {@code RWSAFE_BUILD_TIME}); {@code schemaVersion} is the Flyway version applied at
     * this start.
     */
    public record SystemView(String version, String commit, Instant buildTime, String javaVersion,
                             String schemaVersion, Instant startedAt, long uptimeSeconds, SwitchesView switches)
        implements MaskedView {

        @Override
        public SystemView masked(TextMasker masker) {
            return this;
        }
    }

    public record LogCountView(String level, String logger, boolean own, long count) {

        static LogCountView of(LogRing.Count c) {
            return new LogCountView(c.level(), c.logger(), c.own(), c.count());
        }
    }

    /** {@code template} null: not shown (a third-party logger, not fixed text, or it failed the identifier check). */
    public record LogEventView(Instant at, String level, String logger, boolean own, String exceptionClass,
                               String template) {
    }

    /**
     * {@code counts} over the last {@code windowHours} hours since {@code since} (this instance's start);
     * {@code capturing} false when the appender could not attach (then both lists stay empty).
     */
    public record LogsView(Instant since, int windowHours, Instant checkedAt, boolean capturing,
                           List<LogCountView> counts, List<LogEventView> recent) implements MaskedView {

        @Override
        public LogsView masked(TextMasker masker) {
            return new LogsView(since, windowHours, checkedAt, capturing, counts, recent.stream()
                .map(e -> new LogEventView(e.at(), e.level(), e.logger(), e.own(), e.exceptionClass(), null)).toList());
        }
    }

    /** One SIEM destination by kind ({@code syslog}, {@code hec}) and, for syslog, its format; never its address. */
    public record ChannelView(String kind, String format, boolean configured) {
    }

    /**
     * What leaves the product today: the SIEM export ({@code siemState} as on the health screen: {@code UP},
     * {@code DEGRADED}, {@code DOWN}, or {@code OFF}) and its destinations by kind. E-mail notifications do not exist
     * yet ({@code emailAvailable} false).
     */
    public record NotificationsView(boolean siemEnabled, String siemState, List<ChannelView> siemDestinations,
                                    boolean emailAvailable) implements MaskedView {

        @Override
        public NotificationsView masked(TextMasker masker) {
            return this;
        }
    }
}
