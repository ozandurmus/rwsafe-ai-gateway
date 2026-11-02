package io.rwsafe.control.admin;

import io.rwsafe.control.identity.DirectorySettingsService;
import io.rwsafe.control.identity.LdapAuthenticator;
import io.rwsafe.control.identity.Roles;
import io.rwsafe.control.privacy.MaskedView;
import io.rwsafe.control.privacy.TextMasker;
import io.rwsafe.persistence.DirectorySettings;
import io.rwsafe.persistence.DirectorySettingsStore;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;

/**
 * The bodies of Administration -> Access -> Directory settings (PO decision Q-47, decision 1.2). Only a
 * {@code security_admin} session reaches these routes (AccessRules {@code admin.access}); the masked projections exist for
 * the funnel's coverage rule and withhold every URL, distinguished name, group name and reason all the same. No body ever
 * carries the bind password: only whether one is set.
 */
public final class DirectoryViews {

    private DirectoryViews() {
    }

    /** The connection fields as entered; {@code newPassword} empty or absent keeps the stored password. */
    public record ConnectionRequest(Integer expectedVersion, Boolean enabled, List<String> urls, String tlsMode,
                                    String caCertificatePem, Boolean clearCaCertificate, String bindDn,
                                    String newPassword, String userSearchBase, String userSearchFilter,
                                    String groupAttribute, String groupSearchBase, String groupSearchFilter,
                                    Integer connectTimeoutMs, Integer responseTimeoutMs, String reason) {

        DirectorySettingsService.Connection connection() {
            return new DirectorySettingsService.Connection(enabled, urls, tlsMode, caCertificatePem,
                Boolean.TRUE.equals(clearCaCertificate), bindDn, newPassword == null ? null : newPassword.toCharArray(),
                userSearchBase, userSearchFilter, groupAttribute, groupSearchBase, groupSearchFilter, connectTimeoutMs,
                responseTimeoutMs);
        }

        @Override
        public String toString() {
            return "ConnectionRequest[redacted]";
        }
    }

    public record GroupRoleEntry(String group, List<String> roles) {

        @Override
        public String toString() {
            return "GroupRoleEntry[" + roles + "]";
        }
    }

    public record GroupRolesRequest(Integer expectedVersion, List<GroupRoleEntry> bindings, String reason) {

        @Override
        public String toString() {
            return "GroupRolesRequest[redacted]";
        }
    }

    /** {@code settings} null tests the saved settings; {@code loginName} optional. */
    public record TestRequest(ConnectionRequest settings, String loginName) {

        @Override
        public String toString() {
            return "TestRequest[redacted]";
        }
    }

    public record GroupRolesView(String group, List<String> roles) {
    }

    /** The active version's fields; the password only as {@code passwordSet}, the CA bundle only as count and expiry. */
    public record SettingsView(boolean enabled, List<String> urls, String tlsMode, int caCertificateCount,
                               Instant caCertificateNotAfter, String bindDn, boolean passwordSet,
                               String userSearchBase, String userSearchFilter, String groupAttribute,
                               String groupSearchBase, String groupSearchFilter, int connectTimeoutMs,
                               int responseTimeoutMs, List<GroupRolesView> groupRoles) {

        static SettingsView of(DirectorySettings s) {
            List<X509Certificate> ca = s.caCertificatePem() == null ? List.of() : certificates(s.caCertificatePem());
            Instant notAfter = ca.stream().map(c -> c.getNotAfter().toInstant()).min(Comparator.naturalOrder())
                .orElse(null);
            return new SettingsView(s.enabled(), s.urls(), s.tlsMode(), ca.size(), notAfter, s.bindDn(),
                s.bindPasswordSealed() != null, s.userSearchBase(), s.userSearchFilter(), s.groupAttribute(),
                s.groupSearchBase(), s.groupSearchFilter(), s.connectTimeoutMs(), s.responseTimeoutMs(),
                s.groupRoles().stream().map(g -> new GroupRolesView(g.group(), g.roles())).toList());
        }

        private static List<X509Certificate> certificates(String pem) {
            try {
                return DirectorySettingsService.certificates(pem);
            } catch (RuntimeException e) {
                return List.of();
            }
        }
    }

    /** One saved version: who (a pseudonym or the system seed), when, what kind of change and the reason. */
    public record HistoryView(int version, Instant createdAt, String actor, String changeKind, String reason) {

        static HistoryView of(DirectorySettingsStore.HistoryEntry h) {
            return new HistoryView(h.version(), h.createdAt(), h.createdBy(), h.changeKind(), h.reason());
        }
    }

    /**
     * The settings page.
     *
     * @param status       {@code ACTIVE}, {@code DISABLED}, {@code NOT_CONFIGURED} or {@code UNAVAILABLE}
     * @param statusReason why it is not active ({@code DIRECTORY_KEY_MISSING}, {@code BIND_PASSWORD_NOT_SET} ...)
     * @param keyState     the directory key: {@code AVAILABLE}, {@code MISSING} or {@code INVALID}
     */
    public record DirectoryView(String status, String statusReason, String keyState, boolean deployValuesPresent,
                                int version, SettingsView settings, List<String> roles, List<HistoryView> history,
                                int maxUrls, int maxGroups, int testsPerMinute) implements MaskedView {

        static DirectoryView of(DirectorySettingsService.State s) {
            return new DirectoryView(s.status().status(), s.status().reason(), s.key().name(), s.deployValuesPresent(),
                s.active().map(DirectorySettings::version).orElse(0), s.active().map(SettingsView::of).orElse(null),
                Roles.ORDERED, s.history().stream().map(HistoryView::of).toList(), DirectorySettingsService.MAX_URLS,
                DirectorySettingsService.MAX_GROUPS, DirectorySettingsService.TESTS_PER_MINUTE);
        }

        @Override
        public MaskedView masked(TextMasker masker) {
            return new DirectoryView(status, statusReason, keyState, deployValuesPresent, version, null, roles,
                history.stream().map(h -> new HistoryView(h.version(), h.createdAt(), h.actor(), h.changeKind(),
                    TextMasker.WITHHELD)).toList(), maxUrls, maxGroups, testsPerMinute);
        }
    }

    /** A connection test's classified answer: a result class, a reason class and counts; never a directory value. */
    public record TestView(String result, String detail, int server, Integer groupsFound, Integer groupsBound,
                           List<String> roles) implements MaskedView {

        static TestView of(LdapAuthenticator.Probe p) {
            return new TestView(p.result().name(), p.detail(), p.server(), p.groupsFound(), p.groupsBound(), p.roles());
        }

        @Override
        public MaskedView masked(TextMasker masker) {
            return this;
        }
    }
}
