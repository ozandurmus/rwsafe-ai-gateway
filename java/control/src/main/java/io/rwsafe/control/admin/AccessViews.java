package io.rwsafe.control.admin;

import io.rwsafe.control.identity.AccessRules;
import io.rwsafe.control.identity.ActiveSessions;
import io.rwsafe.control.identity.Roles;
import io.rwsafe.control.privacy.MaskedView;
import io.rwsafe.control.privacy.TextMasker;
import io.rwsafe.persistence.LocalAccount;
import io.rwsafe.persistence.LocalUser;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * The bodies of Administration -> Access (PO decision Q-47). Only a {@code security_admin} session reaches these routes
 * (AccessRules {@code admin.access}); the masked projections exist for the funnel's coverage rule and withhold every
 * login name, display name and password all the same.
 */
public final class AccessViews {

    private AccessViews() {
    }

    /** Never printed: a reason is free text. */
    public record CreateUserRequest(String loginName, String displayName, List<String> roles, String reason) {

        @Override
        public String toString() {
            return "CreateUserRequest[redacted]";
        }
    }

    public record RolesRequest(List<String> roles, String reason) {

        @Override
        public String toString() {
            return "RolesRequest[" + roles + "]";
        }
    }

    public record ReasonRequest(String reason) {

        @Override
        public String toString() {
            return "ReasonRequest[redacted]";
        }
    }

    /** One local user; {@code subject} (its pseudonym) names it in every route. */
    public record UserView(String subject, String loginName, String displayName, List<String> roles, boolean enabled,
                           boolean passwordChangeRequired, Instant createdAt, Instant updatedAt,
                           Instant passwordChangedAt) implements MaskedView {

        static UserView of(LocalUser u) {
            return new UserView(u.subjectFingerprint(), u.loginName(), u.displayName(), u.roles(), u.enabled(),
                u.mustChangePassword(), u.createdAt(), u.updatedAt(), u.passwordChangedAt());
        }

        @Override
        public UserView masked(TextMasker masker) {
            return new UserView(subject, TextMasker.WITHHELD, TextMasker.WITHHELD, roles, enabled,
                passwordChangeRequired, createdAt, updatedAt, passwordChangedAt);
        }
    }

    /** A break-glass account, listed read-only; {@code signInEnabled} is the deploy's switch. */
    public record BreakGlassView(String loginName, List<String> roles, boolean enabled, boolean signInEnabled) {

        static BreakGlassView of(LocalAccount a, boolean signInEnabled) {
            return new BreakGlassView(a.accountName(), a.roles(), a.enabled(), signInEnabled);
        }
    }

    public record UsersView(List<UserView> users, List<BreakGlassView> breakGlass, List<String> roles,
                            int enabledSecurityAdmins, int minPasswordLength) implements MaskedView {

        @Override
        public MaskedView masked(TextMasker masker) {
            return new UsersView(users.stream().map(u -> u.masked(masker)).toList(), breakGlass.stream()
                .map(b -> new BreakGlassView(TextMasker.WITHHELD, b.roles(), b.enabled(), b.signInEnabled())).toList(),
                roles, enabledSecurityAdmins, minPasswordLength);
        }
    }

    /**
     * A created user or a reset: the generated password, shown to the administrator this once (it is stored only as a
     * hash and the user must replace it at the next sign-in).
     */
    public record IssuedView(UserView user, String oneTimePassword) implements MaskedView {

        @Override
        public MaskedView masked(TextMasker masker) {
            return new IssuedView(user.masked(masker), TextMasker.WITHHELD);
        }

        @Override
        public String toString() {
            return "IssuedView[" + user.subject() + "]";
        }
    }

    public record RuleView(String id, String method, String pattern, List<String> anyOf, boolean maskedRefused,
                           boolean pendingAllowed) {

        static RuleView of(AccessRules.Rule r) {
            return new RuleView(r.id(), r.method() == null ? "ANY" : r.method().name(), r.pattern(),
                Roles.ORDERED.stream().filter(r.anyOf()::contains).toList(), r.maskedRefused(), r.pendingAllowed());
        }
    }

    public record RoleView(String role, boolean masked, List<String> permissions) {
    }

    /** The roles and the rules, both read from the rules the security chain enforces ({@link AccessRules}). */
    public record RolesView(List<RoleView> roles, List<RuleView> rules) implements MaskedView {

        static RolesView current() {
            Map<String, List<String>> allowed = AccessRules.describe();
            return new RolesView(Roles.ORDERED.stream().map(r -> new RoleView(r, r.equals(Roles.REPLAY_VIEWER),
                allowed.get(r))).toList(), AccessRules.RULES.stream().map(RuleView::of).toList());
        }

        @Override
        public MaskedView masked(TextMasker masker) {
            return this;
        }
    }

    /**
     * One open session: who, from which source, since when and the last request; never the client address and never
     * the session id ({@code handle} is a random name of this registry's own).
     */
    public record SessionView(String handle, String loginName, String source, List<String> roles, Instant signedInAt,
                              Instant lastActivity, boolean passwordChangePending, boolean current) {

        static SessionView of(ActiveSessions.Entry e, String currentHandle) {
            return new SessionView(e.handle(), e.loginName(), e.source(),
                Roles.ORDERED.stream().filter(e.roles()::contains).toList(), e.signedInAt(),
                e.lastActivity().orElse(null), e.passwordChangePending(), e.handle().equals(currentHandle));
        }
    }

    public record SessionsView(List<SessionView> sessions) implements MaskedView {

        @Override
        public MaskedView masked(TextMasker masker) {
            return new SessionsView(sessions.stream().map(s -> new SessionView(s.handle(), TextMasker.WITHHELD,
                s.source(), s.roles(), s.signedInAt(), s.lastActivity(), s.passwordChangePending(), s.current()))
                .toList());
        }
    }
}
