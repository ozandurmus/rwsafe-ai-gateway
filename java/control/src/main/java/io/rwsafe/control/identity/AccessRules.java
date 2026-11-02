package io.rwsafe.control.identity;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * The admin API's authorisation rules, in the order the security chain applies them (the first rule whose method and
 * path match a request decides). {@link SecurityConfig} builds its matchers from this list, and the Roles & permissions
 * screen describes the same list by evaluating each rule for each role ({@link #describe()}), so the screen cannot drift
 * from what the server enforces (PO decision Q-47).
 *
 * <p>Two routes stay outside the list because they need no session: {@code POST /api/v1/auth/login} and
 * {@code GET /api/v1/auth/csrf}. A session whose local user has not yet replaced the generated password
 * ({@link Roles#PASSWORD_CHANGE_PENDING}) passes only the rule that allows it.
 */
public final class AccessRules {

    /**
     * One rule.
     *
     * @param id             stable identifier; the UI labels it ({@code permission.<id>})
     * @param method         the HTTP method, or null for every method
     * @param pattern        the Spring path pattern
     * @param anyOf          roles of which the session must hold one; empty means any signed-in session
     * @param maskedRefused  a masked ({@code replay_viewer}) session is refused whatever else it holds
     * @param pendingAllowed a session still waiting for its password change passes
     */
    public record Rule(String id, HttpMethod method, String pattern, Set<String> anyOf, boolean maskedRefused,
                       boolean pendingAllowed) {

        public Rule {
            anyOf = Set.copyOf(anyOf);
        }

        /** The decision for {@code auth}, as the security chain takes it. */
        public boolean allows(Authentication auth) {
            if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
                return false;
            }
            if (!pendingAllowed && has(auth, Roles.PASSWORD_CHANGE_PENDING)) {
                return false;
            }
            if (maskedRefused && has(auth, Roles.authority(Roles.REPLAY_VIEWER))) {
                return false;
            }
            return anyOf.isEmpty() || anyOf.stream().anyMatch(r -> has(auth, Roles.authority(r)));
        }

        private static boolean has(Authentication auth, String authority) {
            return auth.getAuthorities().stream().anyMatch(a -> authority.equals(a.getAuthority()));
        }
    }

    public static final String SESSION_OWN = "session.own";
    public static final String ADMIN_AUDIT_READ = "admin.audit.read";
    public static final String ADMIN_ACCESS = "admin.access";
    public static final String SCREENS_READ = "screens.read";
    public static final String POLICY_APPROVE = "policy.approve";
    public static final String CAPTURE_READ = "capture.read";
    public static final String CHANGE_ALL = "change.all";

    private static final Set<String> READERS = Set.of(Roles.SECURITY_ADMIN, Roles.PRIVACY_OFFICER, Roles.VIEWER,
        Roles.REPLAY_VIEWER);
    private static final Set<String> APPROVERS = Set.of(Roles.SECURITY_ADMIN, Roles.PRIVACY_OFFICER);

    /** In the chain's order. */
    public static final List<Rule> RULES = List.of(
        // The session's own routes: who am I, sign out, the CSRF token and the own password change.
        new Rule(SESSION_OWN, null, "/api/v1/auth/**", Set.of(), false, true),
        // Administration -> Records -> Audit log (PO decision Q-47 decision 1.3): read by either approver role, never
        // by a masked session; decided before the rest of Administration.
        new Rule(ADMIN_AUDIT_READ, HttpMethod.GET, "/api/v1/admin/audit", APPROVERS, true, false),
        // Administration (PO decision Q-47): security_admin only, never a masked session, reads included.
        new Rule(ADMIN_ACCESS, null, "/api/v1/admin/**", Set.of(Roles.SECURITY_ADMIN), true, false),
        // Every screen's reads; the masked role through the masking funnel.
        new Rule(SCREENS_READ, HttpMethod.GET, "/api/v1/**", READERS, false, false),
        // A policy approval: either approver role, never a masked session; the service checks that the session holds
        // the role the approval is given in (AGENTS.md section 6).
        new Rule(POLICY_APPROVE, HttpMethod.POST, "/api/v1/policy/rules/*/versions/*/approvals", APPROVERS, true,
            false),
        // A C3 read (ADR-009 §5): either reader role, never a masked session; a refusal is ledgered (SecurityConfig).
        new Rule(CAPTURE_READ, HttpMethod.POST, "/api/v1/captures/*/read", APPROVERS, true, false),
        // Every other change: security_admin, and never a masked session (PR 12 review D-02).
        new Rule(CHANGE_ALL, null, "/api/**", Set.of(Roles.SECURITY_ADMIN), true, false));

    private AccessRules() {
    }

    /** What a role may do: per role, the ids of the rules a session holding that role alone passes. */
    public static Map<String, List<String>> describe() {
        Map<String, List<String>> out = new LinkedHashMap<>();
        for (String role : Roles.ORDERED) {
            Authentication probe = UsernamePasswordAuthenticationToken.authenticated("role-probe", null,
                List.of(new SimpleGrantedAuthority(Roles.authority(role))));
            List<String> allowed = new ArrayList<>();
            for (Rule rule : RULES) {
                if (rule.allows(probe)) {
                    allowed.add(rule.id());
                }
            }
            out.put(role, List.copyOf(allowed));
        }
        return out;
    }
}
