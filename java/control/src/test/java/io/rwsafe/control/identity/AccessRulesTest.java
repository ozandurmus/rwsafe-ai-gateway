package io.rwsafe.control.identity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/** The one rule list (PO decision Q-47): its decisions, the pending password change and the masked role. */
class AccessRulesTest {

    private static Authentication session(String... authorities) {
        return UsernamePasswordAuthenticationToken.authenticated("synthetic-probe", null,
            Arrays.stream(authorities).map(SimpleGrantedAuthority::new).toList());
    }

    private static AccessRules.Rule rule(String id) {
        return AccessRules.RULES.stream().filter(r -> r.id().equals(id)).findFirst().orElseThrow();
    }

    @Test
    void administrationIsASecurityAdministratorsAndNeverAMaskedSessions() {
        AccessRules.Rule admin = rule(AccessRules.ADMIN_ACCESS);
        assertTrue(admin.allows(session("ROLE_security_admin")));
        assertFalse(admin.allows(session("ROLE_security_admin", "ROLE_replay_viewer")));
        assertFalse(admin.allows(session("ROLE_privacy_officer")));
        assertFalse(admin.allows(session("ROLE_security_admin", Roles.PASSWORD_CHANGE_PENDING)));
        assertTrue(AccessRules.RULES.indexOf(admin) < AccessRules.RULES.indexOf(rule(AccessRules.SCREENS_READ)),
            "administration reads are decided before the general read rule");
    }

    @Test
    void theAuditLogIsReadByEitherApproverAndNeverByAMaskedSession() {
        AccessRules.Rule audit = rule(AccessRules.ADMIN_AUDIT_READ);
        assertTrue(audit.allows(session("ROLE_security_admin")));
        assertTrue(audit.allows(session("ROLE_privacy_officer")));
        assertFalse(audit.allows(session("ROLE_viewer")));
        assertFalse(audit.allows(session("ROLE_replay_viewer")));
        assertFalse(audit.allows(session("ROLE_privacy_officer", "ROLE_replay_viewer")));
        assertFalse(audit.allows(session("ROLE_privacy_officer", Roles.PASSWORD_CHANGE_PENDING)));
        assertEquals(org.springframework.http.HttpMethod.GET, audit.method(), "reads only");
        assertEquals("/api/v1/admin/audit", audit.pattern(), "the audit page only, not the rest of Administration");
        assertTrue(AccessRules.RULES.indexOf(audit) < AccessRules.RULES.indexOf(rule(AccessRules.ADMIN_ACCESS)));
    }

    @Test
    void aPendingPasswordChangeReachesOnlyTheSessionsOwnRoutes() {
        Authentication pending = session("ROLE_viewer", Roles.PASSWORD_CHANGE_PENDING);
        for (AccessRules.Rule r : AccessRules.RULES) {
            assertEquals(r.id().equals(AccessRules.SESSION_OWN), r.allows(pending), r.id());
        }
        assertFalse(rule(AccessRules.SESSION_OWN).allows(new AnonymousAuthenticationToken("k", "anonymous",
            List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS")))));
        assertFalse(rule(AccessRules.SESSION_OWN).allows(null));
    }

    @Test
    void theDescriptionIsTheRulesEvaluatedPerRole() {
        var described = AccessRules.describe();
        assertEquals(Roles.ORDERED, List.copyOf(described.keySet()));
        assertEquals(List.of(AccessRules.SESSION_OWN, AccessRules.ADMIN_AUDIT_READ, AccessRules.ADMIN_ACCESS,
            AccessRules.SCREENS_READ, AccessRules.POLICY_APPROVE, AccessRules.CAPTURE_READ, AccessRules.CHANGE_ALL),
            described.get(Roles.SECURITY_ADMIN));
        assertEquals(List.of(AccessRules.SESSION_OWN, AccessRules.ADMIN_AUDIT_READ, AccessRules.SCREENS_READ,
            AccessRules.POLICY_APPROVE, AccessRules.CAPTURE_READ), described.get(Roles.PRIVACY_OFFICER));
        assertEquals(List.of(AccessRules.SESSION_OWN, AccessRules.SCREENS_READ), described.get(Roles.VIEWER));
        assertThrows(UnsupportedOperationException.class, () -> described.get(Roles.VIEWER).add("x"));
    }

    @Test
    void newPasswordsFollowTheRule() {
        char[] current = "Synthetic-current-1".toCharArray();
        assertEquals("PASSWORD_TOO_SHORT", refusal("synthetic", current, "Short-1"));
        assertEquals("PASSWORD_TOO_SIMPLE", refusal("synthetic", current, "abababababababab"));
        assertEquals("PASSWORD_CONTAINS_LOGIN", refusal("synthetic.user", current, "my-Synthetic.User-9x"));
        assertEquals("PASSWORD_UNCHANGED", refusal("nobody", current, "Synthetic-current-1"));
        assertEquals("PASSWORD_TOO_LONG", refusal("synthetic", current, "Ab1-" + "ç".repeat(40)));
        LocalUsers.checkNewPassword("synthetic", current, "Another-Phrase-42".toCharArray());
    }

    private static String refusal(String login, char[] current, String next) {
        return assertThrows(AccessRefusal.class, () -> LocalUsers.checkNewPassword(login, current, next.toCharArray()))
            .reason();
    }
}
