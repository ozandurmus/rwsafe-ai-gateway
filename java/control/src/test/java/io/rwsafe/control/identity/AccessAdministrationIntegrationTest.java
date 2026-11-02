package io.rwsafe.control.identity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.rwsafe.control.privacy.Pseudonymiser;
import io.rwsafe.control.support.ApiClient;
import io.rwsafe.control.support.ControlTestEnvironment;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.Statement;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Administration -> Access part 1 end to end (PO decision Q-47): local users (one-time password, forced change, disable,
 * throttle, self and last-administrator rules), roles and permissions from the enforced rules, sessions (list, end),
 * the ledger, and every route refused to every role but {@code security_admin}, the masked one first. Each test uses
 * login names of its own, so the tests share one context.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(OutputCaptureExtension.class)
class AccessAdministrationIntegrationTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String ADMIN = "synthetic-admin";

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) throws Exception {
        ControlTestEnvironment.register(r, true, true);
    }

    @LocalServerPort
    int port;
    @Autowired
    Pseudonymiser pseudonymiser;
    @Autowired
    DataSource dataSource;

    private ApiClient directory(String login) throws Exception {
        ApiClient c = new ApiClient(port);
        ApiClient.Response r = c.login(login, ControlTestEnvironment.PASSWORDS.get(login));
        assertEquals(200, r.status(), String.valueOf(r.body()));
        return c;
    }

    /** A password built at runtime (AGENTS.md 4.5): long enough, varied, never a committed literal. */
    private static String freshPassword() {
        byte[] b = new byte[10];
        new SecureRandom().nextBytes(b);
        return "Synthetic-" + HexFormat.of().formatHex(b) + "-Qz";
    }

    private static String reason(String text) {
        return JSON.createObjectNode().put("reason", text).toString();
    }

    private static String create(String login, List<String> roles, String reason) {
        ObjectNode body = JSON.createObjectNode().put("loginName", login).put("displayName", "Synthetic Person");
        var granted = body.putArray("roles");
        roles.forEach(granted::add);
        if (reason != null) {
            body.put("reason", reason);
        }
        return body.toString();
    }

    private static String password(String current, String next) {
        return JSON.createObjectNode().put("currentPassword", current).put("newPassword", next).toString();
    }

    /** Creates a local user and returns its subject and one-time password. */
    private String[] created(ApiClient admin, String login, List<String> roles) throws Exception {
        ApiClient.Response r = admin.post("/api/v1/admin/users", create(login, roles, "synthetic onboarding"), true);
        assertEquals(201, r.status(), String.valueOf(r.body()));
        return new String[] {r.body().get("user").get("subject").asText(), r.body().get("oneTimePassword").asText()};
    }

    /** Signs a fresh local user in and replaces the generated password; returns the client and the new password. */
    private Object[] activated(String login, String oneTime) throws Exception {
        ApiClient c = new ApiClient(port);
        assertEquals(200, c.login(login, oneTime).status());
        String next = freshPassword();
        ApiClient.Response changed = c.post("/api/v1/auth/password", password(oneTime, next), true);
        assertEquals(200, changed.status(), String.valueOf(changed.body()));
        return new Object[] {c, next};
    }

    private List<Map<String, Object>> ledger(String action, String rowKey) {
        return new JdbcTemplate(dataSource).queryForList("SELECT actor_fingerprint, action_id, reason_code, row_key "
            + "FROM audit_event WHERE action_id = ? AND row_key = ? ORDER BY audit_id", action, rowKey);
    }

    @Test
    void aCreatedUserGetsItsPasswordOnceAndMustReplaceItFirst(CapturedOutput output) throws Exception {
        ApiClient admin = directory(ADMIN);
        String login = "synthetic.onetime";
        ApiClient.Response r = admin.post("/api/v1/admin/users", create(login, List.of("viewer"),
            "synthetic onboarding"), true);
        assertEquals(201, r.status(), String.valueOf(r.body()));
        assertTrue(r.raw().headers().firstValue("Cache-Control").orElse("").contains("no-store"));
        String oneTime = r.body().get("oneTimePassword").asText();
        String subject = r.body().get("user").get("subject").asText();
        assertEquals(LocalUsers.GENERATED_LENGTH, oneTime.length());
        assertEquals(pseudonymiser.user(login), subject);
        assertTrue(r.body().get("user").get("passwordChangeRequired").asBoolean());

        // Shown once: the list never carries it, and only a BCrypt hash is stored.
        ApiClient.Response list = admin.get("/api/v1/admin/users");
        assertEquals(200, list.status());
        assertFalse(list.raw().body().contains(oneTime));
        assertFalse(list.raw().body().contains("passwordHash"));
        String hash = new JdbcTemplate(dataSource).queryForObject(
            "SELECT password_hash FROM local_user WHERE subject_fingerprint = ?", String.class, subject);
        assertTrue(hash.startsWith("$2"));
        assertFalse(hash.contains(oneTime));
        List<Map<String, Object>> created = ledger("local_user.create", subject);
        assertEquals(1, created.size());
        assertEquals(pseudonymiser.user(ADMIN), created.get(0).get("actor_fingerprint"));
        assertEquals("synthetic onboarding", created.get(0).get("reason_code"));

        // Signed in with the generated password: nothing but the session's own routes until it is replaced.
        ApiClient user = new ApiClient(port);
        ApiClient.Response login1 = user.login(login, oneTime);
        assertEquals(200, login1.status(), String.valueOf(login1.body()));
        assertTrue(login1.body().get("passwordChangeRequired").asBoolean());
        assertEquals("local_user", login1.body().get("source").asText());
        assertTrue(user.get("/api/v1/auth/me").body().get("passwordChangeRequired").asBoolean());
        assertEquals(403, user.get("/api/v1/overview").status());
        assertEquals(403, user.get("/api/v1/health").status());

        assertEquals("PASSWORD_TOO_SHORT", user.post("/api/v1/auth/password", password(oneTime, "Short-1x"), true)
            .body().get("reason").asText());
        assertEquals("PASSWORD_CONTAINS_LOGIN", user.post("/api/v1/auth/password",
            password(oneTime, "Xy-" + login + "-Zq9"), true).body().get("reason").asText());
        assertEquals("PASSWORD_TOO_SIMPLE", user.post("/api/v1/auth/password",
            password(oneTime, "aaaaabbbbbaaaaabbbbb"), true).body().get("reason").asText());
        assertEquals("PASSWORD_UNCHANGED", user.post("/api/v1/auth/password", password(oneTime, oneTime), true)
            .body().get("reason").asText());
        String next = freshPassword();
        ApiClient.Response wrong = user.post("/api/v1/auth/password", password(freshPassword(), next), true);
        assertEquals(403, wrong.status());
        assertEquals("CURRENT_PASSWORD_WRONG", wrong.body().get("reason").asText());

        ApiClient.Response changed = user.post("/api/v1/auth/password", password(oneTime, next), true);
        assertEquals(200, changed.status(), String.valueOf(changed.body()));
        assertFalse(changed.body().get("passwordChangeRequired").asBoolean());
        assertEquals(200, user.get("/api/v1/health").status());
        assertEquals(403, user.get("/api/v1/admin/users").status(), "a viewer reaches no administration");
        assertEquals(1, ledger("local_user.password_change", subject).size());

        assertEquals(401, new ApiClient(port).login(login, oneTime).status(), "the generated password is spent");
        ApiClient again = new ApiClient(port);
        ApiClient.Response login2 = again.login(login, next);
        assertEquals(200, login2.status());
        assertFalse(login2.body().get("passwordChangeRequired").asBoolean());

        // AGENTS.md 4.14: no login name, display name or password in any log line.
        for (String value : List.of(login, oneTime, next, "Synthetic Person")) {
            assertFalse(output.getAll().contains(value), "a log line carries a value of class "
                + (value.equals(login) ? "login name" : value.equals(oneTime) || value.equals(next) ? "password"
                : "display name"));
        }
        assertTrue(output.getAll().contains("login accepted: source=local_user"));
    }

    @Test
    void aDisabledUserIsSignedOutAndRefusedUntilEnabledAgain() throws Exception {
        ApiClient admin = directory(ADMIN);
        String login = "synthetic.disabled";
        String[] u = created(admin, login, List.of("viewer"));
        Object[] active = activated(login, u[1]);
        ApiClient user = (ApiClient) active[0];
        assertEquals(200, user.get("/api/v1/health").status());

        ApiClient.Response disabled = admin.post("/api/v1/admin/users/" + u[0] + "/disable",
            reason("left the synthetic team"), true);
        assertEquals(200, disabled.status(), String.valueOf(disabled.body()));
        assertFalse(disabled.body().get("enabled").asBoolean());
        assertEquals(401, user.get("/api/v1/health").status(), "the open session ended");
        ApiClient.Response refused = new ApiClient(port).login(login, (String) active[1]);
        assertEquals(401, refused.status());
        assertEquals("INVALID_CREDENTIALS", refused.body().get("reason").asText(), "refused like a wrong password");
        assertEquals(1, ledger("local_user.disable", u[0]).size());

        assertEquals(200, admin.post("/api/v1/admin/users/" + u[0] + "/enable", reason("back on the synthetic team"),
            true).status());
        assertEquals(200, new ApiClient(port).login(login, (String) active[1]).status());

        // A reset ends the user's sessions, returns a new one-time password and asks for a change again.
        ApiClient.Response reset = admin.post("/api/v1/admin/users/" + u[0] + "/password-reset",
            reason("forgot the password"), true);
        assertEquals(200, reset.status(), String.valueOf(reset.body()));
        String oneTime = reset.body().get("oneTimePassword").asText();
        assertEquals(401, new ApiClient(port).login(login, (String) active[1]).status());
        ApiClient.Response afterReset = new ApiClient(port).login(login, oneTime);
        assertEquals(200, afterReset.status());
        assertTrue(afterReset.body().get("passwordChangeRequired").asBoolean());
        assertEquals(1, ledger("local_user.password_reset", u[0]).size());

        // A role change ends the sessions too and applies at the next sign-in.
        Object[] again = activated(login, oneTime);
        ApiClient.Response roles = admin.post("/api/v1/admin/users/" + u[0] + "/roles", JSON.createObjectNode()
            .put("reason", "now reviews privacy").set("roles", JSON.createArrayNode().add("privacy_officer")).toString(),
            true);
        assertEquals(200, roles.status(), String.valueOf(roles.body()));
        assertEquals(401, ((ApiClient) again[0]).get("/api/v1/health").status());
        ApiClient officer = new ApiClient(port);
        assertEquals(List.of("privacy_officer"), JSON.convertValue(officer.login(login, (String) again[1]).body()
            .get("roles"), List.class));
    }

    @Test
    void theLoginThrottleCoversLocalUsers() throws Exception {
        ApiClient admin = directory(ADMIN);
        String login = "synthetic.throttled";
        String[] u = created(admin, login, List.of("viewer"));
        for (int i = 0; i < LoginThrottle.MAX_PER_PAIR; i++) {
            assertEquals(401, new ApiClient(port).login(login, freshPassword()).status());
        }
        ApiClient.Response locked = new ApiClient(port).login(login, u[1]);
        assertEquals(429, locked.status());
        assertEquals("LOGIN_THROTTLED", locked.body().get("reason").asText());
    }

    @Test
    void anAdministratorCannotDisableDemoteOrResetThemself() throws Exception {
        ApiClient admin = directory(ADMIN);
        String login = "synthetic.selfadmin";
        String[] u = created(admin, login, List.of("security_admin"));
        ApiClient self = (ApiClient) activated(login, u[1])[0];
        assertEquals(200, self.get("/api/v1/admin/users").status());
        ApiClient.Response disable = self.post("/api/v1/admin/users/" + u[0] + "/disable", reason("synthetic"), true);
        assertEquals(409, disable.status());
        assertEquals("SELF_DISABLE_REFUSED", disable.body().get("reason").asText());
        ApiClient.Response demote = self.post("/api/v1/admin/users/" + u[0] + "/roles", JSON.createObjectNode()
            .put("reason", "synthetic").set("roles", JSON.createArrayNode().add("viewer")).toString(), true);
        assertEquals(409, demote.status());
        assertEquals("SELF_DEMOTION_REFUSED", demote.body().get("reason").asText());
        ApiClient.Response reset = self.post("/api/v1/admin/users/" + u[0] + "/password-reset", reason("synthetic"),
            true);
        assertEquals("SELF_RESET_REFUSED", reset.body().get("reason").asText());
        // Adding a role to oneself keeps the administrator role and is allowed.
        assertEquals(200, self.post("/api/v1/admin/users/" + u[0] + "/roles", JSON.createObjectNode()
            .put("reason", "synthetic").set("roles", JSON.createArrayNode().add("security_admin").add("viewer"))
            .toString(), true).status());
    }

    @Test
    void theLastEnabledSecurityAdministratorCannotBeDisabledOrDemoted() throws Exception {
        ApiClient admin = directory(ADMIN);
        String[] last = created(admin, "synthetic.lastadmin", List.of("security_admin"));
        breakGlass(false);
        try {
            // Every other enabled local administrator is disabled first; the directory administrator does not count.
            for (JsonNode user : admin.get("/api/v1/admin/users").body().get("users")) {
                boolean otherAdmin = user.get("enabled").asBoolean() && !user.get("subject").asText().equals(last[0])
                    && user.get("roles").toString().contains("security_admin");
                if (otherAdmin) {
                    assertEquals(200, admin.post("/api/v1/admin/users/" + user.get("subject").asText() + "/disable",
                        reason("synthetic cleanup"), true).status());
                }
            }
            assertEquals(1, admin.get("/api/v1/admin/users").body().get("enabledSecurityAdmins").asInt());
            ApiClient.Response disable = admin.post("/api/v1/admin/users/" + last[0] + "/disable", reason("synthetic"),
                true);
            assertEquals(409, disable.status());
            assertEquals("LAST_SECURITY_ADMIN", disable.body().get("reason").asText());
            ApiClient.Response demote = admin.post("/api/v1/admin/users/" + last[0] + "/roles", JSON.createObjectNode()
                .put("reason", "synthetic").set("roles", JSON.createArrayNode().add("viewer")).toString(), true);
            assertEquals("LAST_SECURITY_ADMIN", demote.body().get("reason").asText());
            assertTrue(ledger("local_user.disable", last[0]).isEmpty(), "a refused change is not ledgered");
        } finally {
            breakGlass(true);
        }
        assertEquals(200, admin.post("/api/v1/admin/users/" + last[0] + "/disable", reason("synthetic"), true)
            .status(), "the break-glass administrator counts again");
    }

    private void breakGlass(boolean enabled) throws Exception {
        try (Connection c = dataSource.getConnection(); Statement s = c.createStatement()) {
            c.setAutoCommit(false);
            s.execute("SELECT set_config('app.actor_fingerprint', 'system:test', true), "
                + "set_config('app.action_id', 'test.break_glass', true), set_config('app.reason_code', 'TEST', true)");
            s.execute("UPDATE local_account SET enabled = " + enabled);
            c.commit();
        }
    }

    @Test
    void everyRouteRefusesEveryRoleButTheSecurityAdministrator() throws Exception {
        ApiClient admin = directory(ADMIN);
        String[] u = created(admin, "synthetic.target", List.of("viewer"));
        String handle = admin.get("/api/v1/admin/sessions").body().get("sessions").get(0).get("handle").asText();
        for (String who : List.of("synthetic-aiview", "synthetic-dual", "synthetic-viewer", "synthetic-officer")) {
            ApiClient c = directory(who);
            List<ApiClient.Response> answers = List.of(
                c.get("/api/v1/admin/users"), c.get("/api/v1/admin/roles"), c.get("/api/v1/admin/sessions"),
                c.post("/api/v1/admin/users", create("synthetic.intruder", List.of("viewer"), "synthetic"), true),
                c.post("/api/v1/admin/users/" + u[0] + "/roles", JSON.createObjectNode().put("reason", "x")
                    .set("roles", JSON.createArrayNode().add("security_admin")).toString(), true),
                c.post("/api/v1/admin/users/" + u[0] + "/disable", reason("synthetic"), true),
                c.post("/api/v1/admin/users/" + u[0] + "/enable", reason("synthetic"), true),
                c.post("/api/v1/admin/users/" + u[0] + "/password-reset", reason("synthetic"), true),
                c.post("/api/v1/admin/sessions/" + handle + "/end", reason("synthetic"), true));
            for (ApiClient.Response r : answers) {
                assertEquals(403, r.status(), who);
                assertEquals("FORBIDDEN", r.body().get("reason").asText(), who);
                assertFalse(r.raw().body().contains("synthetic.target"), who);
            }
        }
        // The masked session reaches its own routes; a directory user has no local password to change.
        ApiClient masked = directory("synthetic-aiview");
        ApiClient.Response own = masked.post("/api/v1/auth/password", password("x", "y"), true);
        assertEquals("NOT_A_LOCAL_USER", own.body().get("reason").asText());
        assertEquals("true", own.raw().headers().firstValue("X-RWSAFE-Masked").orElse(""));
    }

    @Test
    void rolesAndPermissionsAreTheEnforcedRules() throws Exception {
        JsonNode view = directory(ADMIN).get("/api/v1/admin/roles").body();
        Map<String, List<String>> enforced = AccessRules.describe();
        assertEquals(Roles.ORDERED.size(), view.get("roles").size());
        for (JsonNode role : view.get("roles")) {
            assertEquals(enforced.get(role.get("role").asText()), JSON.convertValue(role.get("permissions"), List.class));
        }
        assertTrue(enforced.get(Roles.SECURITY_ADMIN).contains(AccessRules.ADMIN_ACCESS));
        for (String other : List.of(Roles.PRIVACY_OFFICER, Roles.VIEWER, Roles.REPLAY_VIEWER)) {
            assertFalse(enforced.get(other).contains(AccessRules.ADMIN_ACCESS), other);
            assertFalse(enforced.get(other).contains(AccessRules.CHANGE_ALL), other);
        }
        assertEquals(List.of(AccessRules.SESSION_OWN, AccessRules.SCREENS_READ), enforced.get(Roles.REPLAY_VIEWER));
        assertEquals(AccessRules.RULES.size(), view.get("rules").size());
        assertEquals("/api/v1/admin/**", view.get("rules").get(1).get("pattern").asText());
    }

    @Test
    void anAdministratorSeesAndEndsAnotherSessionWithAReason() throws Exception {
        ApiClient admin = directory(ADMIN);
        ApiClient viewer = directory("synthetic-viewer");
        JsonNode sessions = admin.get("/api/v1/admin/sessions").body().get("sessions");
        JsonNode mine = null;
        JsonNode theirs = null;
        for (JsonNode s : sessions) {
            assertFalse(s.has("address") || s.has("clientAddress") || s.has("sessionId") || s.has("remoteAddr"));
            assertNotNull(s.get("signedInAt").asText());
            assertNotNull(s.get("lastActivity").asText());
            if (s.get("current").asBoolean()) {
                mine = s;
            } else if (theirs == null && s.get("loginName").asText().equals("synthetic-viewer")) {
                // The latest sign-in comes first; other tests may have left older sessions of the same user.
                theirs = s;
            }
        }
        assertNotNull(mine);
        assertNotNull(theirs);
        assertEquals("ldap", theirs.get("source").asText());
        assertFalse(sessions.toString().contains("127.0.0.1"), "never the client address");

        ApiClient.Response own = admin.post("/api/v1/admin/sessions/" + mine.get("handle").asText() + "/end",
            reason("synthetic"), true);
        assertEquals("SELF_SESSION_REFUSED", own.body().get("reason").asText());
        ApiClient.Response noReason = admin.post("/api/v1/admin/sessions/" + theirs.get("handle").asText() + "/end",
            reason(" "), true);
        assertEquals("INVALID_REASON", noReason.body().get("reason").asText());
        assertEquals(200, viewer.get("/api/v1/health").status());

        ApiClient.Response end = admin.post("/api/v1/admin/sessions/" + theirs.get("handle").asText() + "/end",
            reason("synthetic incident drill"), true);
        assertEquals(204, end.status(), String.valueOf(end.body()));
        assertEquals(401, viewer.get("/api/v1/health").status(), "signed out on the next request");
        List<Map<String, Object>> ledgered = ledger("session.end", pseudonymiser.user("synthetic-viewer"));
        assertEquals(1, ledgered.size());
        assertEquals(pseudonymiser.user(ADMIN), ledgered.get(0).get("actor_fingerprint"));
        assertEquals("synthetic incident drill", ledgered.get(0).get("reason_code"));
        assertEquals("SESSION_NOT_FOUND", admin.post("/api/v1/admin/sessions/" + theirs.get("handle").asText()
            + "/end", reason("synthetic"), true).body().get("reason").asText());
    }

    @Test
    void everyChangeNeedsAReasonWithoutIdentifiersAndValidInput() throws Exception {
        ApiClient admin = directory(ADMIN);
        assertEquals("INVALID_REASON", admin.post("/api/v1/admin/users", create("synthetic.noreason",
            List.of("viewer"), null), true).body().get("reason").asText());
        ApiClient.Response mail = admin.post("/api/v1/admin/users", create("synthetic.mail", List.of("viewer"),
            "asked by synthetic.person@example.invalid"), true);
        assertEquals("REASON_HOLDS_IDENTIFIER", mail.body().get("reason").asText());
        assertFalse(mail.raw().body().contains("example.invalid"), "the refusal echoes nothing");
        assertEquals("INVALID_USER_LOGIN", admin.post("/api/v1/admin/users", create("breakglass", List.of("viewer"),
            "synthetic"), true).body().get("reason").asText());
        assertEquals("INVALID_ROLES", admin.post("/api/v1/admin/users", create("synthetic.mixed",
            List.of("replay_viewer", "viewer"), "synthetic"), true).body().get("reason").asText());
        assertEquals("INVALID_ROLES", admin.post("/api/v1/admin/users", create("synthetic.unknown",
            List.of("superuser"), "synthetic"), true).body().get("reason").asText());
        created(admin, "synthetic.twice", List.of("viewer"));
        ApiClient.Response twice = admin.post("/api/v1/admin/users", create("Synthetic.Twice", List.of("viewer"),
            "synthetic"), true);
        assertEquals(409, twice.status());
        assertEquals("LOCAL_USER_EXISTS", twice.body().get("reason").asText());
        assertEquals("LOCAL_USER_NOT_FOUND", admin.post("/api/v1/admin/users/USR-0000000000/disable",
            reason("synthetic"), true).body().get("reason").asText());
        // The break-glass account is listed, read-only.
        JsonNode list = admin.get("/api/v1/admin/users").body();
        assertEquals("breakglass", list.get("breakGlass").get(0).get("loginName").asText());
    }
}
