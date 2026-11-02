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
        // A directory administrator whose login name a local user takes later (PR 48 review D-01, D-04).
        ControlTestEnvironment.addUser("synthetic-twin", "security_admin");
    }

    @LocalServerPort
    int port;
    @Autowired
    Pseudonymiser pseudonymiser;
    @Autowired
    DataSource dataSource;
    @Autowired
    LocalUsers localUsers;

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
        ApiClient.Response r = admin.post("/api/v1/admin/users", create(login, roles, "onboarding"), true);
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
            "onboarding"), true);
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
        assertEquals("onboarding", created.get(0).get("reason_code"));

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
            reason("left the team"), true);
        assertEquals(200, disabled.status(), String.valueOf(disabled.body()));
        assertFalse(disabled.body().get("enabled").asBoolean());
        assertEquals(401, user.get("/api/v1/health").status(), "the open session ended");
        ApiClient.Response refused = new ApiClient(port).login(login, (String) active[1]);
        assertEquals(401, refused.status());
        assertEquals("INVALID_CREDENTIALS", refused.body().get("reason").asText(), "refused like a wrong password");
        assertEquals(1, ledger("local_user.disable", u[0]).size());

        assertEquals(200, admin.post("/api/v1/admin/users/" + u[0] + "/enable", reason("back on the team"),
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
        ApiClient.Response disable = self.post("/api/v1/admin/users/" + u[0] + "/disable", reason("routine change"), true);
        assertEquals(409, disable.status());
        assertEquals("SELF_DISABLE_REFUSED", disable.body().get("reason").asText());
        ApiClient.Response demote = self.post("/api/v1/admin/users/" + u[0] + "/roles", JSON.createObjectNode()
            .put("reason", "routine change").set("roles", JSON.createArrayNode().add("viewer")).toString(), true);
        assertEquals(409, demote.status());
        assertEquals("SELF_ROLES_CHANGE_REFUSED", demote.body().get("reason").asText());
        ApiClient.Response reset = self.post("/api/v1/admin/users/" + u[0] + "/password-reset", reason("routine change"),
            true);
        assertEquals("SELF_RESET_REFUSED", reset.body().get("reason").asText());
        // PR 48 review D-01: no self-granted role either (a privacy officer approval or a DSAR read of one's own).
        ApiClient.Response grant = self.post("/api/v1/admin/users/" + u[0] + "/roles", JSON.createObjectNode()
            .put("reason", "routine change").set("roles", JSON.createArrayNode().add("security_admin")
                .add("privacy_officer")).toString(), true);
        assertEquals(409, grant.status());
        assertEquals("SELF_ROLES_CHANGE_REFUSED", grant.body().get("reason").asText());
        assertEquals(List.of("security_admin"), JSON.convertValue(self.get("/api/v1/admin/users").body().get("users")
            .findParents("subject").stream().filter(n -> n.get("subject").asText().equals(u[0])).findFirst()
            .orElseThrow().get("roles"), List.class));
        assertTrue(ledger("local_user.roles_change", u[0]).isEmpty());
    }

    /**
     * PR 48 review D-01 and D-04: a local user owns its login name. A directory session that was open before a local
     * user took the same name is not that local user ("self" is the local source only), and from then on the directory
     * is never asked for the name, whether the local user is enabled or not.
     */
    @Test
    void aLocalUserOwnsItsLoginNameAndOnlyItsOwnSessionIsSelf() throws Exception {
        String twin = "synthetic-twin";
        ApiClient directoryTwin = directory(twin);
        ApiClient admin = directory(ADMIN);
        String[] u = created(admin, twin, List.of("viewer"));
        ApiClient.Response refused = new ApiClient(port).login(twin, ControlTestEnvironment.PASSWORDS.get(twin));
        assertEquals(401, refused.status(), "the directory password no longer opens the name");
        assertEquals("INVALID_CREDENTIALS", refused.body().get("reason").asText());

        ApiClient.Response disabled = directoryTwin.post("/api/v1/admin/users/" + u[0] + "/disable",
            reason("routine change"), true);
        assertEquals(200, disabled.status(), "a directory session is not the local user of the same name");
        assertEquals(401, new ApiClient(port).login(twin, ControlTestEnvironment.PASSWORDS.get(twin)).status(),
            "a disabled local user still owns the name");
        assertEquals(401, new ApiClient(port).login(twin, u[1]).status());
    }

    /** PR 48 review D-02: the own change ends the user's other sessions and keeps the stored roles. */
    @Test
    void anOwnPasswordChangeEndsTheOtherSessions() throws Exception {
        ApiClient admin = directory(ADMIN);
        String login = "synthetic.twosessions";
        String[] u = created(admin, login, List.of("viewer"));
        ApiClient first = new ApiClient(port);
        ApiClient second = new ApiClient(port);
        assertEquals(200, first.login(login, u[1]).status());
        assertEquals(200, second.login(login, u[1]).status());
        String next = freshPassword();
        ApiClient.Response changed = first.post("/api/v1/auth/password", password(u[1], next), true);
        assertEquals(200, changed.status(), String.valueOf(changed.body()));
        assertEquals(List.of("viewer"), JSON.convertValue(changed.body().get("roles"), List.class));
        assertEquals(401, second.get("/api/v1/auth/me").status(), "the other session ended");
        assertEquals(200, first.get("/api/v1/health").status());

        // A masked local user changes its password too, served through the funnel.
        String[] m = created(admin, "synthetic.maskedlocal", List.of("replay_viewer"));
        ApiClient masked = new ApiClient(port);
        assertEquals(200, masked.login("synthetic.maskedlocal", m[1]).status());
        ApiClient.Response own = masked.post("/api/v1/auth/password", password(m[1], freshPassword()), true);
        assertEquals(200, own.status(), String.valueOf(own.body()));
        assertEquals("true", own.raw().headers().firstValue("X-RWSAFE-Masked").orElse(""));
        assertEquals("masked session", own.body().get("displayName").asText());
    }

    /** PR 48 review D-02: the update refuses a row that was reset or disabled after the current password was checked. */
    @Test
    void anOwnChangeNeverOverwritesAResetOrADisable() {
        io.rwsafe.persistence.LocalUser checked = new io.rwsafe.persistence.LocalUser("synthetic.race", "USR-00000000a1",
            "Display", "$2a$12$" + "a".repeat(53), List.of("viewer"), true, true, null, null, null);
        io.rwsafe.persistence.LocalUser reset = new io.rwsafe.persistence.LocalUser("synthetic.race", "USR-00000000a1",
            "Display", "$2a$12$" + "b".repeat(53), List.of("viewer"), true, true, null, null, null);
        io.rwsafe.persistence.LocalUser off = new io.rwsafe.persistence.LocalUser("synthetic.race", "USR-00000000a1",
            "Display", checked.passwordHash(), List.of("viewer"), false, true, null, null, null);
        String hash = "$2a$12$" + "c".repeat(53);
        for (io.rwsafe.persistence.LocalUser locked : List.of(reset, off)) {
            io.rwsafe.persistence.LocalUserConflict e = org.junit.jupiter.api.Assertions.assertThrows(
                io.rwsafe.persistence.LocalUserConflict.class, () -> LocalUsers.ownChange(checked, locked, hash));
            assertEquals("ACCOUNT_CHANGED", e.reason());
        }
        io.rwsafe.persistence.LocalUser done = LocalUsers.ownChange(checked, checked, hash);
        assertEquals(hash, done.passwordHash());
        assertFalse(done.mustChangePassword());
        assertNotNull(done.passwordChangedAt());
    }

    /** PR 48 review D-03: a sign-in whose user changed meanwhile is not kept. */
    @Test
    void aSignInIsCheckedAgainstTheStoredUser() throws Exception {
        ApiClient admin = directory(ADMIN);
        String login = "synthetic.raced";
        String[] u = created(admin, login, List.of("viewer"));
        AuthenticatedUser signedIn = new AuthenticatedUser(login, java.util.Set.of("viewer"), "local_user", true);
        assertTrue(localUsers.stillMatches(signedIn));
        assertFalse(localUsers.stillMatches(new AuthenticatedUser(login, java.util.Set.of("viewer"), "local_user",
            false)), "the change mark differs");
        assertFalse(localUsers.stillMatches(new AuthenticatedUser(login, java.util.Set.of("security_admin"),
            "local_user", true)), "the roles differ");
        assertEquals(200, admin.post("/api/v1/admin/users/" + u[0] + "/disable", reason("routine change"), true)
            .status());
        assertFalse(localUsers.stillMatches(signedIn), "disabled");
    }

    /** PR 48 review D-05 and D-08: no person's name in a reason, no identifier in a name. */
    @Test
    void reasonsNameNoPersonAndNamesHoldNoIdentifier() throws Exception {
        ApiClient admin = directory(ADMIN);
        String[] u = created(admin, "synthetic.kemalettin", List.of("viewer"));
        ObjectNode other = JSON.createObjectNode().put("loginName", "synthetic.bystander")
            .put("displayName", "Quorvex Plimb").put("reason", "onboarding");
        other.putArray("roles").add("viewer");
        assertEquals(201, admin.post("/api/v1/admin/users", other.toString(), true).status());
        for (String reason : List.of("asked by kemalettin", "Kemalettin'in talebi", "kemalettinin talebi",
            "for the admin team", "Synthetic request", "asked by quorvex", "bystander moved")) {
            ApiClient.Response r = admin.post("/api/v1/admin/users/" + u[0] + "/disable", reason(reason), true);
            assertEquals(400, r.status(), "a reason naming a known person");
            assertEquals("REASON_HOLDS_IDENTIFIER", r.body().get("reason").asText());
        }
        assertTrue(ledger("local_user.disable", u[0]).isEmpty());
        assertTrue(LocalUsers.namesPerson("Ali'nin talebi", List.of("ali.can")));
        assertFalse(LocalUsers.namesPerson("cancel the access", List.of("ali.can")), "a 3-letter token matches whole");
        assertTrue(LocalUsers.namesPerson("Şükrü'nün isteği", List.of("Şükrü Öztürk")));

        for (String login : List.of("synthetic1234567", "synthetic-estate")) {
            ApiClient.Response r = admin.post("/api/v1/admin/users", create(login, List.of("viewer"), "onboarding"),
                true);
            assertEquals("NAME_HOLDS_IDENTIFIER", r.body().get("reason").asText(), "a login name with an identifier");
        }
        ObjectNode estate = JSON.createObjectNode().put("loginName", "synthetic.estatename")
            .put("displayName", "Synthetic Estate Team").put("reason", "onboarding");
        estate.putArray("roles").add("viewer");
        assertEquals("NAME_HOLDS_IDENTIFIER", admin.post("/api/v1/admin/users", estate.toString(), true).body()
            .get("reason").asText(), "a display name with an estate term");
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
                        reason("cleanup"), true).status());
                }
            }
            assertEquals(1, admin.get("/api/v1/admin/users").body().get("enabledSecurityAdmins").asInt());
            ApiClient.Response disable = admin.post("/api/v1/admin/users/" + last[0] + "/disable", reason("routine change"),
                true);
            assertEquals(409, disable.status());
            assertEquals("LAST_SECURITY_ADMIN", disable.body().get("reason").asText());
            ApiClient.Response demote = admin.post("/api/v1/admin/users/" + last[0] + "/roles", JSON.createObjectNode()
                .put("reason", "routine change").set("roles", JSON.createArrayNode().add("viewer")).toString(), true);
            assertEquals("LAST_SECURITY_ADMIN", demote.body().get("reason").asText());
            assertTrue(ledger("local_user.disable", last[0]).isEmpty(), "a refused change is not ledgered");
        } finally {
            breakGlass(true);
        }
        assertEquals(200, admin.post("/api/v1/admin/users/" + last[0] + "/disable", reason("routine change"), true)
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
                c.post("/api/v1/admin/users", create("synthetic.intruder", List.of("viewer"), "routine change"), true),
                c.post("/api/v1/admin/users/" + u[0] + "/roles", JSON.createObjectNode().put("reason", "x")
                    .set("roles", JSON.createArrayNode().add("security_admin")).toString(), true),
                c.post("/api/v1/admin/users/" + u[0] + "/disable", reason("routine change"), true),
                c.post("/api/v1/admin/users/" + u[0] + "/enable", reason("routine change"), true),
                c.post("/api/v1/admin/users/" + u[0] + "/password-reset", reason("routine change"), true),
                c.post("/api/v1/admin/sessions/" + handle + "/end", reason("routine change"), true));
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
            reason("routine change"), true);
        assertEquals("SELF_SESSION_REFUSED", own.body().get("reason").asText());
        ApiClient.Response noReason = admin.post("/api/v1/admin/sessions/" + theirs.get("handle").asText() + "/end",
            reason(" "), true);
        assertEquals("INVALID_REASON", noReason.body().get("reason").asText());
        assertEquals(200, viewer.get("/api/v1/health").status());

        ApiClient.Response end = admin.post("/api/v1/admin/sessions/" + theirs.get("handle").asText() + "/end",
            reason("incident drill"), true);
        assertEquals(204, end.status(), String.valueOf(end.body()));
        assertEquals(401, viewer.get("/api/v1/health").status(), "signed out on the next request");
        List<Map<String, Object>> ledgered = ledger("session.end", pseudonymiser.user("synthetic-viewer"));
        assertEquals(1, ledgered.size());
        assertEquals(pseudonymiser.user(ADMIN), ledgered.get(0).get("actor_fingerprint"));
        assertEquals("incident drill", ledgered.get(0).get("reason_code"));
        // PR 48 review D-06: a session that is no longer live is 404 and nothing more is ledgered.
        ApiClient.Response again = admin.post("/api/v1/admin/sessions/" + theirs.get("handle").asText() + "/end",
            reason("routine change"), true);
        assertEquals(404, again.status());
        assertEquals("SESSION_NOT_FOUND", again.body().get("reason").asText());
        assertEquals(1, ledger("session.end", pseudonymiser.user("synthetic-viewer")).size());
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
            "routine change"), true).body().get("reason").asText());
        assertEquals("INVALID_ROLES", admin.post("/api/v1/admin/users", create("synthetic.mixed",
            List.of("replay_viewer", "viewer"), "routine change"), true).body().get("reason").asText());
        assertEquals("INVALID_ROLES", admin.post("/api/v1/admin/users", create("synthetic.unknown",
            List.of("superuser"), "routine change"), true).body().get("reason").asText());
        created(admin, "synthetic.twice", List.of("viewer"));
        ApiClient.Response twice = admin.post("/api/v1/admin/users", create("Synthetic.Twice", List.of("viewer"),
            "routine change"), true);
        assertEquals(409, twice.status());
        assertEquals("LOCAL_USER_EXISTS", twice.body().get("reason").asText());
        assertEquals("LOCAL_USER_NOT_FOUND", admin.post("/api/v1/admin/users/USR-0000000000/disable",
            reason("routine change"), true).body().get("reason").asText());
        // The break-glass account is listed, read-only.
        JsonNode list = admin.get("/api/v1/admin/users").body();
        assertEquals("breakglass", list.get("breakGlass").get(0).get("loginName").asText());
    }
}
