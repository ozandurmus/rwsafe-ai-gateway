package io.rwsafe.control.identity;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.rwsafe.control.privacy.Pseudonymiser;
import io.rwsafe.control.support.ApiClient;
import io.rwsafe.control.support.ControlTestEnvironment;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
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
 * Administration -> Access -> Directory settings end to end (PO decision Q-47, decision 1.2) against the synthetic
 * in-memory directory: the deploy values seed an empty table once and never override a saved setting, the bind password
 * is sealed and never returned (a save without one keeps it), every save is a ledgered version that the sign-in uses at
 * once, the group -> role bindings are the one source of directory roles (GroupNames form), the connection test answers
 * classes under a rate limit, nothing identifying is logged, and only a security_admin reaches the routes.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(OutputCaptureExtension.class)
class DirectorySettingsIntegrationTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String SEED_ADMIN = "synthetic-diradmin-seed";
    private static final String SAVE_ADMIN = "synthetic-diradmin-save";
    private static final String GROUP_ADMIN = "synthetic-diradmin-groups";
    private static final String TEST_ADMIN = "synthetic-diradmin-test";
    private static final String GROUP_USER = "synthetic-dirviewer";

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) throws Exception {
        ControlTestEnvironment.register(r, true, true);
        for (String admin : List.of(SEED_ADMIN, SAVE_ADMIN, GROUP_ADMIN, TEST_ADMIN)) {
            ControlTestEnvironment.addUser(admin, "security_admin");
        }
        ControlTestEnvironment.addUser(GROUP_USER, "viewer");
    }

    @LocalServerPort
    int port;
    @Autowired
    DataSource dataSource;
    @Autowired
    DirectorySettingsService directory;
    @Autowired
    Pseudonymiser pseudonymiser;
    @Autowired
    io.rwsafe.persistence.Database database;

    private ApiClient signedIn(String login) throws Exception {
        ApiClient c = new ApiClient(port);
        ApiClient.Response r = c.login(login, ControlTestEnvironment.PASSWORDS.get(login));
        assertEquals(200, r.status(), login + " " + r.body());
        return c;
    }

    private ApiClient.Response login(String login) throws Exception {
        return new ApiClient(port).login(login, ControlTestEnvironment.PASSWORDS.get(login));
    }

    /** The saved connection as a save request, with the current version, a reason and optional changes. */
    private static ObjectNode connection(JsonNode view, String reason) {
        JsonNode s = view.get("settings");
        ObjectNode body = JSON.createObjectNode();
        body.put("expectedVersion", view.get("version").asInt());
        body.put("enabled", s.get("enabled").asBoolean());
        body.set("urls", s.get("urls").deepCopy());
        body.put("tlsMode", s.get("tlsMode").asText());
        body.put("bindDn", s.get("bindDn").asText());
        body.put("userSearchBase", s.get("userSearchBase").asText());
        body.put("userSearchFilter", s.get("userSearchFilter").asText());
        body.put("groupAttribute", s.get("groupAttribute").asText());
        body.put("connectTimeoutMs", s.get("connectTimeoutMs").asInt());
        body.put("responseTimeoutMs", s.get("responseTimeoutMs").asInt());
        if (reason != null) {
            body.put("reason", reason);
        }
        return body;
    }

    private static ObjectNode groups(JsonNode view, String reason, List<Map.Entry<String, List<String>>> bindings) {
        ObjectNode body = JSON.createObjectNode().put("expectedVersion", view.get("version").asInt())
            .put("reason", reason);
        ArrayNode list = body.putArray("bindings");
        for (Map.Entry<String, List<String>> b : bindings) {
            ObjectNode e = list.addObject().put("group", b.getKey());
            ArrayNode roles = e.putArray("roles");
            b.getValue().forEach(r -> roles.add(r));
        }
        return body;
    }

    private static List<Map.Entry<String, List<String>>> current(JsonNode view) {
        List<Map.Entry<String, List<String>>> out = new ArrayList<>();
        for (JsonNode g : view.get("settings").get("groupRoles")) {
            List<String> roles = new ArrayList<>();
            g.get("roles").forEach(r -> roles.add(r.asText()));
            out.add(Map.entry(g.get("group").asText(), roles));
        }
        return out;
    }

    private byte[] sealed(int version) {
        return new JdbcTemplate(dataSource).queryForObject(
            "SELECT bind_password_sealed FROM directory_settings WHERE version = ?", byte[].class, version);
    }

    private List<Map<String, Object>> ledger(String action) {
        return new JdbcTemplate(dataSource).queryForList("SELECT actor_fingerprint, action_id, reason_code, row_key "
            + "FROM audit_event WHERE table_name = 'directory_settings' AND action_id = ? ORDER BY audit_id", action);
    }

    @Autowired
    org.springframework.core.env.Environment environment;

    /** PR 50 review Q-1: the suite runs the test-only switch under the test profile, so no start-up alarm fires. */
    @Test
    void theTestSwitchRunsUnderTheTestProfile() {
        assertTrue(directory.localTargets());
        assertTrue(DirectorySettingsService.testProfile(environment));
        assertFalse(DirectorySettingsService.testSwitchAlarm(directory.localTargets(),
            DirectorySettingsService.testProfile(environment)));
    }

    @Test
    void theDeployValuesSeedOnceAndNeverOverrideASavedSetting() throws Exception {
        ApiClient admin = signedIn(SEED_ADMIN);
        JsonNode view = admin.get("/api/v1/admin/directory").body();
        assertEquals("ACTIVE", view.get("status").asText());
        assertEquals("AVAILABLE", view.get("keyState").asText());
        assertTrue(view.get("deployValuesPresent").asBoolean());
        JsonNode history = view.get("history");
        JsonNode first = history.get(history.size() - 1);
        assertEquals(1, first.get("version").asInt());
        assertEquals("seed", first.get("changeKind").asText());
        assertEquals(DirectorySettingsService.SEED_ACTOR, first.get("actor").asText());
        List<Map<String, Object>> seeded = ledger("directory_settings.seed");
        assertEquals(1, seeded.size());
        assertEquals(DirectorySettingsService.SEED_ACTOR, seeded.get(0).get("actor_fingerprint"));
        assertEquals("1", seeded.get(0).get("row_key"));
        // The deploy's group DNs became bindings by the group's name (the first RDN's value).
        List<String> names = current(view).stream().map(Map.Entry::getKey).toList();
        assertTrue(names.contains("rwsafe-security_admin") && names.contains("rwsafe-replay_viewer"), names.toString());
        assertTrue(names.stream().noneMatch(n -> n.contains(",")));

        // A screen save, then what a restart does: the seed is skipped and the saved value stays.
        ObjectNode change = connection(view, "routine timeout change");
        change.put("responseTimeoutMs", 9_000);
        ApiClient.Response saved = admin.post("/api/v1/admin/directory/connection", change.toString(), true);
        assertEquals(200, saved.status(), String.valueOf(saved.body()));
        int version = saved.body().get("version").asInt();
        directory.seedFromDeploy();
        directory.reload();
        JsonNode after = admin.get("/api/v1/admin/directory").body();
        assertEquals(version, after.get("version").asInt());
        assertEquals(9_000, after.get("settings").get("responseTimeoutMs").asInt());
        assertEquals(1, ledger("directory_settings.seed").size());
        assertEquals(200, login("synthetic-admin").status(), "the directory sign-in works after the reload");
    }

    @Test
    void thePasswordIsNeverReturnedAndASaveWithoutOneKeepsIt(CapturedOutput output) throws Exception {
        ApiClient admin = signedIn(SAVE_ADMIN);
        String bindPassword = ControlTestEnvironment.bindPassword();
        ApiClient.Response got = admin.get("/api/v1/admin/directory");
        assertTrue(got.raw().headers().firstValue("Cache-Control").orElse("").contains("no-store"));
        JsonNode view = got.body();
        assertTrue(view.get("settings").get("passwordSet").asBoolean());
        assertFalse(got.raw().body().contains(bindPassword));
        assertFalse(got.raw().body().toLowerCase(java.util.Locale.ROOT).contains("sealed"));
        int before = view.get("version").asInt();
        byte[] sealedBefore = sealed(before);
        assertFalse(new String(sealedBefore, StandardCharsets.ISO_8859_1).contains(bindPassword));

        // Without a new password the stored one is carried over unchanged.
        ObjectNode keep = connection(view, "routine keep password");
        keep.put("connectTimeoutMs", 4_000);
        ApiClient.Response kept = admin.post("/api/v1/admin/directory/connection", keep.toString(), true);
        assertEquals(200, kept.status(), String.valueOf(kept.body()));
        assertFalse(kept.raw().body().contains(bindPassword));
        int keptVersion = kept.body().get("version").asInt();
        assertEquals(before + 1, keptVersion);
        // Kept, but sealed again for the new version (PR 50 review D-01): the old ciphertext opens only for its own.
        assertFalse(java.util.Arrays.equals(sealedBefore, sealed(keptVersion)));
        assertEquals(200, login("synthetic-officer").status());
        List<Map<String, Object>> ledgered = ledger("directory_settings.connection");
        Map<String, Object> last = ledgered.get(ledgered.size() - 1);
        assertEquals(pseudonymiser.user(SAVE_ADMIN), last.get("actor_fingerprint"));
        assertEquals("routine keep password", last.get("reason_code"));
        assertEquals(String.valueOf(keptVersion), last.get("row_key"));

        // A wrong new password: the next sign-in already uses it (no restart) and fails; the right one restores it.
        ObjectNode wrong = connection(kept.body(), "routine wrong password");
        wrong.put("newPassword", "not-" + bindPassword);
        assertEquals(200, admin.post("/api/v1/admin/directory/connection", wrong.toString(), true).status());
        assertEquals(401, login("synthetic-officer").status());
        JsonNode now = admin.get("/api/v1/admin/directory").body();
        ObjectNode right = connection(now, "routine right password");
        right.put("newPassword", bindPassword);
        assertEquals(200, admin.post("/api/v1/admin/directory/connection", right.toString(), true).status());
        assertEquals(200, login("synthetic-officer").status());

        // PR 50 review D-01: without a new password, another server, TLS mode or CA bundle is refused; the stored
        // password never goes where it was not saved for.
        JsonNode saved = admin.get("/api/v1/admin/directory").body();
        ObjectNode elsewhere = connection(saved, "routine move");
        elsewhere.putArray("urls").add("ldap://127.0.0.1:" + (ControlTestEnvironment.ldapPort() + 1));
        assertEquals("PASSWORD_REQUIRED", admin.post("/api/v1/admin/directory/connection", elsewhere.toString(), true)
            .body().get("reason").asText());
        ObjectNode otherTls = connection(saved, "routine encryption");
        otherTls.put("tlsMode", "starttls");
        assertEquals("PASSWORD_REQUIRED", admin.post("/api/v1/admin/directory/connection", otherTls.toString(), true)
            .body().get("reason").asText());
        ObjectNode otherDn = connection(saved, "routine account");
        otherDn.put("bindDn", "cn=synthetic-other," + ControlTestEnvironment.BASE);
        assertEquals("PASSWORD_REQUIRED", admin.post("/api/v1/admin/directory/connection", otherDn.toString(), true)
            .body().get("reason").asText());
        ObjectNode farPort = connection(saved, "routine port");
        farPort.put("tlsMode", "ldaps").putArray("urls").add("ldaps://synthetic-dc.example.test:5432");
        assertEquals("PORT_NOT_ALLOWED", admin.post("/api/v1/admin/directory/connection", farPort.toString(), true)
            .body().get("reason").asText());
        // PR 50 review D-06: a word of a directory DN in the reason (here the user search base's) is refused.
        assertEquals("REASON_HOLDS_IDENTIFIER", admin.post("/api/v1/admin/directory/connection",
            connection(saved, "the people branch moved").toString(), true).body().get("reason").asText());

        // PR 50 review D-08: switching the directory off ends the open directory sessions, not the administrator's own.
        ApiClient open = signedIn("synthetic-viewer");
        assertEquals(200, open.get("/api/v1/auth/me").status());
        ObjectNode off = connection(saved, "routine pause");
        off.put("enabled", false);
        ApiClient.Response paused = admin.post("/api/v1/admin/directory/connection", off.toString(), true);
        assertEquals(200, paused.status(), String.valueOf(paused.body()));
        assertEquals("DISABLED", paused.body().get("status").asText());
        assertEquals(401, open.get("/api/v1/auth/me").status(), "the open directory session ended");
        assertEquals(200, admin.get("/api/v1/admin/directory").status(), "the administrator's own session stays");
        assertEquals(401, login("synthetic-viewer").status());
        ObjectNode on = connection(paused.body(), "routine resume");
        on.put("enabled", true);
        assertEquals(200, admin.post("/api/v1/admin/directory/connection", on.toString(), true).status());
        assertEquals(200, login("synthetic-viewer").status(), "the password was kept across the pause");

        // A stale version, a missing reason, a reason holding an identifier, plain LDAP to a remote host: refused.
        ApiClient.Response stale = admin.post("/api/v1/admin/directory/connection", keep.toString(), true);
        assertEquals(409, stale.status());
        assertEquals("DIRECTORY_SETTINGS_CHANGED", stale.body().get("reason").asText());
        JsonNode latest = admin.get("/api/v1/admin/directory").body();
        assertEquals("INVALID_REASON", admin.post("/api/v1/admin/directory/connection",
            connection(latest, null).toString(), true).body().get("reason").asText());
        assertEquals("REASON_HOLDS_IDENTIFIER", admin.post("/api/v1/admin/directory/connection",
            connection(latest, "moved to 192.0.2.10").toString(), true).body().get("reason").asText());
        ObjectNode remote = connection(latest, "routine remote");
        remote.putArray("urls").add("ldap://synthetic-dc.example.test:389");
        assertEquals("PLAIN_LDAP_REFUSED", admin.post("/api/v1/admin/directory/connection", remote.toString(), true)
            .body().get("reason").asText());
        ObjectNode key = connection(latest, "routine key paste");
        key.put("tlsMode", "starttls").put("caCertificatePem", "-----BEGIN PRIVATE" + " KEY-----\nAAAA\n");
        assertEquals("CA_HOLDS_KEY", admin.post("/api/v1/admin/directory/connection", key.toString(), true)
            .body().get("reason").asText());
        assertEquals(latest.get("version").asInt(), admin.get("/api/v1/admin/directory").body().get("version").asInt());
        assertFalse(output.getAll().contains(bindPassword), "the bind password reached the log");
        assertFalse(output.getAll().contains("synthetic-people"), "a directory DN reached the log");
    }

    @Test
    void theGroupBindingsAreTheOneSourceOfDirectoryRolesAndApplyAtOnce(CapturedOutput output) throws Exception {
        ApiClient admin = signedIn(GROUP_ADMIN);
        assertEquals("viewer", login(GROUP_USER).body().get("roles").get(0).asText());
        ApiClient openSession = signedIn(GROUP_USER);
        JsonNode view = admin.get("/api/v1/admin/directory").body();
        List<Map.Entry<String, List<String>>> original = current(view);

        // The viewer group, entered in capitals with a dotted capital I, now gives the privacy officer role.
        List<Map.Entry<String, List<String>>> changed = new ArrayList<>();
        for (Map.Entry<String, List<String>> b : original) {
            changed.add(b.getKey().equals("rwsafe-viewer") ? Map.entry("RWSAFE-VİEWER", List.of("privacy_officer")) : b);
        }
        ApiClient.Response saved = admin.post("/api/v1/admin/directory/group-roles",
            groups(view, "routine regrouping", changed).toString(), true);
        assertEquals(200, saved.status(), String.valueOf(saved.body()));
        // PR 50 review D-08: changed bindings end the open directory sessions, never the administrator's own.
        assertEquals(401, openSession.get("/api/v1/auth/me").status());
        assertEquals(200, admin.get("/api/v1/admin/directory").status());
        ApiClient.Response relogged = login(GROUP_USER);
        assertEquals(200, relogged.status());
        assertEquals("privacy_officer", relogged.body().get("roles").get(0).asText());
        Map<String, Object> ledgered = ledger("directory_settings.group_roles").get(0);
        assertEquals(pseudonymiser.user(GROUP_ADMIN), ledgered.get("actor_fingerprint"));
        assertEquals("routine regrouping", ledgered.get("reason_code"));
        assertEquals(saved.body().get("version").asText(), ledgered.get("row_key"));
        assertFalse(new JdbcTemplate(dataSource).queryForList("SELECT row_key FROM audit_event").toString()
            .toLowerCase(java.util.Locale.ROOT).contains("rwsafe-viewer"), "the ledger never names a group");

        // Without a binding for the user's group the directory gives no role.
        List<Map.Entry<String, List<String>>> without = new ArrayList<>(changed);
        without.removeIf(b -> b.getKey().equals("RWSAFE-VİEWER"));
        assertEquals(200, admin.post("/api/v1/admin/directory/group-roles",
            groups(saved.body(), "routine unbinding", without).toString(), true).status());
        ApiClient.Response noRole = login(GROUP_USER);
        assertEquals(403, noRole.status());
        assertEquals("NO_ROLE", noRole.body().get("reason").asText());

        JsonNode latest = admin.get("/api/v1/admin/directory").body();
        assertEquals("INVALID_GROUP_NAME", admin.post("/api/v1/admin/directory/group-roles", groups(latest, "r dn",
            List.of(Map.entry("cn=rwsafe-viewer,ou=synthetic-groups,dc=example,dc=test", List.of("viewer"))))
            .toString(), true).body().get("reason").asText());
        assertEquals("DUPLICATE_GROUP", admin.post("/api/v1/admin/directory/group-roles", groups(latest, "r dup",
            List.of(Map.entry("synthetic-ıdari", List.of("viewer")), Map.entry("SYNTHETIC-IDARI", List.of("viewer"))))
            .toString(), true).body().get("reason").asText());
        assertEquals("INVALID_ROLES", admin.post("/api/v1/admin/directory/group-roles", groups(latest, "r masked",
            List.of(Map.entry("synthetic-auditors", List.of("replay_viewer", "viewer")))).toString(), true)
            .body().get("reason").asText());

        // A reason that names a bound directory group (any case, Turkish letters folded) is refused.
        ApiClient.Response named = admin.post("/api/v1/admin/directory/group-roles", groups(latest,
            "moved RWSAFE-PRIVACY_OFFICER over", original).toString(), true);
        assertEquals(400, named.status());
        assertEquals("REASON_HOLDS_IDENTIFIER", named.body().get("reason").asText());
        assertFalse(named.raw().body().contains("PRIVACY_OFFICER"), "the refusal never echoes the reason");

        // Restored as seeded.
        assertEquals(200, admin.post("/api/v1/admin/directory/group-roles",
            groups(latest, "routine restore", original).toString(), true).status());
        assertEquals("viewer", login(GROUP_USER).body().get("roles").get(0).asText());
        assertFalse(output.getAll().contains("RWSAFE-VİEWER"), "a group name reached the log");
        assertFalse(output.getAll().contains(GROUP_USER), "a login name reached the log");
    }

    @Test
    void theConnectionTestAnswersClassesUnderARateLimit(CapturedOutput output) throws Exception {
        ApiClient admin = signedIn(TEST_ADMIN);
        JsonNode view = admin.get("/api/v1/admin/directory").body();
        ApiClient.Response saved = admin.post("/api/v1/admin/directory/test", "{}", true);
        assertEquals(200, saved.status(), String.valueOf(saved.body()));
        assertEquals("OK", saved.body().get("result").asText());
        assertEquals(1, saved.body().get("server").asInt());
        assertTrue(saved.raw().headers().firstValue("Cache-Control").orElse("").contains("no-store"));

        JsonNode user = admin.post("/api/v1/admin/directory/test", JSON.createObjectNode()
            .put("loginName", "synthetic-admin").toString(), true).body();
        assertEquals("OK", user.get("result").asText());
        assertEquals(1, user.get("groupsFound").asInt());
        assertEquals(1, user.get("groupsBound").asInt());
        assertEquals("security_admin", user.get("roles").get(0).asText());
        assertFalse(user.toString().contains("synthetic-groups"), "no group or DN in the answer");

        assertEquals("USER_NOT_FOUND", admin.post("/api/v1/admin/directory/test", JSON.createObjectNode()
            .put("loginName", "synthetic-nobody").toString(), true).body().get("result").asText());

        // Unsaved settings for another server: the stored password is not sent there.
        int closed;
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            closed = s.getLocalPort();
        }
        ObjectNode elsewhere = connection(view, null);
        elsewhere.putArray("urls").add("ldap://127.0.0.1:" + closed);
        ApiClient.Response refused = admin.post("/api/v1/admin/directory/test", JSON.createObjectNode()
            .set("settings", elsewhere).toString(), true);
        assertEquals(400, refused.status());
        assertEquals("PASSWORD_REQUIRED", refused.body().get("reason").asText());
        ObjectNode otherMode = connection(view, null);
        otherMode.put("tlsMode", "starttls");
        assertEquals("PASSWORD_REQUIRED", admin.post("/api/v1/admin/directory/test", JSON.createObjectNode()
            .set("settings", otherMode).toString(), true).body().get("reason").asText());
        elsewhere.put("newPassword", "synthetic-entered");
        assertEquals("UNREACHABLE", admin.post("/api/v1/admin/directory/test", JSON.createObjectNode()
            .set("settings", elsewhere).toString(), true).body().get("result").asText());

        ObjectNode wrong = connection(view, null);
        wrong.put("newPassword", "synthetic-wrong");
        JsonNode bind = admin.post("/api/v1/admin/directory/test", JSON.createObjectNode().set("settings", wrong)
            .toString(), true).body();
        assertEquals("BIND_REFUSED", bind.get("result").asText());

        // Six tests a minute per administrator (a refused request spends none: the PASSWORD_REQUIRED above), then a
        // refusal that names the limit; nothing was saved by a test.
        assertEquals("OK", admin.post("/api/v1/admin/directory/test", "{}", true).body().get("result").asText());
        ApiClient.Response limited = admin.post("/api/v1/admin/directory/test", "{}", true);
        assertEquals(429, limited.status());
        assertEquals("DIRECTORY_TEST_RATE_LIMITED", limited.body().get("reason").asText());
        assertEquals(view.get("version").asInt(), admin.get("/api/v1/admin/directory").body().get("version").asInt());
        assertFalse(output.getAll().contains("synthetic-nobody"), "the tested login name reached the log");
        assertFalse(output.getAll().contains("synthetic-people"), "a directory DN reached the log");
        assertTrue(output.getAll().contains("directory connection test: USER_NOT_FOUND"));
    }

    /**
     * PR 50 review D-05: a local user owns its login name in every spelling the sign-in folds to it (Turkish İ/I/ı,
     * case), and a name with surrounding white space is refused before any front, so neither reaches the directory.
     */
    @Test
    void aLocalUserOwnsItsNameInEverySpelling() throws Exception {
        ControlTestEnvironment.addUser("synthetic.dirtwin", "security_admin");
        String directoryPassword = ControlTestEnvironment.PASSWORDS.get("synthetic.dirtwin");
        assertEquals(200, new ApiClient(port).login("synthetic.dirtwin", directoryPassword).status());
        assertEquals(400, new ApiClient(port).login(" synthetic.dirtwin", directoryPassword).status());
        assertEquals(400, new ApiClient(port).login("synthetic.dirtwin\t", directoryPassword).status());

        ApiClient admin = signedIn("synthetic-admin");
        ObjectNode local = JSON.createObjectNode().put("loginName", "synthetic.dirtwin").put("displayName", "Twin")
            .put("reason", "onboarding");
        local.putArray("roles").add("viewer");
        assertEquals(201, admin.post("/api/v1/admin/users", local.toString(), true).status());
        LocalUserAuthenticator locals = new LocalUserAuthenticator(database);
        for (String spelling : List.of("synthetic.dirtwin", "SYNTHETIC.DIRTWIN", "SYNTHET\u0130C.D\u0130RTW\u0130N",
            "synthet\u0131c.d\u0131rtw\u0131n")) {
            assertTrue(locals.authoritative(spelling), "the local row owns this spelling");
            assertEquals(401, new ApiClient(port).login(spelling, directoryPassword).status(),
                "the directory is never asked for a local name");
        }
    }

    @Test
    void onlyASecurityAdministratorReachesTheDirectoryRoutes() throws Exception {
        assertEquals(401, new ApiClient(port).get("/api/v1/admin/directory").status());
        for (String login : List.of("synthetic-viewer", "synthetic-officer", "synthetic-aiview")) {
            ApiClient c = signedIn(login);
            ApiClient.Response read = c.get("/api/v1/admin/directory");
            assertEquals(403, read.status(), login);
            assertEquals("FORBIDDEN", read.body().get("reason").asText());
            assertEquals(403, c.post("/api/v1/admin/directory/test", "{}", true).status(), login);
            assertEquals(403, c.post("/api/v1/admin/directory/group-roles", "{}", true).status(), login);
            assertEquals(403, c.post("/api/v1/admin/directory/connection", "{}", true).status(), login);
        }
        assertNotEquals(403, signedIn("synthetic-admin").get("/api/v1/admin/directory").status());
    }
}
