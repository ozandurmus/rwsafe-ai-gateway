package io.rwsafe.control.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.rwsafe.control.config.ControlProperties;
import io.rwsafe.control.config.InternalConnector;
import io.rwsafe.control.privacy.PrivacyKeys;
import io.rwsafe.control.privacy.Pseudonymiser;
import io.rwsafe.control.support.ApiClient;
import io.rwsafe.control.support.ControlTestEnvironment;
import io.rwsafe.persistence.Database;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.Signature;
import java.util.Base64;
import java.util.Set;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * The pilot single-approval switch on (PO decision Q-47, decision 2; {@code RWSAFE_POLICY_SINGLE_APPROVAL=true}): one
 * security administrator's approval with a reason activates a version at once, it is ledgered as a single-approval
 * activation and it reaches the signed snapshot; a privacy officer never activates alone, the masked role never
 * approves, a missing or identifier-bearing reason is refused. With the switch off the service behaves as before and
 * refuses a reason. Each test leaves the registry changed, so each runs on a fresh context.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class PolicySingleApprovalIntegrationTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String REASON = "Synthetic pilot change";

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) throws Exception {
        ControlTestEnvironment.register(r, true, true);
        r.add("rwsafe.policy.single-approval", () -> "true");
    }

    @LocalServerPort
    int port;
    @Autowired
    InternalConnector internal;
    @Autowired
    DataSource dataSource;
    @Autowired
    Database database;
    @Autowired
    Pseudonymiser pseudonymiser;
    @Autowired
    PrivacyKeys keys;
    @Autowired
    PolicyRegistryService registry;

    private ApiClient signedIn(String login) throws Exception {
        ApiClient c = new ApiClient(port);
        ApiClient.Response r = c.login(login, ControlTestEnvironment.PASSWORDS.get(login));
        assertEquals(200, r.status(), String.valueOf(r.body()));
        return c;
    }

    private static String draftBody(String action) {
        return JSON.createObjectNode().put("action", action).put("mode", "enforce").put("reasonCode", "SYNTHETIC_CHANGE")
            .toString();
    }

    private static String approval(String role, String reason) {
        var body = JSON.createObjectNode().put("role", role);
        if (reason != null) {
            body.put("reason", reason);
        }
        return body.toString();
    }

    private JsonNode snapshot() throws Exception {
        HttpResponse<byte[]> r = HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"
            + internal.snapshotPort() + SnapshotFeedController.PATH)).GET().build(), HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(200, r.statusCode());
        String signature = r.headers().firstValue("X-RWSAFE-Signature").orElseThrow();
        Signature verify = Signature.getInstance("Ed25519");
        verify.initVerify(ControlTestEnvironment.snapshotPublicKey());
        verify.update(r.body());
        assertTrue(verify.verify(Base64.getDecoder().decode(signature.substring("ed25519:".length()))));
        return JSON.readTree(r.body());
    }

    @Test
    void oneSecurityAdministratorActivatesAloneWithAReasonLedgeredAndSigned() throws Exception {
        ApiClient admin = signedIn("synthetic-admin");
        ApiClient viewer = signedIn("synthetic-viewer");
        ApiClient masked = signedIn("synthetic-aiview");
        assertTrue(viewer.get("/api/v1/policy/rules").body().get("singleApproval").asBoolean(),
            "the screen learns the switch from the registry read");
        assertEquals("REDACT", snapshot().get("classActions").get("TCKN").asText());

        ApiClient.Response draft = admin.post("/api/v1/policy/rules/class.TCKN/versions", draftBody("BLOCK"), true);
        assertEquals(201, draft.status(), String.valueOf(draft.body()));
        String approvals = "/api/v1/policy/rules/class.TCKN/versions/2/approvals";

        assertEquals(403, masked.post(approvals, approval("security_admin", REASON), true).status(),
            "the masked role never approves");
        assertEquals(403, viewer.post(approvals, approval("security_admin", REASON), true).status());
        ApiClient.Response missing = admin.post(approvals, approval("security_admin", null), true);
        assertEquals(400, missing.status());
        assertEquals("INVALID_SINGLE_APPROVAL", missing.body().get("reason").asText());
        ApiClient.Response blank = admin.post(approvals, approval("security_admin", "   "), true);
        assertEquals("INVALID_SINGLE_APPROVAL", blank.body().get("reason").asText());
        ApiClient.Response identifier = admin.post(approvals, approval("security_admin", "see 192.0.2.10"), true);
        assertEquals(400, identifier.status());
        assertEquals("REASON_HOLDS_IDENTIFIER", identifier.body().get("reason").asText());
        assertFalse(identifier.body().toString().contains("192.0.2.10"), "the refusal never echoes the reason");
        assertEquals(0, ledger("policy_approval", "INSERT", "policy.approve"), "refusals change nothing");

        ApiClient.Response alone = admin.post(approvals, approval("security_admin", REASON), true);
        assertEquals(200, alone.status(), String.valueOf(alone.body()));
        assertEquals("active", alone.body().get("status").asText());
        assertEquals(1, alone.body().get("approvals").size());
        String by = alone.body().get("approvals").get(0).get("approver").asText();
        assertTrue(by.matches("USR-[0-9a-f]{10}"));
        assertEquals(by, alone.body().get("singleApproval").get("activatedBy").asText());
        assertEquals(REASON, alone.body().get("singleApproval").get("reason").asText());

        JsonNode doc = snapshot();
        assertEquals(2, doc.get("version").asLong(), "a new signed snapshot once the rules changed");
        assertEquals("BLOCK", doc.get("classActions").get("TCKN").asText());
        JsonNode rules = viewer.get("/api/v1/policy/rules").body();
        assertTrue(rules.get("snapshot").get("ruleVersions").toString().contains("class.TCKN@v2"));

        // The ledger: one approval, and the activation under its own action with the administrator and the reason.
        assertEquals(1, ledger("policy_approval", "INSERT", "policy.approve"));
        assertEquals(1, new JdbcTemplate(dataSource).queryForObject("SELECT count(*) FROM audit_event WHERE "
            + "table_name = 'policy_rule_version' AND operation = 'UPDATE' AND action_id = "
            + "'policy.activate_single_approval' AND actor_fingerprint = ? AND reason_code = ? "
            + "AND row_key = 'class.TCKN@v2'", Integer.class, by, REASON));
        assertEquals(0, ledger("policy_rule_version", "UPDATE", "policy.activate"));

        JsonNode maskedRules = masked.get("/api/v1/policy/rules").body();
        assertFalse(maskedRules.toString().contains(REASON), "the masked role never reads the free-text reason");
        assertTrue(maskedRules.get("singleApproval").asBoolean());
    }

    @Test
    void aPrivacyOfficerNeverActivatesAlone() throws Exception {
        ApiClient admin = signedIn("synthetic-admin");
        ApiClient officer = signedIn("synthetic-officer");
        assertEquals(201, admin.post("/api/v1/policy/rules/class.PAYMENT_CARD/versions", draftBody("BLOCK"), true)
            .status());
        String approvals = "/api/v1/policy/rules/class.PAYMENT_CARD/versions/2/approvals";
        ApiClient.Response withReason = officer.post(approvals, approval("privacy_officer", REASON), true);
        assertEquals(400, withReason.status());
        assertEquals("SINGLE_APPROVAL_NOT_AVAILABLE", withReason.body().get("reason").asText());
        assertEquals(403, officer.post(approvals, approval("security_admin", REASON), true).status(),
            "a privacy officer cannot approve as a security administrator");
        ApiClient.Response once = officer.post(approvals, approval("privacy_officer", null), true);
        assertEquals(200, once.status(), String.valueOf(once.body()));
        assertEquals("pending", once.body().get("status").asText());
        assertEquals("REDACT", snapshot().get("classActions").get("PAYMENT_CARD").asText());
        assertEquals(0, ledger("policy_rule_version", "UPDATE", "policy.activate_single_approval"));

        // The security administrator's approval then completes the two approvals: an ordinary activation.
        ApiClient.Response two = admin.post(approvals, approval("security_admin", REASON), true);
        assertEquals("active", two.body().get("status").asText());
        assertEquals(2, two.body().get("approvals").size());
        assertTrue(two.body().get("singleApproval").isNull());
        assertEquals(2, ledger("policy_rule_version", "UPDATE", "policy.activate"),
            "the activation and the seed version's supersede, under the two-approval context");
    }

    @Test
    void withTheSwitchOffTheServiceKeepsTheTwoApprovalsAndRefusesAReason() {
        ControlProperties props = new ControlProperties(null, null, null, null, new ControlProperties.Policy(null,
            ControlTestEnvironment.dir().resolve("snapshot-signing.key"), ControlTestEnvironment.SNAPSHOT_KEY_ID, null,
            null, false), null, null, null);
        PolicyRegistryService off = new PolicyRegistryService(database, props, pseudonymiser, keys,
            new SnapshotSigner(props));
        assertFalse(off.singleApproval());
        assertTrue(registry.singleApproval());
        off.draft("class.TCKN", new PolicyRegistryService.DraftRequest("BLOCK", null, null, null, null, "enforce", null,
            null, "SYNTHETIC_CHANGE"), "synthetic-admin", Set.of("security_admin"));
        assertEquals("SINGLE_APPROVAL_NOT_AVAILABLE", assertThrows(RegistryRefusal.class, () -> off.approve(
            "class.TCKN", 2, "security_admin", REASON, "synthetic-admin", Set.of("security_admin"))).reason());
        assertEquals("pending", off.approve("class.TCKN", 2, "security_admin", null, "synthetic-admin",
            Set.of("security_admin")).status(), "one approval with the switch off leaves the version pending");
        assertEquals(0, ledger("policy_rule_version", "UPDATE", "policy.activate_single_approval"));
    }

    private int ledger(String table, String operation, String action) {
        return new JdbcTemplate(dataSource).queryForObject("SELECT count(*) FROM audit_event WHERE table_name = ? "
            + "AND operation = ? AND action_id = ?", Integer.class, table, operation, action);
    }
}
