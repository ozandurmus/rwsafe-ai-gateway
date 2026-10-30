package io.rwsafe.control.policy;

import static io.rwsafe.control.support.EventsJson.batch;
import static io.rwsafe.control.support.EventsJson.event;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.rwsafe.control.config.InternalConnector;
import io.rwsafe.control.support.ApiClient;
import io.rwsafe.control.support.ControlTestEnvironment;
import io.rwsafe.persistence.PolicyRuleVersion;
import io.rwsafe.persistence.PolicySnapshotStore.IssuedSnapshot;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.Signature;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.ArrayList;
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
 * The registry end to end: the seed, the signed snapshot feed of POLICY_SNAPSHOT_CONTRACT, drafts, two approvals by two
 * people, the fail-closed refusals, the simulation stub, the scheduled re-sign and the ledger. Each test leaves the
 * registry changed, so each runs on a fresh context.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class PolicyRegistryIntegrationTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) throws Exception {
        ControlTestEnvironment.register(r, true, true);
    }

    @LocalServerPort
    int port;
    @Autowired
    InternalConnector internal;
    @Autowired
    PolicyRegistryService registry;
    @Autowired
    DataSource dataSource;

    private final HttpClient http = HttpClient.newHttpClient();

    private HttpResponse<byte[]> snapshot(int onPort, String ifNoneMatch) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + onPort
            + SnapshotFeedController.PATH)).GET();
        if (ifNoneMatch != null) {
            b.header("If-None-Match", ifNoneMatch);
        }
        return http.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
    }

    private ApiClient signedIn(String login) throws Exception {
        ApiClient c = new ApiClient(port);
        ApiClient.Response r = c.login(login, ControlTestEnvironment.PASSWORDS.get(login));
        assertEquals(200, r.status(), String.valueOf(r.body()));
        return c;
    }

    private static String draftBody(String action, String mode, String stage) {
        return JSON.createObjectNode().put("action", action).put("mode", mode).put("rolloutStage", stage)
            .put("reasonCode", "SYNTHETIC_CHANGE").toString();
    }

    private static String role(String role) {
        return JSON.createObjectNode().put("role", role).toString();
    }

    private static JsonNode verified(HttpResponse<byte[]> r) throws Exception {
        assertEquals(200, r.statusCode());
        assertEquals(ControlTestEnvironment.SNAPSHOT_KEY_ID, r.headers().firstValue("X-RWSAFE-Key-Id").orElseThrow());
        String signature = r.headers().firstValue("X-RWSAFE-Signature").orElseThrow();
        assertTrue(signature.startsWith("ed25519:"));
        Signature verify = Signature.getInstance("Ed25519");
        verify.initVerify(ControlTestEnvironment.snapshotPublicKey());
        verify.update(r.body());
        assertTrue(verify.verify(Base64.getDecoder().decode(signature.substring("ed25519:".length()))),
            "the signature covers the exact body bytes");
        return JSON.readTree(r.body());
    }

    @Test
    void theFeedServesTheSeedSignedWithETagAnd304OnItsOwnPortOnly() throws Exception {
        HttpResponse<byte[]> first = snapshot(internal.snapshotPort(), null);
        JsonNode doc = verified(first);
        List<String> fields = new ArrayList<>();
        for (Iterator<String> it = doc.fieldNames(); it.hasNext(); ) {
            fields.add(it.next());
        }
        assertEquals(List.of("format", "version", "id", "issuedAt", "enforceFailClosed", "classActions", "platforms"),
            fields);
        assertEquals(1, doc.get("version").asLong());
        assertEquals("\"1\"", first.headers().firstValue("ETag").orElseThrow());
        assertTrue(first.headers().firstValue("Content-Type").orElseThrow().startsWith("application/json"));
        assertEquals("BLOCK", doc.get("classActions").get("SECRET").asText());
        assertEquals(9, doc.get("platforms").size());
        assertTrue(Duration.between(Instant.parse(doc.get("issuedAt").asText()), Instant.now()).toMinutes() < 5);

        HttpResponse<byte[]> again = snapshot(internal.snapshotPort(), null);
        assertEquals(new String(first.body()), new String(again.body()), "unchanged rules: the same bytes");
        HttpResponse<byte[]> notModified = snapshot(internal.snapshotPort(), "\"1\"");
        assertEquals(304, notModified.statusCode());
        assertEquals(0, notModified.body().length);
        assertEquals(200, snapshot(internal.snapshotPort(), "\"0\"").statusCode());

        assertEquals(404, snapshot(port, null).statusCode(), "never on the admin port");
        assertEquals(404, snapshot(internal.port(), null).statusCode(), "never on the capture sink");
        assertEquals(404, new ApiClient(internal.snapshotPort())
            .post("/internal/v1/verdict-events", "[]", false).status(), "ingestion never on the snapshot feed");
        assertEquals(1, ledger("policy_snapshot"));
    }

    @Test
    void aVersionNeedsBothApprovalsFromTwoPeopleThenReachesTheSnapshot() throws Exception {
        ApiClient admin = signedIn("synthetic-admin");
        ApiClient officer = signedIn("synthetic-officer");
        ApiClient viewer = signedIn("synthetic-viewer");
        ApiClient masked = signedIn("synthetic-aiview");

        assertEquals(403, viewer.post("/api/v1/policy/rules/class.TCKN/versions",
            draftBody("BLOCK", "enforce", "all"), true).status());
        assertEquals(403, officer.post("/api/v1/policy/rules/class.TCKN/versions",
            draftBody("BLOCK", "enforce", "all"), true).status(), "drafting is the security administrator's");
        ApiClient.Response draft = admin.post("/api/v1/policy/rules/class.TCKN/versions",
            draftBody("BLOCK", "enforce", "all"), true);
        assertEquals(201, draft.status(), String.valueOf(draft.body()));
        assertEquals(2, draft.body().get("version").asInt());
        assertEquals("pending", draft.body().get("status").asText());
        assertTrue(draft.body().get("author").asText().matches("USR-[0-9a-f]{10}"));

        String approvals = "/api/v1/policy/rules/class.TCKN/versions/2/approvals";
        assertEquals(403, masked.post(approvals, role("security_admin"), true).status());
        ApiClient.Response wrongRole = admin.post(approvals, role("privacy_officer"), true);
        assertEquals(403, wrongRole.status());
        assertEquals("APPROVER_ROLE_MISSING", wrongRole.body().get("reason").asText());
        ApiClient.Response one = admin.post(approvals, role("security_admin"), true);
        assertEquals(200, one.status(), String.valueOf(one.body()));
        assertEquals("pending", one.body().get("status").asText());
        assertEquals("APPROVAL_ROLE_TAKEN", signedIn("synthetic-admin-two").post(approvals, role("security_admin"), true)
            .body().get("reason").asText());

        // Still the seed in the feed until the second approval.
        assertEquals("REDACT", verified(snapshot(internal.snapshotPort(), null)).get("classActions").get("TCKN").asText());
        ApiClient.Response two = officer.post(approvals, role("privacy_officer"), true);
        assertEquals(200, two.status(), String.valueOf(two.body()));
        assertEquals("active", two.body().get("status").asText());
        assertEquals(2, two.body().get("approvals").size());
        assertFalse(two.body().get("approvals").get(0).get("approver").asText()
            .equals(two.body().get("approvals").get(1).get("approver").asText()), "two different people");

        HttpResponse<byte[]> next = snapshot(internal.snapshotPort(), "\"1\"");
        JsonNode doc = verified(next);
        assertEquals(2, doc.get("version").asLong(), "a new version once the rules changed");
        assertEquals("BLOCK", doc.get("classActions").get("TCKN").asText());

        JsonNode rules = viewer.get("/api/v1/policy/rules").body();
        JsonNode tckn = find(rules.get("rules"), "class.TCKN");
        assertTrue(tckn.get("failClosed").asBoolean());
        assertEquals("active", tckn.get("versions").get(0).get("status").asText());
        assertTrue(tckn.get("versions").get(0).get("inSnapshot").asBoolean());
        assertEquals("superseded", tckn.get("versions").get(1).get("status").asText());
        assertEquals(2, rules.get("snapshot").get("version").asLong());

        ApiClient.Response maskedRules = masked.get("/api/v1/policy/rules");
        assertEquals(200, maskedRules.status());
        assertEquals("true", maskedRules.raw().headers().firstValue("X-RWSAFE-Masked").orElseThrow());

        assertEquals(1, ledger("policy_rule_version", "INSERT", "policy.draft"));
        assertEquals(2, ledger("policy_approval", "INSERT", "policy.approve"));
        assertEquals(2, ledger("policy_rule_version", "UPDATE", "policy.activate"));
        assertEquals(2, ledger("policy_snapshot"));
    }

    @Test
    void failClosedClassesAreNeverRelaxedAndTakeNoException() throws Exception {
        ApiClient admin = signedIn("synthetic-admin");
        for (String mode : new String[] {"enforce", "monitor"}) {
            for (String action : new String[] {"ALLOW", "WARN"}) {
                ApiClient.Response r = admin.post("/api/v1/policy/rules/class.SECRET/versions",
                    draftBody(action, mode, "all"), true);
                assertEquals(409, r.status(), mode + " " + action);
                assertEquals("FAIL_CLOSED_CLASS_NOT_RELAXABLE", r.body().get("reason").asText());
            }
        }
        ApiClient.Response flow = admin.post("/api/v1/policy/rules/flow.ai-category/versions",
            JSON.createObjectNode().put("enforceFailClosed", false).put("mode", "enforce").put("rolloutStage", "all")
                .put("reasonCode", "SYNTHETIC_CHANGE").toString(), true);
        assertEquals("FAIL_CLOSED_FLOW_NOT_RELAXABLE", flow.body().get("reason").asText());
        ApiClient.Response exception = admin.post("/api/v1/policy/rules/class.TCKN/exceptions", "{}", true);
        assertEquals(409, exception.status());
        assertEquals("FAIL_CLOSED_NO_EXCEPTION", exception.body().get("reason").asText());
        assertEquals("INVALID_DRAFT", admin.post("/api/v1/policy/rules/class.TCKN/versions",
            draftBody("BLOCK", "shadow", "all"), true).body().get("reason").asText());
        assertEquals(400, admin.post("/api/v1/policy/rules/class.TCKN/versions",
            "{\"action\":\"BLOCK\",\"mode\":\"enforce\",\"rolloutStage\":\"all\",\"reasonCode\":\"SYNTHETIC_CHANGE\","
                + "\"note\":\"x\"}", true).status(), "unknown fields are refused");
        assertEquals(0, ledger("policy_rule_version", "INSERT", "policy.draft"));
    }

    @Test
    void aPlatformRowIsVendorHostsOnly() throws Exception {
        ApiClient admin = signedIn("synthetic-admin");
        String base = "/api/v1/policy/rules/platform.synthetic-vendor/versions";
        ApiClient.Response overlap = admin.post(base, platform("[\"api.anthropic.com\"]", "[]"), true);
        assertEquals("INVALID_PLATFORM_ROW", overlap.body().get("reason").asText());
        ApiClient.Response address = admin.post(base, platform("[\"192.0.2.10\"]", "[]"), true);
        assertEquals("INVALID_PLATFORM_ROW", address.body().get("reason").asText());
        ApiClient.Response estate = admin.post(base, platform("[\"synthetic-estate.example\"]", "[]"), true);
        assertEquals("ESTATE_NAME_REFUSED", estate.body().get("reason").asText());
        ApiClient.Response ok = admin.post(base, platform("[\"vendor.example\"]", "[\"api.vendor.example\"]"), true);
        assertEquals(201, ok.status(), String.valueOf(ok.body()));
        assertEquals(1, ok.body().get("version").asInt());
    }

    // PR 16 review D-04: the activating approval compiles the would-be registry in its own transaction.

    @Test
    void anActivationThatWouldNotCompileIsRefusedAndRolledBack() throws Exception {
        ApiClient admin = signedIn("synthetic-admin");
        ApiClient officer = signedIn("synthetic-officer");
        assertEquals(201, admin.post("/api/v1/policy/rules/platform.vendor-a/versions",
            platform("[\"vendor.example\"]", "[]"), true).status());
        // Valid against the active rows when drafted, but it overlaps vendor-a once that is active.
        assertEquals(201, admin.post("/api/v1/policy/rules/platform.vendor-b/versions",
            platform("[\"api.vendor.example\"]", "[]"), true).status());
        assertEquals(200, admin.post("/api/v1/policy/rules/platform.vendor-a/versions/1/approvals",
            role("security_admin"), true).status());
        assertEquals(200, officer.post("/api/v1/policy/rules/platform.vendor-a/versions/1/approvals",
            role("privacy_officer"), true).status());
        assertEquals(200, admin.post("/api/v1/policy/rules/platform.vendor-b/versions/1/approvals",
            role("security_admin"), true).status());
        ApiClient.Response refused = officer.post("/api/v1/policy/rules/platform.vendor-b/versions/1/approvals",
            role("privacy_officer"), true);
        assertEquals(409, refused.status());
        assertEquals("ACTIVATION_WOULD_NOT_COMPILE", refused.body().get("reason").asText());
        JsonNode b = find(admin.get("/api/v1/policy/rules").body().get("rules"), "platform.vendor-b").get("versions")
            .get(0);
        assertEquals("pending", b.get("status").asText());
        assertEquals(1, b.get("approvals").size(), "the refused approval is rolled back with the activation");
        JsonNode doc = verified(snapshot(internal.snapshotPort(), null));
        assertEquals(10, doc.get("platforms").size(), "the feed still compiles, with vendor-a");
    }

    // PR 16 review D-05: every free registry value is checked against the estate dictionary and masked.

    @Test
    void platformIdsAndReasonCodesNeverNameTheEstate() throws Exception {
        ApiClient admin = signedIn("synthetic-admin");
        assertEquals("ESTATE_NAME_REFUSED", admin.post("/api/v1/policy/rules/platform.synthetic-estate-vendor/versions",
            platform("[\"vendor.example\"]", "[]"), true).body().get("reason").asText());
        assertEquals("ESTATE_NAME_REFUSED", admin.post("/api/v1/policy/rules/class.TCKN/versions",
            JSON.createObjectNode().put("action", "BLOCK").put("mode", "enforce").put("rolloutStage", "all")
                .put("reasonCode", "SYNTHETIC_ESTATE_REVIEW").toString(), true).body().get("reason").asText());
    }

    @Autowired
    io.rwsafe.control.privacy.Masking masking;
    @Autowired
    ObjectMapper springJson;

    @Test
    void theMaskedRegistryMasksReasonCodesRuleVersionsAndTheKeyId() throws Exception {
        PolicyRuleVersion v = new PolicyRuleVersion("platform.synthetic-estate", 1, "platform", null, null,
            "synthetic-estate", List.of("synthetic-estate.example"), List.of(), List.of(), null, "enforce", "all",
            "active", "registry", "USR-00000000a1", "SYNTHETIC-ESTATE", Instant.EPOCH, Instant.EPOCH, null, List.of());
        IssuedSnapshot s = new IssuedSnapshot(1, "registry-000000000000", Instant.EPOCH, "a".repeat(64), "b".repeat(64),
            "{}", List.of("platform.synthetic-estate@v1"), List.of("system:seed-fixture"));
        PolicyViews.RegistryView view = PolicyViews.RegistryView.of(List.of(v), s, "synthetic-estate-key");
        String plain = springJson.writeValueAsString(view).toLowerCase(java.util.Locale.ROOT);
        assertTrue(plain.contains("synthetic-estate"), "the unmasked view carries the synthetic term");
        String masked = springJson.writeValueAsString(view.masked(masking.masker())).toLowerCase(java.util.Locale.ROOT);
        assertFalse(masked.contains("synthetic-estate"), masked);
    }

    // PR 16 review D-06: nothing is issued or ledgered as signed without a signing key.

    @Autowired
    io.rwsafe.persistence.Database database;
    @Autowired
    io.rwsafe.control.privacy.Pseudonymiser pseudonymiser;
    @Autowired
    io.rwsafe.control.privacy.PrivacyKeys keys;

    @Test
    void withoutASigningKeyNoSnapshotIsIssuedOrLedgered() {
        io.rwsafe.control.config.ControlProperties props = new io.rwsafe.control.config.ControlProperties(null, null,
            null, null, new io.rwsafe.control.config.ControlProperties.Policy(null,
                ControlTestEnvironment.dir().resolve("absent-signing-key"), "k1", null, null), null, null);
        PolicyRegistryService unsigned = new PolicyRegistryService(database, props, pseudonymiser, keys,
            new SnapshotSigner(props));
        assertEquals("SNAPSHOT_SIGNING_UNAVAILABLE",
            org.junit.jupiter.api.Assertions.assertThrows(RegistryRefusal.class, unsigned::currentSnapshot).reason());
        unsigned.reissueWhenDue();
        assertTrue(database.policySnapshots().latest().isEmpty());
        assertEquals(0, ledger("policy_snapshot"));
    }

    private static String platform(String suffixes, String apiHosts) {
        return "{\"hostSuffixes\":" + suffixes + ",\"apiHosts\":" + apiHosts + ",\"loginHosts\":[],\"mode\":\"enforce\","
            + "\"rolloutStage\":\"all\",\"reasonCode\":\"SYNTHETIC_CHANGE\"}";
    }

    @Test
    void theSimulationCountsHowStoredVerdictsWouldChange() throws Exception {
        ApiClient sink = new ApiClient(internal.port());
        assertEquals(202, sink.post("/internal/v1/verdict-events", batch(event("claude", "REDACT", null, null),
            event("claude", "REDACT", null, null), event("openai", "ALLOW", null, null)), false).status());
        ApiClient viewer = signedIn("synthetic-viewer");
        JsonNode sim = viewer.get("/api/v1/policy/simulation?ruleId=class.TCKN&action=BLOCK").body();
        assertEquals("REDACT", sim.get("currentAction").asText());
        assertEquals(3, sim.get("eventsInWindow").asLong());
        assertEquals(2, sim.get("eventsWithClass").asLong());
        assertEquals(2, sim.get("eventsChanged").asLong());
        assertEquals("REDACT", sim.get("transitions").get(0).get("from").asText());
        assertEquals("BLOCK", sim.get("transitions").get(0).get("to").asText());
        JsonNode same = viewer.get("/api/v1/policy/simulation?ruleId=class.TCKN&action=REDACT").body();
        assertEquals(0, same.get("eventsChanged").asLong());
        assertEquals("SIMULATION_NOT_SUPPORTED", viewer.get(
            "/api/v1/policy/simulation?ruleId=platform.claude&action=BLOCK").body().get("reason").asText());
    }

    @Test
    void theActivePolicyIsReSignedAtLeastEverySixHours() throws Exception {
        registry.reissueWhenDue();
        IssuedSnapshot first = registry.latestSnapshot().orElseThrow(() -> new AssertionError("the scheduler issues"));
        registry.reissueWhenDue();
        assertEquals(first, registry.latestSnapshot().orElseThrow(), "a fresh snapshot is not re-issued");
        IssuedSnapshot sameWindow = registry.currentSnapshot(first.issuedAt().plus(Duration.ofHours(5)));
        assertEquals(first.version(), sameWindow.version());
        IssuedSnapshot reissued = registry.currentSnapshot(first.issuedAt().plus(Duration.ofHours(6)));
        assertEquals(first.version() + 1, reissued.version(), "re-issued with the next version");
        assertEquals(first.rulesDigest(), reissued.rulesDigest(), "no rule changed");
        assertEquals(first.issuedAt().plus(Duration.ofHours(6)), reissued.issuedAt(), "a fresh issuedAt");
        JsonNode doc = JSON.readTree(reissued.document());
        assertEquals(reissued.version(), doc.get("version").asLong());
        assertEquals(reissued.issuedAt().toString(), doc.get("issuedAt").asText());
        assertEquals(2, ledger("policy_snapshot"), "each re-issue is ledgered");
        assertNotNull(new JdbcTemplate(dataSource).queryForObject(
            "SELECT reason_code FROM audit_event WHERE table_name = 'policy_snapshot' AND row_key = ?", String.class,
            String.valueOf(reissued.version())));
    }

    private int ledger(String table) {
        return new JdbcTemplate(dataSource).queryForObject(
            "SELECT count(*) FROM audit_event WHERE table_name = ?", Integer.class, table);
    }

    private int ledger(String table, String operation, String action) {
        return new JdbcTemplate(dataSource).queryForObject("SELECT count(*) FROM audit_event WHERE table_name = ? "
            + "AND operation = ? AND action_id = ?", Integer.class, table, operation, action);
    }

    private static JsonNode find(JsonNode rules, String ruleId) {
        for (JsonNode r : rules) {
            if (r.get("ruleId").asText().equals(ruleId)) {
                return r;
            }
        }
        throw new AssertionError(ruleId + " not listed");
    }
}
