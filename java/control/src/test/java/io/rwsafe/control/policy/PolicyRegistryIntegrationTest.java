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
@org.junit.jupiter.api.extension.ExtendWith(org.springframework.boot.test.system.OutputCaptureExtension.class)
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
        assertEquals(List.of("format", "version", "id", "issuedAt", "enforceFailClosed", "classActions", "platforms",
            "scopedRules"), fields);
        assertEquals(2, doc.get("format").asInt());
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
                ControlTestEnvironment.dir().resolve("absent-signing-key"), "k1", null, null), null, null, null);
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

    // PO decision Q-39: a version is scoped to everyone or to directory groups; stages are retired.

    private static final String GROUP_ONE = "GRP-ALPHA-SYNTHETIC";
    private static final String GROUP_TWO = "GRP-BETA-SYNTHETIC";
    /** The stored, compared and sent form (GroupNames: trimmed, lower case, the i forms folded). */
    private static final String ONE = "grp-alpha-synthetic";
    private static final String TWO = "grp-beta-synthetic";

    private static String scopedBody(String action, String mode, String... groups) {
        var body = JSON.createObjectNode().put("action", action).put("mode", mode).put("reasonCode", "SYNTHETIC_CHANGE");
        var scope = body.putObject("scope").put("kind", "GROUPS");
        var list = scope.putArray("groups");
        for (String g : groups) {
            list.add(g);
        }
        return body.toString();
    }

    @Test
    void aGroupScopedVersionReachesTheSnapshotAsAScopedRuleAndTheMaskedRoleSeesPseudonyms(
        org.springframework.boot.test.system.CapturedOutput output) throws Exception {
        ApiClient admin = signedIn("synthetic-admin");
        ApiClient officer = signedIn("synthetic-officer");
        ApiClient viewer = signedIn("synthetic-viewer");
        ApiClient masked = signedIn("synthetic-aiview");
        String versions = "/api/v1/policy/rules/class.TR_IBAN/versions";

        ApiClient.Response draft = admin.post(versions, scopedBody("BLOCK", "enforce", " " + GROUP_TWO + " ", GROUP_ONE),
            true);
        assertEquals(201, draft.status(), String.valueOf(draft.body()));
        assertEquals("GROUPS", draft.body().get("scope").get("kind").asText());
        assertEquals("[\"" + ONE + "\",\"" + TWO + "\"]", draft.body().get("scope").get("groups").toString(),
            "normalised and ordered");
        assertEquals("all", draft.body().get("rolloutStage").asText());
        assertEquals(200, admin.post(versions + "/2/approvals", role("security_admin"), true).status());
        assertEquals(200, officer.post(versions + "/2/approvals", role("privacy_officer"), true).status());

        JsonNode doc = verified(snapshot(internal.snapshotPort(), null));
        assertEquals("REDACT", doc.get("classActions").get("TR_IBAN").asText(), "the ANY baseline is unchanged");
        assertEquals("[{\"id\":\"class.TR_IBAN@2\",\"groups\":[\"" + ONE + "\",\"" + TWO + "\"],"
            + "\"mode\":\"enforce\",\"classActions\":{\"TR_IBAN\":\"BLOCK\"}}]", doc.get("scopedRules").toString());

        JsonNode plain = find(viewer.get("/api/v1/policy/rules").body().get("rules"), "class.TR_IBAN");
        assertEquals(ONE, plain.get("versions").get(0).get("scope").get("groups").get(0).asText(),
            "operators see the group names");
        assertEquals("active", plain.get("versions").get(1).get("status").asText(), "the ANY version stays active");
        ApiClient.Response maskedRules = masked.get("/api/v1/policy/rules");
        assertEquals(200, maskedRules.status());
        String maskedText = maskedRules.body().toString().toLowerCase(java.util.Locale.ROOT);
        assertFalse(maskedText.contains("alpha-synthetic") || maskedText.contains("beta-synthetic"), maskedText);
        JsonNode maskedGroups = find(maskedRules.body().get("rules"), "class.TR_IBAN").get("versions").get(0)
            .get("scope").get("groups");
        assertEquals(2, maskedGroups.size());
        for (JsonNode g : maskedGroups) {
            assertTrue(g.asText().matches("GRP-[0-9a-f]{10}"), g.asText());
        }
        String logs = output.getAll().toLowerCase(java.util.Locale.ROOT);
        assertFalse(logs.contains("alpha-synthetic") || logs.contains("beta-synthetic"), "a group name is never logged");
    }

    @Test
    void aScopeIsValidatedAndStagesAreRetired() throws Exception {
        ApiClient admin = signedIn("synthetic-admin");
        String versions = "/api/v1/policy/rules/class.TCKN/versions";
        ApiClient.Response staged = admin.post(versions, draftBody("BLOCK", "enforce", "pilot"), true);
        assertEquals(400, staged.status());
        assertEquals("ROLLOUT_STAGE_RETIRED", staged.body().get("reason").asText());
        for (String body : new String[] {
            scopedBody("BLOCK", "enforce"),
            scopedBody("BLOCK", "enforce", GROUP_ONE, GROUP_ONE.toLowerCase(java.util.Locale.ROOT)),
            scopedBody("BLOCK", "enforce", GROUP_ONE + "," + GROUP_TWO),
            scopedBody("BLOCK", "enforce", "G".repeat(257)),
            scopedBody("BLOCK", "enforce", java.util.stream.IntStream.rangeClosed(1, 33).mapToObj(i -> "GRP-" + i)
                .toArray(String[]::new))}) {
            ApiClient.Response r = admin.post(versions, body, true);
            assertEquals(400, r.status());
            assertEquals("INVALID_SCOPE", r.body().get("reason").asText());
            assertFalse(r.body().toString().contains("GRP-"), "a refusal never echoes a group");
        }
        ApiClient.Response platform = admin.post("/api/v1/policy/rules/platform.vendor-x/versions",
            "{\"hostSuffixes\":[\"vendor.example\"],\"apiHosts\":[],\"loginHosts\":[],\"mode\":\"enforce\","
                + "\"scope\":{\"kind\":\"GROUPS\",\"groups\":[\"" + GROUP_ONE + "\"]},\"reasonCode\":\"SYNTHETIC_CHANGE\"}",
            true);
        assertEquals("INVALID_SCOPE", platform.body().get("reason").asText());
        for (String action : new String[] {"ALLOW", "WARN"}) {
            ApiClient.Response relaxed = admin.post("/api/v1/policy/rules/class.SECRET/versions",
                scopedBody(action, "monitor", GROUP_ONE), true);
            assertEquals(409, relaxed.status());
            assertEquals("FAIL_CLOSED_CLASS_NOT_RELAXABLE", relaxed.body().get("reason").asText());
        }
        ApiClient.Response noStage = admin.post(versions, "{\"action\":\"BLOCK\",\"mode\":\"enforce\","
            + "\"scope\":{\"kind\":\"ANY\",\"groups\":[]},\"reasonCode\":\"SYNTHETIC_CHANGE\"}", true);
        assertEquals(201, noStage.status(), String.valueOf(noStage.body()));
        assertEquals("ANY", noStage.body().get("scope").get("kind").asText());
        assertEquals(1, ledger("policy_rule_version", "INSERT", "policy.draft"));
    }

    // PO decision Q-40: one security administrator retires a platform row with a reason.

    /** The reason may name a vendor endpoint of an active platform row (public, not estate data). */
    @Test
    void onlyASecurityAdministratorRetiresAPlatformWithAReasonAndItLeavesTheSnapshot() throws Exception {
        String retire = "/api/v1/policy/rules/platform.github/retirement";
        String reason = JSON.createObjectNode().put("reason", "Synthetic vendor retired, see api.github.com").toString();
        for (String login : new String[] {"synthetic-viewer", "synthetic-officer", "synthetic-aiview",
            "synthetic-dual"}) {
            assertEquals(403, signedIn(login).post(retire, reason, true).status(), login);
        }
        ApiClient admin = signedIn("synthetic-admin");
        ApiClient.Response blank = admin.post(retire, JSON.createObjectNode().put("reason", "  ").toString(), true);
        assertEquals(400, blank.status());
        assertEquals("INVALID_RETIREMENT", blank.body().get("reason").asText());
        assertEquals("ESTATE_NAME_REFUSED", admin.post(retire, JSON.createObjectNode()
            .put("reason", "moved to synthetic-estate").toString(), true).body().get("reason").asText());
        assertEquals("UNKNOWN_PLATFORM", admin.post("/api/v1/policy/rules/class.TCKN/retirement", reason, true).body()
            .get("reason").asText());
        assertEquals(1, verified(snapshot(internal.snapshotPort(), null)).get("version").asLong());

        ApiClient.Response done = admin.post(retire, reason, true);
        assertEquals(200, done.status(), String.valueOf(done.body()));
        JsonNode row = done.body().get("retired").get(0);
        assertEquals("retired", row.get("status").asText());
        assertEquals("Synthetic vendor retired, see api.github.com", row.get("retirement").get("reason").asText());
        assertTrue(row.get("retirement").get("retiredBy").asText().matches("USR-[0-9a-f]{10}"));

        JsonNode doc = verified(snapshot(internal.snapshotPort(), "\"1\""));
        assertEquals(2, doc.get("version").asLong());
        assertEquals(8, doc.get("platforms").size());
        for (JsonNode p : doc.get("platforms")) {
            assertFalse("github".equals(p.get("platform").asText()), "the retired platform left the snapshot");
        }
        JsonNode listed = find(signedIn("synthetic-viewer").get("/api/v1/policy/rules").body().get("rules"),
            "platform.github").get("versions").get(0);
        assertEquals("retired", listed.get("status").asText(), "the row is kept, never deleted");
        assertEquals(1, new JdbcTemplate(dataSource).queryForObject("SELECT count(*) FROM audit_event WHERE "
            + "table_name = 'policy_rule_version' AND operation = 'UPDATE' AND action_id = 'policy.platform_retire' "
            + "AND reason_code = 'Synthetic vendor retired, see api.github.com' AND actor_fingerprint = ?", Integer.class,
            row.get("retirement").get("retiredBy").asText()));
        ApiClient.Response again = admin.post(retire, reason, true);
        assertEquals(404, again.status());
        assertEquals("POLICY_VERSION_NOT_FOUND", again.body().get("reason").asText());
    }

    @Test
    void theLastPlatformIsNeverRetired() throws Exception {
        ApiClient admin = signedIn("synthetic-admin");
        String reason = JSON.createObjectNode().put("reason", "Synthetic clean-up").toString();
        JsonNode rules = admin.get("/api/v1/policy/rules").body().get("rules");
        List<String> platforms = new ArrayList<>();
        for (JsonNode r : rules) {
            if ("platform".equals(r.get("kind").asText())) {
                platforms.add(r.get("ruleId").asText());
            }
        }
        for (String id : platforms.subList(0, platforms.size() - 1)) {
            assertEquals(200, admin.post("/api/v1/policy/rules/" + id + "/retirement", reason, true).status(), id);
        }
        ApiClient.Response last = admin.post("/api/v1/policy/rules/" + platforms.get(platforms.size() - 1)
            + "/retirement", reason, true);
        assertEquals(409, last.status());
        assertEquals("RETIRE_WOULD_NOT_COMPILE", last.body().get("reason").asText());
        assertEquals(1, verified(snapshot(internal.snapshotPort(), null)).get("platforms").size());
    }

    // PR 21 review D-06: the service checks the drafting role, platform rows are enforce only, reasons hold no identifier.

    @Test
    void draftsAreTheSecurityAdministratorsPlatformRowsAreEnforcedAndReasonsHoldNoIdentifier() throws Exception {
        PolicyRegistryService.DraftRequest body = new PolicyRegistryService.DraftRequest("BLOCK", null, null, null, null,
            "enforce", null, null, "SYNTHETIC_CHANGE");
        for (java.util.Set<String> roles : List.of(java.util.Set.of("viewer"), java.util.Set.of("privacy_officer"),
            java.util.Set.of("security_admin", "replay_viewer"))) {
            RegistryRefusal refused = org.junit.jupiter.api.Assertions.assertThrows(RegistryRefusal.class,
                () -> registry.draft("class.TCKN", body, "synthetic-admin", roles));
            assertEquals("DRAFT_ROLE_MISSING", refused.reason(), roles.toString());
        }
        ApiClient admin = signedIn("synthetic-admin");
        ApiClient.Response monitorPlatform = admin.post("/api/v1/policy/rules/platform.vendor-x/versions",
            "{\"hostSuffixes\":[\"vendor.example\"],\"apiHosts\":[],\"loginHosts\":[],\"mode\":\"monitor\","
                + "\"reasonCode\":\"SYNTHETIC_CHANGE\"}", true);
        assertEquals(400, monitorPlatform.status());
        assertEquals("ENFORCE_ONLY", monitorPlatform.body().get("reason").asText());
        String retire = "/api/v1/policy/rules/platform.github/retirement";
        // Identifier-shaped values are built at runtime (AGENTS.md 4.5).
        for (String reason : new String[] {"moved, see 192.0.2.10",
            "contact " + String.join("@", "synthetic.person", "example.com"),
            "card " + SyntheticCard.luhnValid(), "asked by Ayşe Yılmaz", "Mehmet'in talebi",
            "moved to node7.example.com", "ticket ref" + "7341029"}) {
            ApiClient.Response r = admin.post(retire, JSON.createObjectNode().put("reason", reason).toString(), true);
            assertEquals(400, r.status(), reason);
            assertEquals("REASON_HOLDS_IDENTIFIER", r.body().get("reason").asText(), reason);
            assertFalse(r.body().toString().contains("192.0.2") || r.body().toString().contains("example.com"));
        }
        assertEquals(0, ledger("policy_rule_version", "UPDATE", "policy.platform_retire"));
    }

    /** A Luhn-valid 16-digit number built at runtime (AGENTS.md 4.5: no identifier-shaped literal is committed). */
    private static final class SyntheticCard {
        static String luhnValid() {
            StringBuilder s = new StringBuilder("411111111111111");
            int sum = 0;
            for (int i = 0; i < s.length(); i++) {
                int d = s.charAt(s.length() - 1 - i) - '0';
                if (i % 2 == 0) {
                    d *= 2;
                    if (d > 9) {
                        d -= 9;
                    }
                }
                sum += d;
            }
            return s.append((10 - sum % 10) % 10).toString();
        }
    }

    // PO decision Q-41 (2026-10-31): one security administrator withdraws a group scope with a reason, at once.

    @Test
    void oneSecurityAdministratorWithdrawsAGroupScopeWithAReasonAndItLeavesTheSnapshot() throws Exception {
        ApiClient admin = signedIn("synthetic-admin");
        ApiClient officer = signedIn("synthetic-officer");
        String versions = "/api/v1/policy/rules/class.TCKN/versions";
        assertEquals(201, admin.post(versions, scopedBody("BLOCK", "enforce", GROUP_ONE), true).status());
        assertEquals(200, admin.post(versions + "/2/approvals", role("security_admin"), true).status());
        assertEquals(200, officer.post(versions + "/2/approvals", role("privacy_officer"), true).status());
        assertEquals(1, verified(snapshot(internal.snapshotPort(), null)).get("scopedRules").size());

        String withdraw = versions + "/2/withdrawal";
        String reason = JSON.createObjectNode().put("reason", "Pilot finished").toString();
        for (String login : new String[] {"synthetic-viewer", "synthetic-officer", "synthetic-aiview",
            "synthetic-dual"}) {
            assertEquals(403, signedIn(login).post(withdraw, reason, true).status(), login);
        }
        ApiClient.Response blank = admin.post(withdraw, JSON.createObjectNode().put("reason", " ").toString(), true);
        assertEquals(400, blank.status());
        assertEquals("INVALID_WITHDRAWAL", blank.body().get("reason").asText());
        assertEquals("ESTATE_NAME_REFUSED", admin.post(withdraw, JSON.createObjectNode()
            .put("reason", "moved to synthetic-estate").toString(), true).body().get("reason").asText());
        // Identifier-shaped values are built at runtime (AGENTS.md 4.5).
        for (String bad : new String[] {"asked by Ayşe Yılmaz", "ticket ref" + "7341029", "see 192.0.2.10"}) {
            ApiClient.Response r = admin.post(withdraw, JSON.createObjectNode().put("reason", bad).toString(), true);
            assertEquals("REASON_HOLDS_IDENTIFIER", r.body().get("reason").asText(), bad);
        }
        assertEquals("WITHDRAWAL_NOT_APPLICABLE", admin.post(versions + "/1/withdrawal", reason, true).body()
            .get("reason").asText(), "the ANY baseline is never withdrawn");
        assertEquals("UNKNOWN_RULE", admin.post("/api/v1/policy/rules/platform.github/versions/1/withdrawal", reason,
            true).body().get("reason").asText(), "a platform row is retired instead");
        assertEquals(1, verified(snapshot(internal.snapshotPort(), null)).get("scopedRules").size(),
            "a refused withdrawal changes nothing");

        ApiClient.Response done = admin.post(withdraw, reason, true);
        assertEquals(200, done.status(), String.valueOf(done.body()));
        assertEquals(2, done.body().get("version").asInt(), "no request version: the version itself is withdrawn");
        assertEquals("withdrawn", done.body().get("status").asText(), "no second approval");
        assertEquals("Pilot finished", done.body().get("withdrawal").get("reason").asText());
        String by = done.body().get("withdrawal").get("withdrawnBy").asText();
        assertTrue(by.matches("USR-[0-9a-f]{10}"), by);
        JsonNode doc = verified(snapshot(internal.snapshotPort(), null));
        assertEquals("[]", doc.get("scopedRules").toString(), "the groups fall back to ANY at once");
        JsonNode tckn = find(signedIn("synthetic-viewer").get("/api/v1/policy/rules").body().get("rules"), "class.TCKN");
        assertEquals(2, tckn.get("versions").size(), "the version is kept, never deleted");
        assertEquals("withdrawn", tckn.get("versions").get(0).get("status").asText());
        assertEquals("active", tckn.get("versions").get(1).get("status").asText());
        assertEquals(1, new JdbcTemplate(dataSource).queryForObject("SELECT count(*) FROM audit_event WHERE "
            + "table_name = 'policy_rule_version' AND operation = 'UPDATE' AND action_id = 'policy.scope_withdraw' "
            + "AND reason_code = 'Pilot finished' AND actor_fingerprint = ? AND row_key = 'class.TCKN@v2'",
            Integer.class, by));
        assertEquals(0, ledger("policy_rule_version", "INSERT", "policy.withdraw_request"));
        ApiClient.Response again = admin.post(withdraw, reason, true);
        assertEquals(409, again.status());
        assertEquals("WITHDRAWAL_NOT_APPLICABLE", again.body().get("reason").asText());
    }

    @Test
    void theMaskedRetirementReasonPassesTheMasker() throws Exception {
        PolicyRuleVersion v = new PolicyRuleVersion("platform.vendor-x", 1, "platform", null, null, "vendor-x",
            List.of("vendor.example"), List.of(), List.of(), null, "enforce", "all", "retired", "registry",
            "USR-00000000a1", "SYNTHETIC_CHANGE", Instant.EPOCH, Instant.EPOCH, null, List.of(), "ANY", List.of(),
            new PolicyRuleVersion.Retirement(Instant.EPOCH, "USR-00000000a1", "see 192.0.2.10 and synthetic-estate"));
        String masked = springJson.writeValueAsString(PolicyViews.VersionView.of(v, java.util.Set.of())
            .masked(masking.masker()));
        assertFalse(masked.contains("192.0.2.10") || masked.contains("synthetic-estate"), masked);
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
