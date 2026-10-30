package io.rwsafe.control.privacy;

import static io.rwsafe.control.support.EventsJson.batch;
import static io.rwsafe.control.support.EventsJson.event;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.rwsafe.control.config.InternalConnector;
import io.rwsafe.control.policy.PolicyViews;
import io.rwsafe.control.support.ApiClient;
import io.rwsafe.control.support.ApiInventory;
import io.rwsafe.control.support.Canaries;
import io.rwsafe.control.support.Canaries.Person;
import io.rwsafe.control.support.ControlTestEnvironment;
import io.rwsafe.control.support.LeakProbe;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

/**
 * The masked-role leak probe (AGENTS.md 4.11, SR-PRIV-2, AC-5) at the API level. The control plane is seeded through its
 * real paths with the synthetic estate of {@link Canaries}: verdict events through the capture sink (identity claims,
 * client addresses, and identifier-shaped values in every free vocabulary field the ingestion contract accepts),
 * directory users with Turkish-name logins who sign in, draft and approve a policy version, an estate dictionary and an
 * operator-chosen signing key id that names an estate host. The masked user then walks every endpoint of the admin UI's
 * API client and every admin API route the server maps; every response body and header is compared token by token, as
 * digests, against every canary. A hit reports the endpoint template, the JSON path class and the canary class only.
 *
 * <p>The same walk as an unmasked viewer is the probe's positive control: it must hit the classes the viewer is meant to
 * see in clear, and must still miss the identity claims and client addresses, which are pseudonymised before persistence.
 * Exports: the UI and the server have none today; the inventory check fails as soon as one appears unprobed.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class MaskedRoleLeakProbeTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static Canaries canaries;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) throws Exception {
        canaries = new Canaries();
        Path dictionary = Files.createTempFile(ControlTestEnvironment.dir() == null
            ? Path.of(System.getProperty("java.io.tmpdir")) : ControlTestEnvironment.dir(), "probe-estate", ".txt");
        Files.writeString(dictionary, canaries.estateDictionary());
        ControlTestEnvironment.register(r, true, dictionary, canaries.signingKeyId);
        // The end-user notice's runtime values (PR 22): complete, so the notice renders with them.
        r.add("RWSAFE_ENDUSER_CONTROLLER_NAME", () -> canaries.noticeController);
        r.add("RWSAFE_ENDUSER_DPO_CONTACT", () -> canaries.noticeContact);
        r.add("RWSAFE_ENDUSER_POLICY_LINK", () -> canaries.noticePolicyLink);
        r.add("RWSAFE_ENDUSER_RETENTION_METADATA", () -> "400");
        r.add("RWSAFE_ENDUSER_RETENTION_REDACTED", () -> "90");
        r.add("RWSAFE_ENDUSER_RETENTION_RAW", () -> "30");
        ControlTestEnvironment.addUser(canaries.admin.login(), "security_admin");
        ControlTestEnvironment.addUser(canaries.adminTwo.login(), "security_admin");
        ControlTestEnvironment.addUser(canaries.officer.login(), "privacy_officer");
        ControlTestEnvironment.addUser(canaries.viewer.login(), "viewer");
        ControlTestEnvironment.addUser(canaries.masked.login(), "replay_viewer");
    }

    @LocalServerPort
    int port;
    @Autowired
    InternalConnector internal;
    @Autowired
    RequestMappingHandlerMapping mapping;
    @Autowired
    javax.sql.DataSource dataSource;

    /** One response of the walk, under the endpoint template it exercised; {@code session} once signed in. */
    private record Probed(String endpoint, ApiClient.Response response, boolean session) {

        Probed(String endpoint, ApiClient.Response response) {
            this(endpoint, response, true);
        }
    }

    @Test
    void theMaskedRoleSeesNoSeededTokenOnAnyEndpoint() throws Exception {
        seed();
        LeakProbe probe = canaries.probe();

        List<Probed> masked = walk(canaries.masked);
        Set<String> inventory = new TreeSet<>(ApiInventory.frontendEndpoints());
        inventory.addAll(ApiInventory.serverEndpoints(mapping));
        Set<String> walked = new TreeSet<>();
        masked.forEach(p -> walked.add(p.endpoint()));
        Set<String> unprobed = new TreeSet<>(inventory);
        unprobed.removeAll(walked);
        assertTrue(unprobed.isEmpty(), "endpoints the leak probe does not walk (add them to walk()): " + unprobed);
        assertTrue(ApiInventory.serverEndpoints(mapping).containsAll(ApiInventory.frontendEndpoints()),
            "the UI calls a route the server does not map");

        List<String> unmarked = new ArrayList<>();
        for (Probed p : masked) {
            int status = p.response().status();
            // Before sign-in nothing is masked; a 204 (logout) has no page to mark; 401 and 403 come from the security
            // filter chain before any controller, with fixed bodies and no data.
            if (!p.session() || status == 204) {
                continue;
            }
            if (status != 401 && status != 403 && !"true".equals(header(p, MaskingFunnel.MASKED_HEADER))) {
                unmarked.add(p.endpoint() + " " + status);
            }
            if (status != 401 && status != 403 && !TextMasker.RULE_SET.equals(header(p, MaskingFunnel.RULES_HEADER))) {
                unmarked.add(p.endpoint() + " " + status + " (rule set)");
            }
        }
        assertTrue(unmarked.isEmpty(), "masked responses without the masked and rule-set headers: " + unmarked);

        Set<String> hits = hits(probe, masked);
        // The free-text reasons exist on the masked page, withheld (not merely passed through the text masker).
        long withheld = masked.stream().filter(p -> p.endpoint().equals("GET /api/v1/policy/rules"))
            .map(p -> p.response().raw().body()).filter(b -> b.contains(PolicyViews.FREE_TEXT_WITHHELD)).count();
        assertTrue(withheld > 0, "the masked registry page shows no withheld reason");
        // The notice: the masked projection leaves out the rendered sections that carry the configured values; the
        // acknowledgements it reads are pseudonyms with records.
        for (Probed p : masked) {
            if (p.endpoint().equals("GET /api/v1/notice")) {
                assertTrue(p.response().body().get("sections").isNull(), "the masked notice carries no sections");
                assertTrue(p.response().body().get("complete").asBoolean(), "the probe's notice is complete");
            }
        }
        long acknowledged = masked.stream().filter(p -> p.endpoint().equals("GET /api/v1/notice/acknowledgements")
            && p.response().status() == 200 && p.response().body().get("records").size() > 0).peek(p ->
                assertTrue(p.response().body().get("user").asText().matches("USR-[0-9a-f]{10}"))).count();
        assertTrue(acknowledged > 0, "the masked walk read no acknowledgement records");
        assertTrue(hits.isEmpty(), "the masked role saw seeded tokens (location class <- canary class): " + hits);
        assertTrue(masked.size() >= 40, "the walk made " + masked.size() + " requests");

        // Positive control: the same walk unmasked sees what a viewer is meant to see (its own login and name, the
        // operator's key id naming an estate host), so the probe can see a leak; and nothing refused at ingestion or
        // pseudonymised there reaches the viewer either.
        Set<String> seenByViewer = new TreeSet<>();
        Set<String> viewerHits = hits(probe, walk(canaries.viewer));
        for (String hit : viewerHits) {
            seenByViewer.add(hit.substring(hit.lastIndexOf(' ') + 1));
        }
        for (String cls : List.of(Canaries.HOST_NAME, Canaries.DIRECTORY_LOGIN, Canaries.TURKISH_NAME,
            Canaries.GROUP_NAME, Canaries.NOTICE_VALUE)) {
            assertTrue(seenByViewer.contains(cls), "the positive control did not see " + cls + ": " + seenByViewer);
        }
        for (String cls : List.of(Canaries.TCKN, Canaries.TR_IBAN, Canaries.TR_MOBILE, Canaries.PAYMENT_CARD,
            Canaries.SECRET_SHAPE, Canaries.CLAIM_USER, Canaries.EMAIL, Canaries.DOMAIN_ACCOUNT,
            Canaries.IPV4)) {
            assertTrue(!seenByViewer.contains(cls), cls + " reached the viewer although ingestion refuses or "
                + "pseudonymises it (location class <- canary class): " + viewerHits);
        }
    }

    /**
     * SR-PRIV-4: every traffic filter of the masked role takes a registry vocabulary value or a pseudonym, never a raw
     * value it could test guesses with against stored data; the refusal echoes nothing.
     */
    @Test
    void theMaskedRolesTrafficFiltersTakeNoRawValue() throws Exception {
        ObjectNode e = event("claude", "REDACT", canaries.email(canaries.claimants.get(0)), canaries.addresses.get(0));
        assertEquals(202, new ApiClient(internal.port()).post("/internal/v1/verdict-events", batch(e), false).status());
        ApiClient masked = signedIn(canaries.masked);
        List<String> guesses = new ArrayList<>(canaries.tckns);
        guesses.add("ref" + canaries.tckns.get(0));
        guesses.add(canaries.ibans.get(0));
        guesses.add(canaries.mobiles.get(0));
        guesses.add(canaries.card);
        guesses.addAll(canaries.hosts);
        guesses.addAll(canaries.groups);
        guesses.add(canaries.claimants.get(0).login());
        guesses.add(canaries.email(canaries.claimants.get(0)));
        guesses.add(canaries.domainAccount(canaries.claimants.get(0)));
        guesses.add(Canaries.fold(canaries.claimants.get(0).given()));
        guesses.addAll(canaries.addresses);
        LeakProbe probe = canaries.probe();
        List<String> accepted = new ArrayList<>();
        Set<String> echoed = new TreeSet<>();
        for (String filter : List.of("platform", "user", "verdict", "service")) {
            for (String guess : guesses) {
                ApiClient.Response r = masked.get("/api/v1/traffic?" + filter + "=" + enc(guess));
                if (r.status() != 400) {
                    accepted.add(filter + " answered " + r.status());
                }
                probe.scan("GET /api/v1/traffic?" + filter, r.body()).forEach(h -> echoed.add(h.toString()));
            }
        }
        for (String guess : guesses) {
            ApiClient.Response r = masked.get("/api/v1/notice/acknowledgements?user=" + enc(guess));
            if (r.status() != 400) {
                accepted.add("notice user answered " + r.status());
            }
            probe.scan("GET /api/v1/notice/acknowledgements?user", r.body()).forEach(h -> echoed.add(h.toString()));
        }
        assertTrue(accepted.isEmpty(), "a raw value was accepted as a filter: " + accepted);
        assertTrue(echoed.isEmpty(), "a refusal echoed the guess: " + echoed);

        // Vocabulary values and pseudonyms work: the screens' own filters stay usable.
        JsonNode page = masked.get("/api/v1/traffic?platform=claude").body();
        assertTrue(page.get("items").size() >= 1);
        String pseudonym = page.get("items").get(0).get("user").asText();
        assertEquals(200, masked.get("/api/v1/traffic?user=" + enc(pseudonym)).status());
        assertEquals(200, masked.get("/api/v1/traffic?platform=unknown&verdict=REDACT&service=reqmod").status());
    }

    /** Verdict events and a registry change through the real paths, carrying the canaries. */
    private void seed() throws Exception {
        List<String> claims = new ArrayList<>();
        for (Person p : canaries.claimants) {
            claims.add(canaries.email(p));
            claims.add(canaries.domainAccount(p));
            claims.add(p.displayName());
        }
        // Accepted events: registry platforms and the fixed surface and step enumerations, canary identities.
        List<String> platforms = List.of("claude", "openai", "copilot", "gemini", "unknown");
        List<String> surfaces = List.of("web", "api", "ide", "cli", "unknown");
        List<String> steps = List.of("chat", "upload", "tool_call", "login", "other");
        String[] verdicts = {"ALLOW", "REDACT", "BLOCK"};
        List<ObjectNode> events = new ArrayList<>();
        for (int i = 0; i < 12; i++) {
            ObjectNode e = event(platforms.get(i % platforms.size()), verdicts[i % verdicts.length],
                claims.get(i % claims.size()), canaries.addresses.get(i % canaries.addresses.size()));
            e.put("surface", surfaces.get(i % surfaces.size()));
            e.put("step", steps.get(i % steps.size()));
            events.add(e);
        }
        ApiClient sink = new ApiClient(internal.port());
        ApiClient.Response ingested = sink.post("/internal/v1/verdict-events", batch(events.toArray(ObjectNode[]::new)),
            false);
        assertEquals(202, ingested.status(), String.valueOf(ingested.body()));
        assertEquals(events.size(), ingested.body().get("accepted").asInt());

        // Refused events: identifier-shaped values, estate names, a Turkish name and a letter-glued TCKN in platform,
        // surface or step. Each batch is refused whole and stores nothing; the walk then proves no role sees them.
        String glued = "ref" + canaries.tckns.get(0);
        String name = Canaries.fold(canaries.claimants.get(0).given()) + "-"
            + Canaries.fold(canaries.claimants.get(0).family());
        List<String> refusedValues = new ArrayList<>(canaries.tckns);
        refusedValues.add(glued);
        refusedValues.add(name);
        refusedValues.add(canaries.ibans.get(0).toLowerCase(java.util.Locale.ROOT));
        refusedValues.add("tel-" + canaries.mobiles.get(0));
        refusedValues.add(canaries.mobiles.get(1));
        refusedValues.add(canaries.card);
        refusedValues.add(canaries.secret);
        refusedValues.addAll(canaries.hosts);
        refusedValues.addAll(canaries.groups);
        org.springframework.jdbc.core.JdbcTemplate jdbc = new org.springframework.jdbc.core.JdbcTemplate(dataSource);
        Integer stored = jdbc.queryForObject("SELECT count(*) FROM verdict_event", Integer.class);
        int refused = 0;
        for (String field : List.of("platform", "surface", "step")) {
            for (String value : refusedValues) {
                ObjectNode e = event("claude", "ALLOW", claims.get(0), canaries.addresses.get(0));
                e.put(field, value);
                ApiClient.Response r = sink.post("/internal/v1/verdict-events", batch(e), false);
                assertEquals(400, r.status(), field);
                assertEquals("INVALID_EVENT", r.body().get("reason").asText());
                assertTrue(canaries.probe().scan("ingestion refusal", r.body()).isEmpty(), "the refusal echoed " + field);
                refused++;
            }
        }
        assertEquals(3 * refusedValues.size(), refused);
        assertEquals(stored, jdbc.queryForObject("SELECT count(*) FROM verdict_event", Integer.class),
            "a refused batch stored nothing");

        ApiClient admin = signedIn(canaries.admin);

        // Notice acknowledgements (PR 22) through the internal intake on the capture-sink port, with the claimants'
        // identity claims; the intake answers on no other port.
        JsonNode notice = admin.get("/api/v1/notice").body();
        assertTrue(notice.get("complete").asBoolean(), "the notice is complete: " + notice.get("missingParameters")
            + notice.get("rejectedParameters"));
        String version = notice.get("currentVersion").asText();
        com.fasterxml.jackson.databind.node.ArrayNode acks = JSON.createArrayNode();
        String[] sources = {"banner", "directory_attribute", "ide_first_run"};
        for (int i = 0; i < claims.size(); i++) {
            acks.addObject().put("userClaim", claims.get(i)).put("noticeVersion", version)
                .put("acknowledgedAt", Instant.now().minusSeconds(60).toString()).put("source", sources[i % 3]);
        }
        String intake = io.rwsafe.control.notice.NoticeIntakeController.PATH;
        ApiClient.Response recorded = sink.post(intake, acks.toString(), false);
        assertEquals(202, recorded.status(), String.valueOf(recorded.body()));
        assertEquals(404, new ApiClient(port).post(intake, acks.toString(), false).status(), "not on the admin port");
        assertEquals(404, admin.post(intake, acks.toString(), true).status(), "not on the admin port, signed in");
        assertEquals(404, new ApiClient(internal.snapshotPort()).post(intake, acks.toString(), false).status(),
            "not on the snapshot feed");

        // The registry's platform id is the one free value that becomes ingestion vocabulary: an identifier-shaped or
        // estate-naming id is refused at the draft.
        String platformDraft = JSON.createObjectNode().put("mode", "monitor").put("rolloutStage", "pilot")
            .put("reasonCode", "SYNTHETIC_CHANGE").set("hostSuffixes", JSON.createArrayNode().add("vendor.example"))
            .toString();
        for (String id : List.of(glued, canaries.tckns.get(1), canaries.hosts.get(0), canaries.card)) {
            ApiClient.Response r = admin.post("/api/v1/policy/rules/platform." + enc(id) + "/versions", platformDraft,
                true);
            assertTrue(r.status() >= 400 && r.status() < 500, "platform draft " + r.status());
            assertTrue(canaries.probe().scan("draft refusal", r.body()).isEmpty(), "the draft refusal echoed the id");
        }
        for (String code : List.of("REF" + canaries.tckns.get(0), "TCKN_" + canaries.tckns.get(1))) {
            String body = JSON.createObjectNode().put("action", "BLOCK").put("mode", "monitor").put("reasonCode", code)
                .toString();
            ApiClient.Response r = admin.post("/api/v1/policy/rules/class.TCKN/versions", body, true);
            assertEquals(400, r.status(), "an identifier-shaped reason code");
            assertTrue(canaries.probe().scan("draft refusal", r.body()).isEmpty(), "the refusal echoed the code");
        }
        ApiClient officer = signedIn(canaries.officer);
        String draft = JSON.createObjectNode().put("action", "BLOCK").put("mode", "enforce").put("rolloutStage", "all")
            .put("reasonCode", "SYNTHETIC_CHANGE").toString();
        assertEquals(201, admin.post("/api/v1/policy/rules/class.TCKN/versions", draft, true).status());
        String approvals = "/api/v1/policy/rules/class.TCKN/versions/2/approvals";
        assertEquals(200, admin.post(approvals, role("security_admin"), true).status());
        assertEquals(200, officer.post(approvals, role("privacy_officer"), true).status());

        // A group-scoped class version (PO decision Q-39) naming the estate's directory groups, activated, then a
        // withdrawal request and a platform retirement (Q-40, Q-41) whose free-text reasons name a person and carry a
        // number glued to letters: the registry's free values that reach the screens.
        ObjectNode scoped = JSON.createObjectNode().put("action", "BLOCK").put("mode", "enforce")
            .put("reasonCode", "SYNTHETIC_SCOPE");
        ObjectNode scope = scoped.putObject("scope").put("kind", "GROUPS");
        com.fasterxml.jackson.databind.node.ArrayNode scopeGroups = scope.putArray("groups");
        canaries.groups.forEach(g -> scopeGroups.add(g));
        ApiClient.Response scopedDraft = admin.post("/api/v1/policy/rules/class.TR_IBAN/versions", scoped.toString(),
            true);
        assertEquals(201, scopedDraft.status(), String.valueOf(scopedDraft.body()));
        int scopedVersion = scopedDraft.body().get("version").asInt();
        String scopedApprovals = "/api/v1/policy/rules/class.TR_IBAN/versions/" + scopedVersion + "/approvals";
        assertEquals(200, admin.post(scopedApprovals, role("security_admin"), true).status());
        assertEquals(200, officer.post(scopedApprovals, role("privacy_officer"), true).status());
        Person named = canaries.claimants.get(1);
        String withdrawalReason = "Talep " + named.displayName() + " kapsam bitti";
        ApiClient.Response withdrawal = admin.post("/api/v1/policy/rules/class.TR_IBAN/versions/" + scopedVersion
            + "/withdrawal", JSON.createObjectNode().put("reason", withdrawalReason).toString(), true);
        assertEquals(201, withdrawal.status(), String.valueOf(withdrawal.body()));
        String retirementReason = named.given() + " " + named.family() + " istedi";
        // A reason with a number glued to letters is refused before it is stored, for every role.
        for (String gluedReason : List.of("kayıt ref" + canaries.tckns.get(0), "arayan tel" + canaries.mobiles.get(0))) {
            ApiClient.Response r = admin.post("/api/v1/policy/rules/platform.devin/retirement",
                JSON.createObjectNode().put("reason", gluedReason).toString(), true);
            assertEquals(400, r.status(), "a reason with a glued number");
            assertTrue(canaries.probe().scan("reason refusal", r.body()).isEmpty(), "the refusal echoed the reason");
        }
        ApiClient.Response retirement = admin.post("/api/v1/policy/rules/platform.windsurf/retirement",
            JSON.createObjectNode().put("reason", retirementReason).toString(), true);
        assertEquals(200, retirement.status(), String.valueOf(retirement.body()));

        // The data plane's pull issues a snapshot, so the operator's key id (naming an estate host) reaches the screens.
        assertEquals(200, new ApiClient(internal.snapshotPort()).get("/internal/v1/policy/snapshot").status());
    }

    /** Every endpoint of the inventory, with the parameters the screens send, as {@code who}. */
    private List<Probed> walk(Person who) throws Exception {
        List<Probed> out = new ArrayList<>();
        ApiClient c = new ApiClient(port);
        out.add(new Probed("GET /api/v1/auth/csrf", c.get("/api/v1/auth/csrf"), false));
        ApiClient.Response login = c.login(who.login(), ControlTestEnvironment.PASSWORDS.get(who.login()));
        assertEquals(200, login.status(), String.valueOf(login.body()));
        out.add(new Probed("POST /api/v1/auth/login", login));
        out.add(get(c, "GET /api/v1/auth/csrf", "/api/v1/auth/csrf"));
        out.add(get(c, "GET /api/v1/auth/me", "/api/v1/auth/me"));

        Instant to = Instant.now().plus(1, ChronoUnit.MINUTES);
        String window = "?from=" + to.minus(2, ChronoUnit.DAYS) + "&to=" + to;
        out.add(get(c, "GET /api/v1/overview", "/api/v1/overview"));
        out.add(get(c, "GET /api/v1/overview", "/api/v1/overview" + window));
        Probed platforms = get(c, "GET /api/v1/platforms", "/api/v1/platforms" + window);
        out.add(platforms);
        out.add(get(c, "GET /api/v1/platforms", "/api/v1/platforms"));

        // Traffic: the default page, every page by cursor, and each filter the screen offers with values it shows.
        Set<String> eventIds = new LinkedHashSet<>();
        Set<String> users = new LinkedHashSet<>();
        String cursor = null;
        for (int page = 0; page < 20; page++) {
            Probed p = get(c, "GET /api/v1/traffic", "/api/v1/traffic" + window + "&limit=5"
                + (cursor == null ? "" : "&cursor=" + enc(cursor)));
            out.add(p);
            for (JsonNode item : p.response().body().get("items")) {
                eventIds.add(item.get("eventId").asText());
                if (item.hasNonNull("user")) {
                    users.add(item.get("user").asText());
                }
            }
            JsonNode next = p.response().body().get("nextCursor");
            if (next == null || next.isNull()) {
                break;
            }
            cursor = next.asText();
        }
        assertTrue(eventIds.size() >= 10, "the walk saw " + eventIds.size() + " events");
        out.add(get(c, "GET /api/v1/traffic", "/api/v1/traffic"));
        for (JsonNode platform : platforms.response().body().get("platforms")) {
            out.add(get(c, "GET /api/v1/traffic", "/api/v1/traffic" + window + "&platform=" + enc(platform.asText())));
        }
        for (String verdict : List.of("REDACT", "BLOCK")) {
            out.add(get(c, "GET /api/v1/traffic", "/api/v1/traffic" + window + "&verdict=" + verdict));
        }
        out.add(get(c, "GET /api/v1/traffic", "/api/v1/traffic" + window + "&service=reqmod"));
        for (String user : users) {
            out.add(get(c, "GET /api/v1/traffic", "/api/v1/traffic" + window + "&user=" + enc(user)));
        }
        for (String id : eventIds) {
            out.add(get(c, "GET /api/v1/traffic/{}", "/api/v1/traffic/" + id));
        }
        out.add(get(c, "GET /api/v1/traffic/{}", "/api/v1/traffic/" + java.util.UUID.randomUUID()));

        out.add(get(c, "GET /api/v1/health", "/api/v1/health"));
        out.add(get(c, "GET /api/v1/notice", "/api/v1/notice"));
        for (String user : users) {
            out.add(get(c, "GET /api/v1/notice/acknowledgements", "/api/v1/notice/acknowledgements?user=" + enc(user)));
        }
        out.add(get(c, "GET /api/v1/notice/acknowledgements", "/api/v1/notice/acknowledgements?user=USR-0000000000"));
        Probed rules = get(c, "GET /api/v1/policy/rules", "/api/v1/policy/rules");
        out.add(rules);
        JsonNode actions = rules.response().body().get("actions");
        String someRule = null;
        int someVersion = 1;
        for (JsonNode rule : rules.response().body().get("rules")) {
            String ruleId = rule.get("ruleId").asText();
            if (someRule == null) {
                someRule = ruleId;
                someVersion = rule.get("versions").get(0).get("version").asInt();
            }
            for (JsonNode action : actions) {
                out.add(get(c, "GET /api/v1/policy/simulation", "/api/v1/policy/simulation?ruleId=" + enc(ruleId)
                    + "&action=" + enc(action.asText())));
            }
        }

        // The mutations the screens offer: the masked role and the viewer are refused; the probe reads the refusal.
        String draft = JSON.createObjectNode().put("action", "BLOCK").put("mode", "monitor").put("rolloutStage", "pilot")
            .put("reasonCode", "SYNTHETIC_PROBE").toString();
        out.add(new Probed("POST /api/v1/policy/rules/{}/versions",
            c.post("/api/v1/policy/rules/" + enc(someRule) + "/versions", draft, true)));
        out.add(new Probed("POST /api/v1/policy/rules/{}/versions/{}/approvals", c.post("/api/v1/policy/rules/"
            + enc(someRule) + "/versions/" + someVersion + "/approvals", role("security_admin"), true)));
        String reason = JSON.createObjectNode().put("reason", "synthetic probe").toString();
        out.add(new Probed("POST /api/v1/policy/rules/{}/versions/{}/withdrawal", c.post("/api/v1/policy/rules/"
            + enc(someRule) + "/versions/" + someVersion + "/withdrawal", reason, true)));
        out.add(new Probed("POST /api/v1/policy/rules/{}/retirement",
            c.post("/api/v1/policy/rules/platform.devin/retirement", reason, true)));
        out.add(new Probed("POST /api/v1/policy/rules/{}/exceptions",
            c.post("/api/v1/policy/rules/" + enc(someRule) + "/exceptions", "{}", true)));
        out.add(new Probed("POST /api/v1/auth/logout", c.post("/api/v1/auth/logout", "", true)));
        return out;
    }

    private static Set<String> hits(LeakProbe probe, List<Probed> responses) {
        Set<String> hits = new TreeSet<>();
        for (Probed p : responses) {
            for (LeakProbe.Hit h : probe.scan(p.endpoint(), p.response().body())) {
                hits.add(h.toString());
            }
            p.response().raw().headers().map().forEach((name, values) -> values.forEach(v ->
                probe.scanText(p.endpoint() + " header " + name.toLowerCase(java.util.Locale.ROOT), v)
                    .forEach(h -> hits.add(h.toString()))));
        }
        return hits;
    }

    private static Probed get(ApiClient c, String endpoint, String path) throws Exception {
        return new Probed(endpoint, c.get(path));
    }

    private static String header(Probed p, String name) {
        return p.response().raw().headers().firstValue(name).orElse(null);
    }

    private ApiClient signedIn(Person who) throws Exception {
        ApiClient c = new ApiClient(port);
        ApiClient.Response r = c.login(who.login(), ControlTestEnvironment.PASSWORDS.get(who.login()));
        assertEquals(200, r.status(), String.valueOf(r.body()));
        return c;
    }

    private static String role(String role) {
        return JSON.createObjectNode().put("role", role).toString();
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
}
