package io.rwsafe.control.privacy;

import static io.rwsafe.control.support.EventsJson.batch;
import static io.rwsafe.control.support.EventsJson.event;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.rwsafe.control.config.InternalConnector;
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
        assertTrue(hits.isEmpty(), "the masked role saw seeded tokens (location class <- canary class): " + hits);
        assertTrue(masked.size() >= 40, "the walk made " + masked.size() + " requests");

        // Positive control: the same walk unmasked sees what a viewer is meant to see, so the probe can see a leak.
        Set<String> seenByViewer = new TreeSet<>();
        for (String hit : hits(probe, walk(canaries.viewer))) {
            seenByViewer.add(hit.substring(hit.lastIndexOf(' ') + 1));
        }
        for (String cls : List.of(Canaries.TCKN, Canaries.TR_IBAN, Canaries.TR_MOBILE, Canaries.PAYMENT_CARD,
            Canaries.SECRET_SHAPE, Canaries.HOST_NAME, Canaries.GROUP_NAME, Canaries.DIRECTORY_LOGIN, Canaries.TURKISH_NAME)) {
            assertTrue(seenByViewer.contains(cls), "the positive control did not see " + cls + ": " + seenByViewer);
        }
        for (String cls : List.of(Canaries.CLAIM_USER, Canaries.EMAIL, Canaries.DOMAIN_ACCOUNT, Canaries.IPV4)) {
            assertTrue(!seenByViewer.contains(cls), cls + " reached a screen although it is pseudonymised at ingestion");
        }
    }

    /** Verdict events and a registry change through the real paths, carrying the canaries. */
    private void seed() throws Exception {
        List<String> claims = new ArrayList<>();
        for (Person p : canaries.claimants) {
            claims.add(canaries.email(p));
            claims.add(canaries.domainAccount(p));
            claims.add(p.displayName());
        }
        // Every value the ingestion vocabulary accepts in platform, surface and step: identifiers and estate names.
        List<String> platforms = new ArrayList<>(canaries.tckns);
        platforms.add(canaries.ibans.get(0).toLowerCase(java.util.Locale.ROOT));
        platforms.add("tel-" + canaries.mobiles.get(0));
        platforms.add(canaries.card);
        platforms.add(canaries.secret);
        platforms.addAll(canaries.hosts);
        List<String> surfaces = new ArrayList<>(canaries.groups);
        surfaces.add(canaries.mobiles.get(1));
        List<String> steps = List.of(canaries.hosts.get(0), "iban-" + canaries.ibans.get(1).toLowerCase(java.util.Locale.ROOT));
        String[] verdicts = {"ALLOW", "REDACT", "BLOCK"};
        List<ObjectNode> events = new ArrayList<>();
        for (int i = 0; i < platforms.size() * 2; i++) {
            ObjectNode e = event(platforms.get(i % platforms.size()), verdicts[i % verdicts.length],
                claims.get(i % claims.size()), canaries.addresses.get(i % canaries.addresses.size()));
            e.put("surface", surfaces.get(i % surfaces.size()));
            e.put("step", steps.get(i % steps.size()));
            events.add(e);
        }
        ApiClient.Response ingested = new ApiClient(internal.port()).post("/internal/v1/verdict-events",
            batch(events.toArray(ObjectNode[]::new)), false);
        assertEquals(202, ingested.status(), String.valueOf(ingested.body()));
        assertEquals(events.size(), ingested.body().get("accepted").asInt());

        ApiClient admin = signedIn(canaries.admin);
        ApiClient officer = signedIn(canaries.officer);
        String draft = JSON.createObjectNode().put("action", "BLOCK").put("mode", "enforce").put("rolloutStage", "all")
            .put("reasonCode", "SYNTHETIC_CHANGE").toString();
        assertEquals(201, admin.post("/api/v1/policy/rules/class.TCKN/versions", draft, true).status());
        String approvals = "/api/v1/policy/rules/class.TCKN/versions/2/approvals";
        assertEquals(200, admin.post(approvals, role("security_admin"), true).status());
        assertEquals(200, officer.post(approvals, role("privacy_officer"), true).status());
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
