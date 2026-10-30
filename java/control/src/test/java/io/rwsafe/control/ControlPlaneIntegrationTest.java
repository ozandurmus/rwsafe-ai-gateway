package io.rwsafe.control;

import static io.rwsafe.control.support.EventsJson.batch;
import static io.rwsafe.control.support.EventsJson.event;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.rwsafe.control.config.InternalConnector;
import io.rwsafe.control.ingest.IngestionService;
import io.rwsafe.control.sample.SampleEvents;
import io.rwsafe.control.support.ApiClient;
import io.rwsafe.control.support.ControlTestEnvironment;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ControlPlaneIntegrationTest {

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) throws Exception {
        ControlTestEnvironment.register(r, true, true);
    }

    @LocalServerPort
    int port;
    @Autowired
    InternalConnector internal;
    @Autowired
    DataSource dataSource;
    @Autowired
    IngestionService ingestion;
    @org.springframework.beans.factory.annotation.Value("${rwsafe.identity.break-glass.initial-password-file}")
    String breakGlassFile;

    private ApiClient admin() {
        return new ApiClient(port);
    }

    private ApiClient internalClient() {
        return new ApiClient(internal.port());
    }

    private ApiClient signedIn(String login) throws Exception {
        ApiClient c = admin();
        ApiClient.Response r = c.login(login, ControlTestEnvironment.PASSWORDS.get(login));
        assertEquals(200, r.status(), String.valueOf(r.body()));
        return c;
    }

    @Test
    void ingestionPseudonymisesBeforePersistenceAndIsIdempotent() throws Exception {
        ObjectNode e = event("claude", "REDACT", "SYNTHETIC\\synthetic.ingest.user", "192.0.2.77");
        ApiClient.Response first = internalClient().post("/internal/v1/verdict-events", batch(e), false);
        assertEquals(202, first.status());
        assertEquals(1, first.body().get("accepted").asInt());
        ApiClient.Response again = internalClient().post("/internal/v1/verdict-events", batch(e), false);
        assertEquals(0, again.body().get("accepted").asInt());
        assertEquals(1, again.body().get("duplicates").asInt());

        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        String row = jdbc.queryForObject("SELECT row_to_json(v)::text FROM verdict_event v WHERE event_id = ?::uuid",
            String.class, e.get("eventId").asText());
        assertFalse(row.toLowerCase().contains("synthetic.ingest.user"), "the raw claim is never stored");
        assertFalse(row.contains("192.0.2"), "the raw address is never stored");
        assertTrue(row.contains("\"user_pseudonym\":\"USR-"));
        assertTrue(row.contains(".0/24"));

        ApiClient viewer = signedIn("synthetic-viewer");
        JsonNode detail = viewer.get("/api/v1/traffic/" + e.get("eventId").asText()).body();
        assertTrue(detail.get("user").asText().matches("USR-[0-9a-f]{10}"));
        assertEquals("TCKN", detail.get("findings").get(0).get("dataClass").asText());
        assertEquals(2, detail.get("findings").get(0).get("count").asInt());
    }

    /** PR 18 review D-01: the kubelet's readiness endpoint, on the admin listener only, without a session. */
    @Test
    void readinessAnswersOnTheAdminListenerOnceEveryListenerIsUp() throws Exception {
        assertTrue(internal.listening());
        ApiClient.Response ready = admin().get("/readyz");
        assertEquals(200, ready.status());
        assertNull(ready.body(), "no body");
        assertEquals(404, internalClient().get("/readyz").status(), "not on the capture sink");
        assertEquals(404, new ApiClient(internal.snapshotPort()).get("/readyz").status(), "not on the snapshot feed");
    }

    @Test
    void sampleEventsPassTheRealIngestionPath() {
        java.time.Instant now = java.time.Instant.now();
        var events = new SampleEvents(42, 60).generate(2500, now);
        int accepted = 0;
        for (int i = 0; i < events.size(); i += IngestionService.MAX_BATCH) {
            accepted += ingestion.ingest(events.subList(i, Math.min(events.size(), i + IngestionService.MAX_BATCH)))
                .accepted();
        }
        assertEquals(2500, accepted);
        assertEquals(events.toString(), new SampleEvents(42, 60).generate(2500, now).toString(), "deterministic per seed");
    }

    @Test
    void scopedRuleIdsAreAcceptedStoredAndBounded() throws Exception {
        ObjectNode scoped = event("claude", "REDACT", null, null);
        scoped.putArray("appliedRuleIds").add("class.SECRET@4");
        scoped.putArray("monitorRuleIds").add("class.TCKN@7").add("class.TR_IBAN@2");
        ObjectNode plain = event("claude", "ALLOW", null, null);
        ApiClient.Response ok = internalClient().post("/internal/v1/verdict-events", batch(scoped, plain), false);
        assertEquals(202, ok.status(), String.valueOf(ok.body()));
        assertEquals(2, ok.body().get("accepted").asInt());
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        assertEquals("class.SECRET@4", jdbc.queryForObject("SELECT array_to_string(applied_rule_ids, ',') FROM "
            + "verdict_event WHERE event_id = ?::uuid", String.class, scoped.get("eventId").asText()));
        assertEquals("class.TCKN@7,class.TR_IBAN@2", jdbc.queryForObject("SELECT array_to_string(monitor_rule_ids, ',') "
            + "FROM verdict_event WHERE event_id = ?::uuid", String.class, scoped.get("eventId").asText()));
        assertEquals(0, jdbc.queryForObject("SELECT cardinality(applied_rule_ids) FROM verdict_event WHERE "
            + "event_id = ?::uuid", Integer.class, plain.get("eventId").asText()), "absent is empty");
        // PR 21 review D-02: the read path returns them (the masked role too: they are vocabulary).
        for (String login : new String[] {"synthetic-viewer", "synthetic-aiview"}) {
            JsonNode detail = signedIn(login).get("/api/v1/traffic/" + scoped.get("eventId").asText()).body();
            assertEquals("[\"class.SECRET@4\"]", detail.get("appliedRuleIds").toString(), login);
            assertEquals("[\"class.TCKN@7\",\"class.TR_IBAN@2\"]", detail.get("monitorRuleIds").toString(), login);
        }

        ObjectNode tooMany = event("claude", "ALLOW", null, null);
        var many = tooMany.putArray("appliedRuleIds");
        for (int i = 1; i <= 17; i++) {
            many.add("class.TCKN@" + i);
        }
        ObjectNode tooLong = event("claude", "ALLOW", null, null);
        tooLong.putArray("monitorRuleIds").add("class." + "X".repeat(130) + "@1");
        ObjectNode notAnId = event("claude", "ALLOW", null, null);
        notAnId.putArray("appliedRuleIds").add("192.0.2.10");
        ObjectNode platformId = event("claude", "ALLOW", null, null);
        platformId.putArray("appliedRuleIds").add("platform.claude@1");
        ObjectNode unknownClass = event("claude", "ALLOW", null, null);
        unknownClass.putArray("monitorRuleIds").add("class.SYNTHETIC_VALUE@1");
        ObjectNode duplicate = event("claude", "ALLOW", null, null);
        duplicate.putArray("appliedRuleIds").add("class.TCKN@3").add("class.TCKN@3");
        for (ObjectNode bad : new ObjectNode[] {tooMany, tooLong, notAnId, platformId, unknownClass, duplicate}) {
            ApiClient.Response refused = internalClient().post("/internal/v1/verdict-events", batch(bad), false);
            assertEquals(400, refused.status());
            assertEquals("INVALID_EVENT", refused.body().get("reason").asText());
            assertFalse(refused.body().get("message").asText().contains("192.0.2"), "values are never echoed");
        }
    }

    @Test
    void theContractIsExact() throws Exception {
        ObjectNode extra = event("claude", "ALLOW", null, null);
        extra.put("prompt", "synthetic");
        ApiClient.Response unknownField = internalClient().post("/internal/v1/verdict-events", batch(extra), false);
        assertEquals(400, unknownField.status());
        assertEquals("INVALID_JSON", unknownField.body().get("reason").asText());

        ObjectNode badVerdict = event("claude", "ALLOW", null, null).put("verdict", "MAYBE");
        ApiClient.Response refused = internalClient().post("/internal/v1/verdict-events",
            batch(event("claude", "ALLOW", null, null), badVerdict), false);
        assertEquals(400, refused.status());
        assertEquals("INVALID_EVENT", refused.body().get("reason").asText());
        assertTrue(refused.body().get("message").asText().contains("event 1: field 'verdict'"));
        assertFalse(refused.body().get("message").asText().contains("MAYBE"), "values are never echoed");

        ObjectNode missing = event("claude", "ALLOW", null, null);
        missing.remove("transport");
        assertEquals(400, internalClient().post("/internal/v1/verdict-events", batch(missing), false).status());
        ObjectNode future = event("claude", "ALLOW", null, null).put("receivedAt", "2099-01-01T00:00:00Z");
        assertEquals(400, internalClient().post("/internal/v1/verdict-events", batch(future), false).status());
        ObjectNode badPlatform = event("Claude.AI", "ALLOW", null, null);
        assertEquals(400, internalClient().post("/internal/v1/verdict-events", batch(badPlatform), false).status());
    }

    @Test
    void anOversizedBatchIsRefusedBeforeItIsRead() throws Exception {
        HttpResponse<String> r = HttpClient.newHttpClient().send(HttpRequest.newBuilder(
                URI.create("http://127.0.0.1:" + internal.port() + "/internal/v1/verdict-events"))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString("[" + " ".repeat(3 * 1024 * 1024) + "]")).build(),
            HttpResponse.BodyHandlers.ofString());
        assertEquals(413, r.statusCode());
    }

    @Test
    void eachPortServesOnlyItsOwnRoutes() throws Exception {
        assertEquals(404, admin().post("/internal/v1/verdict-events", "[]", false).status());
        assertEquals(404, internalClient().get("/api/v1/auth/csrf").status());
        assertEquals(404, internalClient().get("/api/v1/overview").status());
    }

    /** PORTS_AND_RESOURCES §3: the Prometheus text on the metrics listener (9400) only, without a session. */
    @Test
    void metricsAnswerOnTheMetricsListenerOnly() throws Exception {
        HttpResponse<String> r = HttpClient.newHttpClient().send(HttpRequest.newBuilder(
                URI.create("http://127.0.0.1:" + internal.metricsPort() + "/metrics")).GET().build(),
            HttpResponse.BodyHandlers.ofString());
        assertEquals(200, r.statusCode());
        String type = r.headers().firstValue("Content-Type").orElse("").replace(" ", "");
        assertTrue(type.startsWith("text/plain;") && type.contains("version=0.0.4"), type);
        assertTrue(r.headers().allValues("Set-Cookie").isEmpty(), "no session and no CSRF cookie");
        ApiClient metrics = new ApiClient(internal.metricsPort());
        assertEquals(404, metrics.get("/readyz").status(), "nothing else on the metrics port");
        assertEquals(404, metrics.get("/api/v1/auth/csrf").status());
        assertEquals(404, metrics.get("/internal/v1/policy/snapshot").status());
        assertEquals(404, metrics.post("/metrics", "[]", false).status(), "GET only, refused before security");
        for (String method : new String[] {"PUT", "DELETE", "OPTIONS"}) {
            HttpResponse<String> other = HttpClient.newHttpClient().send(HttpRequest.newBuilder(
                    URI.create("http://127.0.0.1:" + internal.metricsPort() + "/metrics"))
                .method(method, HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(404, other.statusCode(), method);
        }
        assertTrue(internal.listening(), "readiness counts the metrics listener (PR 27 review D-04)");
        assertEquals(404, admin().get("/metrics").status(), "never on the admin listener behind the ingress");
        assertEquals(404, internalClient().get("/metrics").status(), "not on the capture sink");
        assertEquals(404, new ApiClient(internal.snapshotPort()).get("/metrics").status(), "not on the snapshot feed");
    }

    @Test
    void readsNeedASessionAndLoginNeedsCsrf() throws Exception {
        ApiClient.Response anonymous = admin().get("/api/v1/overview");
        assertEquals(401, anonymous.status());
        assertEquals("AUTHENTICATION_REQUIRED", anonymous.body().get("reason").asText());

        ApiClient c = admin();
        ApiClient.Response noCsrf = c.post("/api/v1/auth/login", "{\"loginName\":\"synthetic-viewer\",\"password\":\"x\"}",
            false);
        assertEquals(403, noCsrf.status());
        assertEquals("CSRF_TOKEN_INVALID", noCsrf.body().get("reason").asText());

        ApiClient.Response wrong = admin().login("synthetic-viewer", "not-the-password");
        assertEquals(401, wrong.status());
        assertEquals("INVALID_CREDENTIALS", wrong.body().get("reason").asText());
        ApiClient.Response unknown = admin().login("synthetic-nobody", "not-the-password");
        assertEquals("INVALID_CREDENTIALS", unknown.body().get("reason").asText());
        ApiClient.Response empty = admin().login("synthetic-viewer", "");
        assertEquals(400, empty.status());

        ApiClient.Response noRole = admin().login("synthetic-norole", ControlTestEnvironment.PASSWORDS.get(
            "synthetic-norole"));
        assertEquals(403, noRole.status());
        assertEquals("NO_ROLE", noRole.body().get("reason").asText());
    }

    @Test
    void repeatedFailuresThrottleTheName() throws Exception {
        for (int i = 0; i < 5; i++) {
            assertEquals(401, admin().login("synthetic-throttled", "wrong").status());
        }
        ApiClient.Response locked = admin().login("synthetic-throttled", "wrong");
        assertEquals(429, locked.status());
        assertEquals("LOGIN_THROTTLED", locked.body().get("reason").asText());
    }

    @Test
    void viewerReadsUnmaskedPseudonymisedPagesAndCannotWrite() throws Exception {
        internalClient().post("/internal/v1/verdict-events", batch(event("gemini", "ALLOW", "synthetic.viewer.one",
            "198.51.100.4")), false);
        ApiClient viewer = signedIn("synthetic-viewer");
        ApiClient.Response overview = viewer.get("/api/v1/overview");
        assertEquals(200, overview.status());
        assertTrue(overview.body().get("total").asLong() >= 1);
        assertNull(overview.raw().headers().firstValue("X-RWSAFE-Masked").orElse(null));
        ApiClient.Response traffic = viewer.get("/api/v1/traffic?platform=gemini&limit=5");
        assertEquals(200, traffic.status());
        assertTrue(traffic.body().get("items").size() >= 1);
        assertEquals(403, viewer.post("/api/v1/policies", "{}", true).status());

        ApiClient.Response rawFilter = viewer.get("/api/v1/traffic?user=synthetic.viewer.one");
        assertEquals(400, rawFilter.status());
        assertEquals("INVALID_USER_FILTER", rawFilter.body().get("reason").asText());
        assertEquals(400, viewer.get("/api/v1/traffic?cursor=bm90LWEtY3Vyc29y").status());
        assertEquals("INVALID_PARAMETER", viewer.get("/api/v1/traffic?verdict=MAYBE").body().get("reason").asText());
        assertEquals("EVENT_NOT_FOUND", viewer.get("/api/v1/traffic/00000000-0000-0000-0000-000000000000").body()
            .get("reason").asText());
        assertEquals(200, viewer.get("/api/v1/health").status());
    }

    @Test
    void theMaskedRoleIsServedThroughTheFunnelAndIsReadOnly() throws Exception {
        ApiClient aiview = signedIn("synthetic-aiview");
        ApiClient.Response me = aiview.get("/api/v1/auth/me");
        assertTrue(me.body().get("masked").asBoolean());
        assertFalse(me.raw().body().contains("synthetic-aiview"), "the masked session does not show the login name");
        ApiClient.Response traffic = aiview.get("/api/v1/traffic?limit=5");
        assertEquals(200, traffic.status());
        assertEquals("true", traffic.raw().headers().firstValue("X-RWSAFE-Masked").orElse(""));
        assertEquals("rwmask-v1-slice1", traffic.raw().headers().firstValue("X-RWSAFE-Mask-Rules").orElse(""));
        assertEquals(403, aiview.post("/api/v1/policies", "{}", true).status());
        assertEquals(204, aiview.post("/api/v1/auth/logout", "", true).status());
        assertEquals(401, aiview.get("/api/v1/traffic").status());
    }

    @Test
    void breakGlassIsCreatedOnceOwnerOnlyAndLedgered() throws Exception {
        java.nio.file.Path file = java.nio.file.Path.of(breakGlassFile);
        assertFalse(Files.exists(file.resolveSibling(file.getFileName() + ".staged")));
        if (!System.getProperty("os.name").toLowerCase().contains("win")) {
            assertEquals(Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
                Files.getPosixFilePermissions(file));
        }
        ApiClient c = admin();
        ApiClient.Response r = c.login("breakglass", Files.readString(file).strip());
        assertEquals(200, r.status());
        assertEquals("local", r.body().get("source").asText());
        assertEquals("security_admin", r.body().get("roles").get(0).asText());
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM audit_event WHERE table_name = 'local_account' AND "
            + "action_id = 'local_account.create' AND actor_fingerprint = 'system:bootstrap'", Integer.class));
        assertTrue(jdbc.queryForObject("SELECT password_hash FROM local_account", String.class).startsWith("$2"));
        assertTrue(jdbc.queryForObject("SELECT count(*) FROM audit_event WHERE table_name = 'login_record' AND "
            + "reason_code = 'BREAK_GLASS_LOGIN' AND actor_fingerprint LIKE 'USR-%'", Integer.class) >= 1);
    }

    @Test
    void aUserInTheMaskedGroupIsSignedInMaskedOnlyAndLedgered() throws Exception {
        ApiClient dual = signedIn("synthetic-dual");
        JsonNode me = dual.get("/api/v1/auth/me").body();
        assertTrue(me.get("masked").asBoolean());
        assertEquals(1, me.get("roles").size());
        assertEquals("replay_viewer", me.get("roles").get(0).asText());
        assertEquals(403, dual.post("/api/v1/policies", "{}", true).status());
        assertTrue(new JdbcTemplate(dataSource).queryForObject("SELECT count(*) FROM audit_event WHERE action_id = "
            + "'session.activate_masked'", Integer.class) >= 1);
    }

    @Test
    void bodiesAreBoundedAsTheyAreRead() throws Exception {
        ApiClient c = admin();
        c.get("/api/v1/auth/csrf");
        ApiClient.Response big = c.post("/api/v1/auth/login", "{\"loginName\":\"" + "a".repeat(100_000) + "\"}", true);
        assertEquals(413, big.status());
        StringBuilder many = new StringBuilder("[");
        for (int i = 0; i <= IngestionService.MAX_BATCH; i++) {
            many.append(i == 0 ? "" : ",").append("{}");
        }
        ApiClient.Response tooMany = internalClient().post("/internal/v1/verdict-events", many.append(']').toString(),
            false);
        assertEquals(400, tooMany.status());
        assertTrue(tooMany.body().get("message").asText().contains("at most 1000"));
        assertEquals(400, internalClient().post("/internal/v1/verdict-events", "{}", false).status());
    }

    @Test
    void reasonsAndCorrelationIdsCannotCarryValues() throws Exception {
        ObjectNode dotted = event("claude", "BLOCK", null, null).put("reason", "synthetic.example.test");
        assertEquals(400, internalClient().post("/internal/v1/verdict-events", batch(dotted), false).status());
        ObjectNode tckn = event("claude", "BLOCK", null, null)
            .put("correlationId", io.rwsafe.control.support.Synthetic.tckn(3));
        ApiClient.Response r = internalClient().post("/internal/v1/verdict-events", batch(tckn), false);
        assertEquals(400, r.status());
        assertTrue(r.body().get("message").asText().contains("correlationId"));
        // A UUID whose digit groups happen to form a Luhn-valid card number is still a UUID (the data plane's ids).
        String cardLike = "41111111-1111-1111-1111-111111111111";
        assertTrue(IngestionService.canonicalUuid(cardLike));
        ObjectNode uuid = event("claude", "ALLOW", null, null).put("correlationId", cardLike);
        assertEquals(202, internalClient().post("/internal/v1/verdict-events", batch(uuid), false).status());
    }

    @Test
    void withoutTheConfiguredNoticeValuesNothingCanBeAcknowledged() throws Exception {
        // PR 22 review D-03: this context configures no RWSAFE_ENDUSER_ value, so no notice was shown.
        ApiClient.Response r = internalClient().post("/internal/v1/notice-acknowledgements",
            "[{\"userClaim\":\"SYNTHETIC\\\\user-x\",\"noticeVersion\":\"tr-2-0a1b2c3d\",\"acknowledgedAt\":\""
                + java.time.Instant.now() + "\",\"source\":\"directory_attribute\"}]", false);
        assertEquals(400, r.status());
        assertEquals("NOTICE_INCOMPLETE", r.body().get("reason").asText());
        assertEquals(0, new JdbcTemplate(dataSource).queryForObject("SELECT count(*) FROM notice_acknowledgement",
            Integer.class));
    }
}
