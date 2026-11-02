package io.rwsafe.control.admin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.rwsafe.control.config.ControlProperties;
import io.rwsafe.control.ops.JobCatalog;
import io.rwsafe.control.ops.ScheduledJobs;
import io.rwsafe.control.privacy.Pseudonymiser;
import io.rwsafe.control.support.ApiClient;
import io.rwsafe.control.support.ApiInventory;
import io.rwsafe.control.support.ControlTestEnvironment;
import io.rwsafe.control.support.Synthetic;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Administration -> Records and Platform end to end (PO decision Q-47 decisions 1.3 and 1.4): who may read each screen,
 * the audit log as the SIEM shows the ledger (newest first, filtered, paged, never a body), the job log, the system
 * facts, the system log as classes and counts, and the outbound channels without an address.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class RecordsAndPlatformIntegrationTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Logger LOG = LoggerFactory.getLogger(RecordsAndPlatformIntegrationTest.class);
    private static final String ADMIN = "synthetic-admin";
    private static final List<String> ROUTES = List.of("/api/v1/admin/audit", "/api/v1/admin/jobs",
        "/api/v1/admin/system", "/api/v1/admin/logs", "/api/v1/admin/notifications");

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
    @Autowired
    ScheduledJobs scheduledJobs;
    @Autowired
    ControlProperties properties;

    private ApiClient signedIn(String login) throws Exception {
        ApiClient c = new ApiClient(port);
        ApiClient.Response r = c.login(login, ControlTestEnvironment.PASSWORDS.get(login));
        assertEquals(200, r.status(), String.valueOf(r.body()));
        return c;
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    @Test
    void eachScreenIsReadByItsRolesOnlyAndNeverByTheMaskedRole() throws Exception {
        Map<String, Set<String>> allowed = Map.of(
            ADMIN, Set.copyOf(ROUTES),
            "synthetic-officer", Set.of("/api/v1/admin/audit"),
            "synthetic-viewer", Set.of(),
            "synthetic-aiview", Set.of(),
            "synthetic-dual", Set.of());
        for (var who : allowed.entrySet()) {
            ApiClient c = signedIn(who.getKey());
            for (String route : ROUTES) {
                ApiClient.Response r = c.get(route);
                if (who.getValue().contains(route)) {
                    assertEquals(200, r.status(), who.getKey() + " " + route + " " + r.body());
                } else {
                    assertEquals(403, r.status(), who.getKey() + " " + route);
                    assertEquals("FORBIDDEN", r.body().get("reason").asText(), "refused by the security chain");
                }
            }
        }
        assertEquals(401, new ApiClient(port).get("/api/v1/admin/audit").status());
    }

    @Test
    void theAuditLogShowsTheLedgerAsTheSiemDoesNewestFirstAndPaged() throws Exception {
        ApiClient admin = signedIn(ADMIN);
        ObjectNode body = JSON.createObjectNode().put("loginName", "synthetic.audited")
            .put("displayName", "Synthetic Audited").put("reason", "onboarding");
        body.putArray("roles").add("viewer");
        ApiClient.Response created = admin.post("/api/v1/admin/users", body.toString(), true);
        assertEquals(201, created.status(), String.valueOf(created.body()));
        String subject = created.body().get("user").get("subject").asText();
        String actor = pseudonymiser.user(ADMIN);

        // The privacy officer reads the same page.
        JsonNode page = signedIn("synthetic-officer").get("/api/v1/admin/audit?action=local_user.create").body();
        JsonNode entry = null;
        for (JsonNode e : page.get("entries")) {
            if (subject.equals(e.get("rowKey").asText())) {
                entry = e;
            }
        }
        assertNotNull(entry, "the creation is in the audit log: " + page);
        assertEquals(actor, entry.get("actor").asText(), "the actor is the pseudonym the ledger stores");
        assertEquals("local_user.create", entry.get("action").asText());
        assertEquals("local_user", entry.get("table").asText());
        assertEquals("INSERT", entry.get("operation").asText());
        assertEquals("onboarding", entry.get("reason").asText());
        // Fixed fields only: the ledger has no body, and the page adds none.
        Set<String> fields = new TreeSet<>();
        entry.fieldNames().forEachRemaining(fields::add);
        assertEquals(new TreeSet<>(Set.of("id", "occurredAt", "actor", "action", "table", "operation", "rowKey",
            "reason")), fields);
        assertTrue(JSON.convertValue(page.get("actions"), List.class).contains("local_user.create"));

        // Newest first, a bounded page, and the cursor continues it.
        JsonNode first = admin.get("/api/v1/admin/audit?limit=1").body();
        assertEquals(1, first.get("entries").size());
        String cursor = first.get("nextCursor").asText();
        JsonNode second = admin.get("/api/v1/admin/audit?limit=1&cursor=" + cursor).body();
        assertTrue(second.get("entries").get(0).get("id").asLong() < first.get("entries").get(0).get("id").asLong());
        // PR 51 review D-04: the action choices come with a first page only.
        assertTrue(first.get("actions").size() > 0);
        assertEquals(0, second.get("actions").size(), "no action query on a cursor page");

        // The actor filter takes a pseudonym; every entry is that actor's.
        JsonNode mine = admin.get("/api/v1/admin/audit?actor=" + enc(actor)).body();
        assertTrue(mine.get("entries").size() > 0);
        mine.get("entries").forEach(e -> assertEquals(actor, e.get("actor").asText()));

        // An account key (the break-glass account's name) never appears as written: it is the account's pseudonym.
        List<String> accounts = new JdbcTemplate(dataSource).queryForList("SELECT account_name FROM local_account",
            String.class);
        String all = admin.get("/api/v1/admin/audit?limit=200").raw().body();
        for (String account : accounts) {
            assertFalse(all.contains("\"" + account + "\""), "an account name reached the audit log");
        }
        assertFalse(all.contains("synthetic.audited"), "a login name reached the audit log");
    }

    @Test
    void theAuditLogRefusesFiltersThatAreNotVocabularyOrPseudonyms() throws Exception {
        ApiClient admin = signedIn(ADMIN);
        Map<String, String> refused = Map.of(
            "/api/v1/admin/audit?action=" + enc("not an action"), "INVALID_ACTION_FILTER",
            "/api/v1/admin/audit?actor=" + ADMIN, "INVALID_ACTOR_FILTER",
            "/api/v1/admin/audit?cursor=abc", "INVALID_CURSOR",
            // PR 51 review D-02: above Long.MAX_VALUE, and not a ledger id.
            "/api/v1/admin/audit?cursor=9999999999999999999", "INVALID_CURSOR",
            "/api/v1/admin/audit?cursor=0", "INVALID_CURSOR",
            "/api/v1/admin/audit?limit=0", "INVALID_LIMIT",
            "/api/v1/admin/audit?limit=201", "INVALID_LIMIT",
            "/api/v1/admin/audit?from=2026-11-02T10:00:00Z&to=2026-11-02T09:00:00Z", "INVALID_WINDOW",
            "/api/v1/admin/audit?from=2024-01-01T00:00:00Z&to=2026-11-02T09:00:00Z", "WINDOW_TOO_LONG");
        for (var r : refused.entrySet()) {
            ApiClient.Response answer = admin.get(r.getKey());
            assertEquals(400, answer.status(), r.getKey());
            assertEquals(r.getValue(), answer.body().get("reason").asText(), r.getKey());
        }
    }

    @Test
    void theJobLogListsEveryJobWithItsScheduleAndLastRun() throws Exception {
        scheduledJobs.captureWatermark();
        scheduledJobs.snapshotResign();
        JsonNode view = signedIn(ADMIN).get("/api/v1/admin/jobs").body();
        assertNotNull(view.get("since").asText());
        List<String> ids = new ArrayList<>();
        view.get("jobs").forEach(j -> ids.add(j.get("id").asText()));
        assertEquals(JobCatalog.JOBS.stream().map(JobCatalog.Job::id).toList(), ids);
        for (JsonNode j : view.get("jobs")) {
            switch (j.get("id").asText()) {
                case JobCatalog.CAPTURE_WATERMARK -> {
                    assertEquals("OK", j.get("state").asText());
                    assertEquals(30, j.get("delaySeconds").asLong());
                    assertTrue(j.get("runs").asLong() >= 1);
                    assertTrue(j.get("counts").has("paths"));
                    assertNotNull(j.get("nextRunAt").asText());
                }
                case JobCatalog.SNAPSHOT_RESIGN -> {
                    assertEquals("OK", j.get("state").asText(), String.valueOf(j));
                    assertTrue(j.get("counts").get("snapshotVersion").asLong() >= 1);
                }
                case JobCatalog.CAPTURE_RETENTION -> {
                    assertEquals("CRON", j.get("kind").asText());
                    assertEquals(JobCatalog.CAPTURE_RETENTION_CRON, j.get("cron").asText());
                    assertEquals("Europe/Istanbul", j.get("zone").asText());
                    assertFalse(j.get("nextRunAt").isNull());
                }
                case JobCatalog.SIEM_EXPORT -> {
                    assertEquals("CONTINUOUS", j.get("kind").asText());
                    assertEquals("OFF", j.get("state").asText());
                    assertTrue(j.get("nextRunAt").isNull());
                }
                default -> {
                }
            }
        }
    }

    @Test
    void theSystemScreenShowsVersionSchemaUptimeAndSwitches() throws Exception {
        JsonNode view = signedIn(ADMIN).get("/api/v1/admin/system").body();
        String highest;
        try (Stream<Path> files = Files.list(ApiInventory.repositoryRoot()
            .resolve("java/persistence/src/main/resources/db/migration"))) {
            highest = Integer.toString(files.map(p -> p.getFileName().toString())
                .filter(n -> n.matches("V\\d+__.*\\.sql")).mapToInt(n -> Integer.parseInt(n.substring(1, n.indexOf("__"))))
                .max().orElseThrow());
        }
        assertEquals(highest, view.get("schemaVersion").asText());
        assertEquals("dev", view.get("version").asText(), "no packaged version in a test run");
        assertTrue(view.get("commit").isNull(), "the test image carries no commit id");
        assertTrue(view.get("javaVersion").asText().startsWith(Integer.toString(Runtime.version().feature())));
        assertTrue(view.get("uptimeSeconds").asLong() >= 0);
        JsonNode s = view.get("switches");
        assertEquals(properties.policy().singleApproval(), s.get("singleApproval").asBoolean());
        assertEquals(properties.identity().breakGlass().enabled(), s.get("breakGlassSignIn").asBoolean());
        // The stored directory settings (PR 50: the deploy values seeded version 1 at start), as facts only.
        assertTrue(s.get("directoryConfigured").asBoolean(), "the seeded settings are stored");
        assertTrue(s.get("directoryEnabled").asBoolean());
        assertTrue(s.get("directoryKeyPresent").asBoolean(), "the test mounts the directory key");
        assertEquals("ACTIVE", s.get("directoryStatus").asText());
        Set<String> switchFields = new TreeSet<>();
        s.fieldNames().forEachRemaining(switchFields::add);
        assertEquals(new TreeSet<>(Set.of("singleApproval", "breakGlassSignIn", "directoryConfigured",
            "directoryEnabled", "directoryKeyPresent", "directoryStatus", "captureMode", "siemExport")), switchFields,
            "no URL, DN or group field");
        assertFalse(view.toString().contains(ControlTestEnvironment.BASE), "no directory name reaches the screen");
        assertEquals("off", s.get("captureMode").asText());
        assertFalse(s.get("siemExport").asBoolean());
    }

    @Test
    void theSystemLogShowsClassesAndCountsNeverAValue() throws Exception {
        String email = "synthetic.person" + "@" + "example.test";
        String tckn = Synthetic.tckn(91);
        String prompt = "Please summarise the synthetic letter about the customer account";
        LOG.warn("synthetic probe failed for {} with {}", email, prompt,
            new IllegalStateException("account " + tckn + " " + email));
        LOG.warn("synthetic concatenated " + email);
        ApiClient.Response r = signedIn(ADMIN).get("/api/v1/admin/logs");
        assertEquals(200, r.status());
        for (String value : List.of(email, tckn, prompt)) {
            assertFalse(r.raw().body().contains(value), "a value reached the system log screen");
        }
        JsonNode view = r.body();
        assertTrue(view.get("capturing").asBoolean());
        assertEquals(24, view.get("windowHours").asInt());
        JsonNode probe = null;
        for (JsonNode e : view.get("recent")) {
            if ("RecordsAndPlatformIntegrationTest".equals(e.get("logger").asText())
                && "IllegalStateException".equals(e.get("exceptionClass").asText())) {
                probe = e;
            }
        }
        assertNotNull(probe, "the warning is listed");
        assertEquals("WARN", probe.get("level").asText());
        assertEquals("synthetic probe failed for {} with {}", probe.get("template").asText());
        Set<String> fields = new TreeSet<>();
        probe.fieldNames().forEachRemaining(fields::add);
        assertEquals(new TreeSet<>(Set.of("at", "level", "logger", "own", "exceptionClass", "template")), fields);
        boolean counted = false;
        for (JsonNode c : view.get("counts")) {
            counted |= "RecordsAndPlatformIntegrationTest".equals(c.get("logger").asText())
                && "WARN".equals(c.get("level").asText()) && c.get("count").asLong() >= 2;
        }
        assertTrue(counted, "the warnings are counted per logger and level");
    }

    @Test
    void notificationsShowTheOutboundChannelsWithoutAnAddress() throws Exception {
        JsonNode view = signedIn(ADMIN).get("/api/v1/admin/notifications").body();
        assertFalse(view.get("siemEnabled").asBoolean());
        assertEquals("OFF", view.get("siemState").asText());
        assertFalse(view.get("emailAvailable").asBoolean());
        List<String> kinds = new ArrayList<>();
        for (JsonNode d : view.get("siemDestinations")) {
            kinds.add(d.get("kind").asText());
            assertFalse(d.get("configured").asBoolean());
            Set<String> fields = new TreeSet<>();
            d.fieldNames().forEachRemaining(fields::add);
            assertEquals(new TreeSet<>(Set.of("kind", "format", "configured")), fields, "no address field");
        }
        assertEquals(List.of("syslog", "hec"), kinds);
        assertNull(view.get("siemDestinations").get(1).get("format").textValue());
        assertNotEquals(0, view.size());
    }
}
