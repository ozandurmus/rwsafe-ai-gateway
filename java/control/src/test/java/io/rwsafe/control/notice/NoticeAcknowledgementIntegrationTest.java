package io.rwsafe.control.notice;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import io.rwsafe.control.config.InternalConnector;
import io.rwsafe.control.privacy.MaskingFunnel;
import io.rwsafe.control.privacy.Pseudonymiser;
import io.rwsafe.control.support.ApiClient;
import io.rwsafe.control.support.ControlTestEnvironment;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
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
 * PRIV-2 and SR-PRIV-10 end to end: the configured notice has a version; acknowledgements from the banner and from the
 * directory's HR acknowledgement (Q-35) open content capture for exactly that version; an older version or no record
 * keeps it closed; the store holds pseudonyms only; the masked role reads the same records through the funnel without
 * the notice's configured values.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class NoticeAcknowledgementIntegrationTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    /** Synthetic directory claims; never a real account. */
    private static final String ALICE = "SYNTHETIC\\user-banner";
    /** The user@realm claim form; the realm has no dot, so it reads as no address. */
    private static final String BORA = "user-directory@SYNTHETIC";
    private static final String CEM = "SYNTHETIC\\user-old-version";
    private static final String CONTROLLER = "Örnek Kurum A.Ş.";

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) throws Exception {
        ControlTestEnvironment.register(r, true, true);
        r.add("RWSAFE_ENDUSER_CONTROLLER_NAME", () -> CONTROLLER);
        r.add("RWSAFE_ENDUSER_DPO_CONTACT", () -> "basvuru.synthetic.example.test");
        r.add("RWSAFE_ENDUSER_POLICY_LINK", () -> "https://intranet.synthetic.example.test/politika");
        r.add("RWSAFE_ENDUSER_RETENTION_METADATA", () -> "400");
        r.add("RWSAFE_ENDUSER_RETENTION_REDACTED", () -> "90");
        r.add("RWSAFE_ENDUSER_RETENTION_RAW", () -> "30");
    }

    @LocalServerPort
    int port;
    @Autowired
    InternalConnector internal;
    @Autowired
    NoticeCatalogue notice;
    @Autowired
    NoticeAcknowledgementService service;
    @Autowired
    Pseudonymiser pseudonymiser;
    @Autowired
    DataSource dataSource;

    private final HttpClient http = HttpClient.newHttpClient();

    private HttpResponse<String> intake(int onPort, String body) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + onPort + NoticeIntakeController.PATH))
            .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body)).build(),
            HttpResponse.BodyHandlers.ofString());
    }

    private static String batch(String[]... records) {
        ArrayNode a = JSON.createArrayNode();
        for (String[] r : records) {
            a.addObject().put("userClaim", r[0]).put("noticeVersion", r[1]).put("acknowledgedAt", r[2])
                .put("source", r[3]);
        }
        return a.toString();
    }

    private ApiClient signedIn(String login) throws Exception {
        ApiClient c = new ApiClient(port);
        assertEquals(200, c.login(login, ControlTestEnvironment.PASSWORDS.get(login)).status());
        return c;
    }

    @Test
    void acknowledgementsOpenContentCaptureForTheCurrentVersionOnly() throws Exception {
        String current = notice.currentVersion().orElseThrow();
        String older = "tr-0-0a1b2c3d";
        String yesterday = Instant.now().minus(1, ChronoUnit.DAYS).toString();
        HttpResponse<String> r = intake(internal.port(), batch(
            new String[] {ALICE, current, yesterday, "banner"},
            new String[] {BORA, current, "2026-03-01T00:00:00Z", "directory_attribute"},
            new String[] {CEM, older, yesterday, "ide_first_run"},
            new String[] {ALICE, current, yesterday, "banner"}));
        assertEquals(202, r.statusCode(), r.body());
        JsonNode result = JSON.readTree(r.body());
        assertEquals(3, result.get("accepted").asInt());
        assertEquals(1, result.get("duplicates").asInt());
        assertEquals(0, JSON.readTree(intake(internal.port(), batch(new String[] {ALICE, current, yesterday,
            "banner"})).body()).get("accepted").asInt(), "a retried record is stored once");

        String alice = pseudonymiser.user(ALICE);
        String bora = pseudonymiser.user(BORA);
        String cem = pseudonymiser.user(CEM);
        assertTrue(service.contentCaptureAllowed(alice), "banner acknowledgement");
        assertTrue(service.contentCaptureAllowed(bora), "Q-35: the directory's HR acknowledgement with version and date");
        assertFalse(service.contentCaptureAllowed(cem), "PC-1: an older version does not count");
        assertFalse(service.contentCaptureAllowed(pseudonymiser.user("SYNTHETIC\\user-never")), "no record");
        assertFalse(service.contentCaptureAllowed(null));

        // The store holds pseudonyms only: no claim, no realm, no name.
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        assertEquals(0, jdbc.queryForObject("SELECT count(*) FROM notice_acknowledgement WHERE user_pseudonym NOT LIKE "
            + "'USR-%' OR user_pseudonym ILIKE '%synthetic%' OR user_pseudonym ILIKE '%user-%'", Integer.class));
        assertEquals(3, jdbc.queryForObject("SELECT count(*) FROM audit_event WHERE table_name = "
            + "'notice_acknowledgement' AND actor_fingerprint = 'system:notice-intake'", Integer.class));

        ApiClient admin = signedIn("synthetic-admin");
        ApiClient.Response mine = admin.get("/api/v1/notice/acknowledgements?user=" + alice);
        assertEquals(200, mine.status(), String.valueOf(mine.body()));
        assertEquals(alice, mine.body().get("user").asText());
        assertEquals(current, mine.body().get("currentVersion").asText());
        assertTrue(mine.body().get("currentAcknowledged").asBoolean());
        assertEquals("banner", mine.body().get("records").get(0).get("source").asText());
        ApiClient.Response old = admin.get("/api/v1/notice/acknowledgements?user=" + cem);
        assertFalse(old.body().get("currentAcknowledged").asBoolean());
        assertEquals(older, old.body().get("records").get(0).get("noticeVersion").asText());

        ApiClient masked = signedIn("synthetic-aiview");
        ApiClient.Response seen = masked.get("/api/v1/notice/acknowledgements?user=" + bora);
        assertEquals(200, seen.status(), String.valueOf(seen.body()));
        assertEquals("true", seen.raw().headers().firstValue(MaskingFunnel.MASKED_HEADER).orElse(""));
        assertTrue(seen.body().get("currentAcknowledged").asBoolean());
        assertEquals("directory_attribute", seen.body().get("records").get(0).get("source").asText());
        assertFalse(seen.raw().body().contains("synthetic.example.test"));

        for (ApiClient c : new ApiClient[] {admin, masked}) {
            ApiClient.Response byName = c.get("/api/v1/notice/acknowledgements?user=user-banner");
            assertEquals(400, byName.status());
            assertEquals("INVALID_USER_FILTER", byName.body().get("reason").asText());
        }
    }

    @Test
    void theNoticeIsServedWholeToOperatorsAndWithoutConfiguredValuesMasked() throws Exception {
        ApiClient admin = signedIn("synthetic-officer");
        ApiClient.Response n = admin.get("/api/v1/notice");
        assertEquals(200, n.status(), String.valueOf(n.body()));
        assertTrue(n.body().get("complete").asBoolean());
        String version = n.body().get("currentVersion").asText();
        assertTrue(version.startsWith("tr-1-"), version);
        assertEquals(0, n.body().get("missingParameters").size());
        assertTrue(n.raw().body().contains(CONTROLLER));
        assertTrue(n.raw().body().contains("sürüm " + version));
        assertEquals(11, n.body().get("sections").size());

        ApiClient masked = signedIn("synthetic-aiview");
        ApiClient.Response m = masked.get("/api/v1/notice");
        assertEquals(200, m.status(), String.valueOf(m.body()));
        assertEquals(version, m.body().get("currentVersion").asText());
        assertTrue(m.body().get("sections").isNull());
        assertFalse(m.raw().body().contains(CONTROLLER));
        assertFalse(m.raw().body().contains("synthetic.example.test"));
    }

    @Test
    void invalidRecordsAreRefusedWholeAndNeverEchoed() throws Exception {
        String current = notice.currentVersion().orElseThrow();
        String now = Instant.now().toString();
        String future = Instant.now().plus(1, ChronoUnit.DAYS).toString();
        String[][] bad = {
            {ALICE, "latest", now, "banner"},
            {ALICE, current, future, "banner"},
            {ALICE, current, "2019-01-01T00:00:00Z", "directory_attribute"},
            {ALICE, current, "yesterday", "banner"},
            {ALICE, current, now, "email"},
            {" ", current, now, "banner"},
        };
        for (String[] record : bad) {
            HttpResponse<String> r = intake(internal.port(), batch(new String[] {BORA, current, now, "banner"}, record));
            assertEquals(400, r.statusCode(), r.body());
            assertTrue(r.body().contains("INVALID_ACKNOWLEDGEMENT"), r.body());
            assertFalse(r.body().contains("user-banner") || r.body().contains("SYNTHETIC"), "the claim is never echoed");
        }
        HttpResponse<String> missingDate = intake(internal.port(),
            "[{\"userClaim\":\"x\",\"noticeVersion\":\"" + current + "\",\"source\":\"directory_attribute\"}]");
        assertEquals(400, missingDate.statusCode(), "Q-35: a directory record without its date does not count");
        assertEquals(400, intake(internal.port(), "[{\"userClaim\":\"x\",\"noticeVersion\":\"" + current
            + "\",\"acknowledgedAt\":\"" + now + "\",\"source\":\"banner\",\"consent\":true}]").statusCode());
        assertEquals(400, intake(internal.port(), "[]").statusCode());
        assertEquals(0, new JdbcTemplate(dataSource).queryForObject("SELECT count(*) FROM notice_acknowledgement",
            Integer.class), "a refused batch stores nothing");

        assertEquals(404, intake(port, batch(new String[] {BORA, current, now, "banner"})).statusCode(),
            "the intake answers only on the capture sink");
        assertEquals(404, intake(internal.snapshotPort(), batch(new String[] {BORA, current, now, "banner"}))
            .statusCode());
    }
}
