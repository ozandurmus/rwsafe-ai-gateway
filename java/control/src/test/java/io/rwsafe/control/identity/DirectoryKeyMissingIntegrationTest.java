package io.rwsafe.control.identity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.rwsafe.control.support.ApiClient;
import io.rwsafe.control.support.ControlTestEnvironment;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Without the directory key Secret (PO decision Q-47, decision 1.2) the control plane starts, the break-glass account
 * signs in, the directory is unavailable with that reason, the deploy values are not seeded, and a bind password is
 * never stored: no plaintext fallback.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class DirectoryKeyMissingIntegrationTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) throws Exception {
        ControlTestEnvironment.register(r, true, ControlTestEnvironment.dir().resolve("dictionary.txt"),
            ControlTestEnvironment.SNAPSHOT_KEY_ID, false);
    }

    @LocalServerPort
    int port;
    @Autowired
    DataSource dataSource;
    @Value("${rwsafe.identity.break-glass.initial-password-file}")
    String breakGlassFile;

    @Test
    void theDirectoryIsUnavailableWithItsReasonAndNoPasswordIsStored() throws Exception {
        ApiClient.Response directoryLogin = new ApiClient(port).login("synthetic-admin",
            ControlTestEnvironment.PASSWORDS.get("synthetic-admin"));
        assertEquals(401, directoryLogin.status(), "no directory sign-in without the key");

        ApiClient admin = new ApiClient(port);
        assertEquals(200, admin.login("breakglass", Files.readString(Path.of(breakGlassFile)).strip()).status());
        JsonNode view = admin.get("/api/v1/admin/directory").body();
        assertEquals("NOT_CONFIGURED", view.get("status").asText());
        assertEquals("DIRECTORY_KEY_MISSING", view.get("statusReason").asText());
        assertEquals("MISSING", view.get("keyState").asText());
        assertEquals(0, view.get("version").asInt());
        assertEquals(0, view.get("history").size(), "the deploy values were not seeded without the key");

        ObjectNode save = JSON.createObjectNode().put("expectedVersion", 0).put("enabled", true)
            .put("tlsMode", "none").put("bindDn", "cn=synthetic-service," + ControlTestEnvironment.BASE)
            .put("userSearchBase", ControlTestEnvironment.PEOPLE).put("userSearchFilter", "(uid={0})")
            .put("newPassword", ControlTestEnvironment.bindPassword()).put("reason", "first connection");
        save.putArray("urls").add("ldap://127.0.0.1:" + ControlTestEnvironment.ldapPort());
        ApiClient.Response refused = admin.post("/api/v1/admin/directory/connection", save.toString(), true);
        assertEquals(503, refused.status());
        assertEquals("DIRECTORY_KEY_MISSING", refused.body().get("reason").asText());
        assertEquals(0, new JdbcTemplate(dataSource).queryForObject("SELECT count(*) FROM directory_settings",
            Integer.class));

        // Without a password the connection is stored, and the directory says why it is not used.
        save.remove("newPassword");
        ApiClient.Response saved = admin.post("/api/v1/admin/directory/connection", save.toString(), true);
        assertEquals(200, saved.status(), String.valueOf(saved.body()));
        assertEquals("UNAVAILABLE", saved.body().get("status").asText());
        assertEquals("BIND_PASSWORD_NOT_SET", saved.body().get("statusReason").asText());
        assertFalse(saved.body().get("settings").get("passwordSet").asBoolean());
        assertEquals(1, new JdbcTemplate(dataSource).queryForObject(
            "SELECT count(*) FROM directory_settings WHERE bind_password_sealed IS NULL", Integer.class));
        assertEquals(401, new ApiClient(port).login("synthetic-admin",
            ControlTestEnvironment.PASSWORDS.get("synthetic-admin")).status());
    }
}
