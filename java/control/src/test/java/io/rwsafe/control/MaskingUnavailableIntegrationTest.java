package io.rwsafe.control;

import static io.rwsafe.control.support.EventsJson.batch;
import static io.rwsafe.control.support.EventsJson.event;
import static org.junit.jupiter.api.Assertions.assertEquals;

import io.rwsafe.control.config.InternalConnector;
import io.rwsafe.control.support.ApiClient;
import io.rwsafe.control.support.ControlTestEnvironment;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/** AGENTS.md 4.10: without the estate dictionary the masked role gets 503, never an unmasked page; others still read. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class MaskingUnavailableIntegrationTest {

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) throws Exception {
        ControlTestEnvironment.register(r, true, false);
    }

    @LocalServerPort
    int port;
    @Autowired
    InternalConnector internal;

    @Test
    void theMaskedRoleGets503AndTheViewerDoesNot() throws Exception {
        assertEquals(202, new ApiClient(internal.port()).post("/internal/v1/verdict-events",
            batch(event("claude", "ALLOW", "synthetic.user.x", "192.0.2.5")), false).status());
        ApiClient aiview = new ApiClient(port);
        // The login answer is itself a masked page, so even it is 503.
        assertEquals(503, aiview.login("synthetic-aiview", ControlTestEnvironment.PASSWORDS.get("synthetic-aiview"))
            .status());
        for (String path : new String[] {"/api/v1/overview", "/api/v1/traffic", "/api/v1/health", "/api/v1/auth/me"}) {
            ApiClient.Response r = aiview.get(path);
            assertEquals(503, r.status(), path);
            assertEquals("MASKING_UNAVAILABLE", r.body().get("reason").asText(), path);
        }
        ApiClient viewer = new ApiClient(port);
        assertEquals(200, viewer.login("synthetic-viewer", ControlTestEnvironment.PASSWORDS.get("synthetic-viewer"))
            .status());
        assertEquals(200, viewer.get("/api/v1/overview").status());
    }
}
