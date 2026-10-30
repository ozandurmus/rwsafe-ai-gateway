package io.rwsafe.control;

import static io.rwsafe.control.support.EventsJson.batch;
import static io.rwsafe.control.support.EventsJson.event;
import static org.junit.jupiter.api.Assertions.assertEquals;

import io.rwsafe.control.config.InternalConnector;
import io.rwsafe.control.support.ApiClient;
import io.rwsafe.control.support.ControlTestEnvironment;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/** Without the privacy key nothing is stored: the batch is refused with 503 so the data plane retries. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class PrivacyKeyMissingIntegrationTest {

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) throws Exception {
        ControlTestEnvironment.register(r, false, true);
    }

    @Autowired
    InternalConnector internal;
    @Autowired
    DataSource dataSource;

    @Test
    void ingestionIsRefusedAndNothingIsStored() throws Exception {
        ApiClient.Response r = new ApiClient(internal.port()).post("/internal/v1/verdict-events",
            batch(event("claude", "ALLOW", "synthetic.user.y", "192.0.2.6")), false);
        assertEquals(503, r.status());
        assertEquals("PRIVACY_KEY_UNAVAILABLE", r.body().get("reason").asText());
        assertEquals(0, new JdbcTemplate(dataSource).queryForObject("SELECT count(*) FROM verdict_event", Integer.class));
    }
}
