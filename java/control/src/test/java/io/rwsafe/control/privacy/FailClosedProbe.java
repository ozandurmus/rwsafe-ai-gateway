package io.rwsafe.control.privacy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.rwsafe.control.identity.Roles;
import io.rwsafe.control.support.ApiClient;
import io.rwsafe.control.support.ApiInventory;
import io.rwsafe.control.support.ControlTestEnvironment;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

/**
 * MASKING_AND_PRIVACY part C "503 fail-closed" (AGENTS.md 4.10, SR-PRIV-7) over the leak probe's whole inventory: with the
 * estate dictionary or the privacy key missing, a masked session cannot be opened, and a request that already carries
 * the masked role (here injected, as a session opened before the mount disappeared would) gets 503
 * {@code MASKING_UNAVAILABLE} on every read the UI or the server has, and 403 on every mutation; never an unmasked page.
 * Each subclass is one context with one part missing.
 */
abstract class FailClosedProbe {

    private static final ObjectMapper JSON = new ObjectMapper();

    @Autowired
    WebApplicationContext context;
    @Autowired
    RequestMappingHandlerMapping mapping;
    @LocalServerPort
    int port;

    @Test
    void everyMaskedRequestIsRefusedAndNoneIsServedUnmasked() throws Exception {
        // The sign-in itself, over the real listener: no masked session is opened, so nothing is read after it. (First:
        // MockMvc's csrf() below swaps the shared CSRF filter's repository for a test one.)
        ApiClient aiview = new ApiClient(port);
        ApiClient.Response login = aiview.login("synthetic-aiview",
            ControlTestEnvironment.PASSWORDS.get("synthetic-aiview"));
        assertEquals(503, login.status(), String.valueOf(login.body()));
        assertEquals(401, aiview.get("/api/v1/overview").status());

        // A request that already carries the masked role, on every endpoint of the inventory.
        MockMvc mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        Set<String> inventory = new TreeSet<>(ApiInventory.frontendEndpoints());
        inventory.addAll(ApiInventory.serverEndpoints(mapping));
        List<String> wrong = new ArrayList<>();
        int reads = 0;
        int writes = 0;
        for (String endpoint : inventory) {
            String method = endpoint.substring(0, endpoint.indexOf(' '));
            String path = endpoint.substring(endpoint.indexOf(' ') + 1).replace("{}", "class.TCKN")
                .replace("/traffic/class.TCKN", "/traffic/" + UUID.randomUUID());
            if (method.equals("GET")) {
                reads++;
                MvcResult r = mvc.perform(get(path + "?ruleId=class.TCKN&action=BLOCK")
                    .with(user("synthetic-masked-probe").roles(Roles.REPLAY_VIEWER))).andReturn();
                String body = r.getResponse().getContentAsString();
                JsonNode json = body.isEmpty() ? null : JSON.readTree(body);
                if (r.getResponse().getStatus() != 503 || json == null
                    || !"MASKING_UNAVAILABLE".equals(json.path("reason").asText())
                    || !"true".equals(r.getResponse().getHeader(MaskingFunnel.MASKED_HEADER))) {
                    wrong.add(endpoint + " answered " + r.getResponse().getStatus());
                }
            } else if (!path.startsWith("/api/v1/auth/")) {
                writes++;
                MvcResult r = mvc.perform(post(path).contentType("application/json").content("{}").with(csrf())
                    .with(user("synthetic-masked-probe").roles(Roles.REPLAY_VIEWER))).andReturn();
                if (r.getResponse().getStatus() != 403) {
                    wrong.add(endpoint + " answered " + r.getResponse().getStatus());
                }
            }
        }
        assertTrue(reads >= 9 && writes >= 3, "the inventory held " + reads + " reads and " + writes + " writes");
        assertTrue(wrong.isEmpty(), "masked requests not refused fail-closed: " + wrong);
    }
}
