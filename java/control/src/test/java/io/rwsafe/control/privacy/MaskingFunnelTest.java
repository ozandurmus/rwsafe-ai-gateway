package io.rwsafe.control.privacy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.control.api.ApiError;
import io.rwsafe.control.api.Views;
import io.rwsafe.control.identity.Roles;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

/** The funnel for an existing masked session: 503 without the dictionary, nothing to refuse for an empty body. */
class MaskingFunnelTest {

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    private static Object write(MaskingFunnel funnel, Object body, MockHttpServletResponse servlet)
        throws java.io.IOException {
        SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated(
            "synthetic-aiview", null, List.of(new SimpleGrantedAuthority(Roles.authority(Roles.REPLAY_VIEWER)))));
        ServletServerHttpResponse response = new ServletServerHttpResponse(servlet);
        Object out = funnel.beforeBodyWrite(body, null, null, null,
            new ServletServerHttpRequest(new MockHttpServletRequest()), response);
        response.flush();
        return out;
    }

    @Test
    void withoutTheDictionaryAMaskedPageIs503AndAnEmptyBodyPasses() throws Exception {
        PrivacyKeys noDictionary = new PrivacyKeys(new byte[32], null);
        MaskingFunnel funnel = new MaskingFunnel(new Masking(noDictionary, new Pseudonymiser(noDictionary)));
        MockHttpServletResponse page = new MockHttpServletResponse();
        Object out = write(funnel, ApiError.of("X", "y"), page);
        assertEquals(503, page.getStatus());
        assertEquals("MASKING_UNAVAILABLE", assertInstanceOf(ApiError.class, out).reason());
        MockHttpServletResponse empty = new MockHttpServletResponse();
        assertNull(write(funnel, null, empty));
        assertEquals(200, empty.getStatus());
    }

    @Test
    void withoutTheNameDictionaryAMaskedPageIs503() throws Exception {
        PrivacyKeys keys = PseudonymiserTest.keys(1);
        MaskingFunnel funnel = new MaskingFunnel(new Masking(keys, new Pseudonymiser(keys), null));
        MockHttpServletResponse page = new MockHttpServletResponse();
        Object out = write(funnel, ApiError.of("X", "y"), page);
        assertEquals(503, page.getStatus());
        assertEquals("MASKING_UNAVAILABLE", assertInstanceOf(ApiError.class, out).reason());
    }

    /** Every masked page names the rule set; free-text fields pass the name and heuristic layers. */
    @Test
    void aMaskedPageCarriesTheRuleSetAndItsFreeTextIsMasked() throws Exception {
        PrivacyKeys keys = PseudonymiserTest.keys(1);
        MaskingFunnel funnel = new MaskingFunnel(new Masking(keys, new Pseudonymiser(keys)));
        MockHttpServletResponse page = new MockHttpServletResponse();
        Object out = write(funnel, ApiError.of("X", "Zeynep asked about node7.example.com"), page);
        assertEquals(200, page.getStatus());
        assertEquals("rwmask-v1", page.getHeader(MaskingFunnel.RULES_HEADER));
        String message = assertInstanceOf(ApiError.class, out).message();
        assertTrue(message.matches("NAME-[A-Z]{8} asked about HST-[0-9a-f]{4}"), message);

        Views.HealthView health = new Views.HealthView(java.time.Instant.EPOCH, List.of(
            new Views.ComponentView("database", "DOWN", "Mehmet Kaya restarted it")), 0, 0, null);
        MockHttpServletResponse healthPage = new MockHttpServletResponse();
        Views.HealthView masked = assertInstanceOf(Views.HealthView.class, write(funnel, health, healthPage));
        assertTrue(masked.components().get(0).detail().matches("NAME-[A-Z]{8} restarted it"));
    }

    @Test
    void aBodyWithoutAMaskedProjectionIsRefused() throws Exception {
        PrivacyKeys keys = PseudonymiserTest.keys(1);
        MaskingFunnel funnel = new MaskingFunnel(new Masking(keys, new Pseudonymiser(keys)));
        MockHttpServletResponse page = new MockHttpServletResponse();
        Object out = write(funnel, java.util.Map.of("raw", "value"), page);
        assertEquals(500, page.getStatus());
        assertEquals("MASKING_NOT_PROVEN", assertInstanceOf(ApiError.class, out).reason());
        assertEquals("true", page.getHeader(MaskingFunnel.MASKED_HEADER));
    }
}
