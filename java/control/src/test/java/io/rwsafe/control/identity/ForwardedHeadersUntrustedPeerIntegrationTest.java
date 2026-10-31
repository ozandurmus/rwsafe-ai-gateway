package io.rwsafe.control.identity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.control.support.ControlTestEnvironment;
import io.rwsafe.control.support.ProxiedClient;
import java.net.http.HttpResponse;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Forwarded headers from a peer outside the trusted expression are ignored: the pilot's expression names the pod
 * network (10-pilot-config.yaml), so a port-forward from 127.0.0.1 (this test's client) cannot choose its address or
 * scheme. Sign-in still works, because the cookies are Secure by configuration.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ForwardedHeadersUntrustedPeerIntegrationTest {

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) throws Exception {
        // The shape of the pilot's expression; the documentation range stands in for the pod network (it never
        // matches the loopback peer).
        ForwardedHeadersIntegrationTest.register(r, "192\\.0\\.2\\.\\d{1,3}");
    }

    @LocalServerPort
    int port;

    @Test
    void anUntrustedPeerCannotChooseItsAddress() throws Exception {
        String login = "synthetic-throttled-untrusted";
        for (int i = 0; i < LoginThrottle.MAX_PER_PAIR; i++) {
            ProxiedClient spoofing = new ProxiedClient(port, "192.0.2." + (40 + i));
            assertEquals(401, spoofing.login(login, "wrong-synthetic-password").statusCode());
        }
        ControlTestEnvironment.addUser(login, "security_admin");
        ProxiedClient other = new ProxiedClient(port, "192.0.2.99");
        assertEquals(429, other.login(login, ControlTestEnvironment.PASSWORDS.get(login)).statusCode(),
            "every attempt came from the one TCP peer, whatever X-Forwarded-For said");
    }

    @Test
    void signInWorksAndTheSchemeIsNotTakenFromTheHeader() throws Exception {
        String login = ForwardedHeadersIntegrationTest.LOGIN;
        ProxiedClient browser = new ProxiedClient(port, "192.0.2.50");
        HttpResponse<String> r = browser.login(login, ControlTestEnvironment.PASSWORDS.get(login));
        assertEquals(200, r.statusCode(), r.body());
        ForwardedHeadersIntegrationTest.assertSecureHostCookies(r);
        HttpResponse<String> me = browser.get("/api/v1/auth/me");
        assertEquals(200, me.statusCode(), me.body());
        assertTrue(me.headers().firstValue("strict-transport-security").isEmpty(),
            "X-Forwarded-Proto from an untrusted peer does not make the request https");
    }
}
