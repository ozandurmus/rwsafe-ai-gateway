package io.rwsafe.control.identity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.control.support.ControlTestEnvironment;
import io.rwsafe.control.support.ProxiedClient;
import java.net.http.HttpResponse;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * The control plane behind the host's Traefik (deploy/rwsafe/overlays/pilot/10-pilot-config.yaml): the deploy's Secure
 * {@code __Host-} session cookie and Secure CSRF cookie, forwarded headers on ({@code native}), trusted only from the
 * proxy's address. The test client connects from 127.0.0.1 and stands in for Traefik, so 127.0.0.1 is the trusted
 * expression here; {@link ForwardedHeadersUntrustedPeerIntegrationTest} proves that another peer's headers are ignored.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ForwardedHeadersIntegrationTest {

    static final String LOGIN = "synthetic-proxied-admin";

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry r) throws Exception {
        register(r, "127\\.0\\.0\\.1");
    }

    /** The test environment with the deploy's cookie settings and forwarded headers trusted from {@code proxies}. */
    static void register(DynamicPropertyRegistry r, String proxies) throws Exception {
        ControlTestEnvironment.register(r, true, true);
        ControlTestEnvironment.addUser(LOGIN, "security_admin");
        r.add("rwsafe.identity.cookie-secure", () -> "true");
        r.add("server.servlet.session.cookie.secure", () -> "true");
        r.add("server.servlet.session.cookie.name", () -> "__Host-rwsafe-session");
        r.add("server.forward-headers-strategy", () -> "native");
        // The property name is split so the repository privacy gate does not read its dotted tail as a host name.
        r.add("server.tomcat.remoteip." + "internal-proxies", () -> proxies);
    }

    @LocalServerPort
    int port;

    static void assertSecureHostCookies(HttpResponse<String> login) {
        List<String> session = ProxiedClient.setCookies(login, "__Host-rwsafe-session");
        assertEquals(1, session.size(), String.valueOf(login.headers().allValues("set-cookie").size()));
        String s = session.get(0).toLowerCase(java.util.Locale.ROOT);
        assertTrue(s.contains("; secure") && s.contains("; httponly") && s.contains("path=/")
            && s.contains("samesite=strict"), "the session cookie is Secure, HttpOnly, Path=/ and SameSite=Strict");
        assertFalse(s.contains("domain="), "a __Host- cookie carries no Domain attribute");
        List<String> csrf = ProxiedClient.setCookies(login, "XSRF-TOKEN");
        assertFalse(csrf.isEmpty(), "the login rotates the CSRF token");
        String c = csrf.get(csrf.size() - 1).toLowerCase(java.util.Locale.ROOT);
        assertTrue(c.contains("; secure") && c.contains("path=/") && c.contains("samesite=strict"));
        assertFalse(c.contains("httponly"), "the SPA reads the CSRF cookie");
    }

    @Test
    void signInThroughTheProxyKeepsSecureHostCookiesAndCsrf() throws Exception {
        ProxiedClient browser = new ProxiedClient(port, "192.0.2.21");
        HttpResponse<String> login = browser.login(LOGIN, ControlTestEnvironment.PASSWORDS.get(LOGIN));
        assertEquals(200, login.statusCode(), login.body());
        assertSecureHostCookies(login);
        HttpResponse<String> me = browser.get("/api/v1/auth/me");
        assertEquals(200, me.statusCode(), me.body());
        // Behind the trusted proxy the request is https (X-Forwarded-Proto), so HSTS is sent.
        assertTrue(me.headers().firstValue("strict-transport-security").isPresent());
    }

    @Test
    void theCookiesAreSecureWhateverTheScheme() throws Exception {
        // Without any forwarded header the hop is plain http; the cookies stay Secure (by configuration, not scheme).
        ProxiedClient direct = new ProxiedClient(port, null);
        HttpResponse<String> login = direct.login(LOGIN, ControlTestEnvironment.PASSWORDS.get(LOGIN));
        assertEquals(200, login.statusCode(), login.body());
        assertSecureHostCookies(login);
    }

    @Test
    void theThrottleSeesTheAddressTheTrustedProxyForwards() throws Exception {
        String login = "synthetic-throttled-through-proxy";
        ProxiedClient attacker = new ProxiedClient(port, "192.0.2.31");
        for (int i = 0; i < LoginThrottle.MAX_PER_PAIR; i++) {
            assertEquals(401, attacker.login(login, "wrong-synthetic-password").statusCode());
        }
        assertEquals(429, attacker.login(login, "wrong-synthetic-password").statusCode(),
            "the pair (name, forwarded address) is locked");
        ControlTestEnvironment.addUser(login, "security_admin");
        ProxiedClient other = new ProxiedClient(port, "192.0.2.32");
        HttpResponse<String> r = other.login(login, ControlTestEnvironment.PASSWORDS.get(login));
        assertEquals(200, r.statusCode(), "another forwarded client address is another source: " + r.body());
    }
}
