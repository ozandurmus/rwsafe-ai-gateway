package io.rwsafe.control.identity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPURL;
import io.rwsafe.control.identity.DirectoryConfig.TlsMode;
import io.rwsafe.control.identity.LdapAuthenticator.Probe;
import io.rwsafe.control.identity.LdapAuthenticator.TestResult;
import io.rwsafe.control.siem.TestPki;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The directory front against synthetic in-memory directories (plain loopback, LDAPS, StartTLS) with a CA and server
 * certificates generated at runtime: each connection-test class, group -> role matching in the GroupNames form, the
 * masked role alone, and the rule that plain LDAP reaches loopback only. No name here is real.
 */
class LdapAuthenticatorTest {

    private static final String BASE = "dc=example,dc=test";
    private static final String PEOPLE = "ou=synthetic-people," + BASE;
    private static final String GROUPS = "ou=synthetic-groups," + BASE;
    private static final String SERVICE = "cn=synthetic-service," + BASE;
    private static final String BIND = secret();
    private static final String USER_PASSWORD = secret();

    private static TestPki pki;
    private static InMemoryDirectoryServer plain;
    private static InMemoryDirectoryServer ldaps;
    private static InMemoryDirectoryServer ldapsOtherName;
    private static InMemoryDirectoryServer startTls;
    private static InMemoryDirectoryServer plainOnly;

    private static String secret() {
        byte[] b = new byte[12];
        new SecureRandom().nextBytes(b);
        return HexFormat.of().formatHex(b);
    }

    @BeforeAll
    static void start() throws Exception {
        pki = new TestPki("synthetic-directory-ca");
        SSLContext server = pki.loopbackServer();
        SSLContext otherName = pki.otherNameServer();
        InetAddress lo = InetAddress.getLoopbackAddress();
        plain = directory(InMemoryListenerConfig.createLDAPConfig("plain", lo, 0, null));
        ldaps = directory(InMemoryListenerConfig.createLDAPSConfig("ldaps", lo, 0, server.getServerSocketFactory(),
            null));
        ldapsOtherName = directory(InMemoryListenerConfig.createLDAPSConfig("ldaps", lo, 0,
            otherName.getServerSocketFactory(), null));
        startTls = directory(InMemoryListenerConfig.createLDAPConfig("starttls", lo, 0, server.getSocketFactory()));
        plainOnly = plain;
    }

    private static InMemoryDirectoryServer directory(InMemoryListenerConfig listener) throws Exception {
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(BASE);
        config.setListenerConfigs(listener);
        config.setSchema(null);
        InMemoryDirectoryServer s = new InMemoryDirectoryServer(config);
        s.add(new Entry(BASE, new Attribute("objectClass", "domain")));
        s.add(new Entry(PEOPLE, new Attribute("objectClass", "organizationalUnit")));
        s.add(new Entry(GROUPS, new Attribute("objectClass", "organizationalUnit")));
        s.add(new Entry(SERVICE, new Attribute("userPassword", BIND)));
        s.add(new Entry("uid=synthetic-person," + PEOPLE, new Attribute("uid", "synthetic-person"),
            new Attribute("userPassword", USER_PASSWORD),
            new Attribute("memberOf", "cn=Synthetic-İdari," + GROUPS, "cn=synthetic-unbound," + GROUPS)));
        s.add(new Entry("uid=synthetic-masked," + PEOPLE, new Attribute("uid", "synthetic-masked"),
            new Attribute("userPassword", USER_PASSWORD),
            new Attribute("memberOf", "cn=synthetic-idari," + GROUPS, "cn=synthetic-auditors," + GROUPS)));
        // A group found by a group search (member holds the user's DN) rather than by memberOf.
        s.add(new Entry("cn=synthetic-searched," + GROUPS, new Attribute("objectClass", "groupOfNames"),
            new Attribute("member", "uid=synthetic-person," + PEOPLE)));
        s.startListening();
        return s;
    }

    @AfterAll
    static void stop() {
        for (InMemoryDirectoryServer s : List.of(plain, ldaps, ldapsOtherName, startTls)) {
            s.shutDown(true);
        }
    }

    private static DirectoryConfig config(String url, TlsMode mode, List<X509Certificate> ca, String password,
                                          Map<String, Set<String>> roles) throws Exception {
        return new DirectoryConfig(List.of(new LDAPURL(url)), mode, ca, SERVICE, password.toCharArray(), PEOPLE,
            "(uid={0})", "memberOf", null, null, 2_000, 2_000, roles);
    }

    private static Map<String, Set<String>> bindings() {
        // Keyed by the GroupNames comparison form: "Synthetic-İdari", "SYNTHETIC-IDARI" and "synthetic-idari" are one.
        return Map.of(DirectoryConfig.groupKey("SYNTHETIC-IDARI"), Set.of(Roles.SECURITY_ADMIN, Roles.VIEWER),
            DirectoryConfig.groupKey("synthetic-auditors"), Set.of(Roles.REPLAY_VIEWER),
            DirectoryConfig.groupKey("synthetic-searched"), Set.of(Roles.PRIVACY_OFFICER));
    }

    private static Probe probe(DirectoryConfig config, String login) {
        try (LdapAuthenticator ldap = new LdapAuthenticator(config)) {
            return ldap.probe(login);
        }
    }

    private static String plainUrl(InMemoryDirectoryServer s) {
        return "ldap://127.0.0.1:" + s.getListenPort();
    }

    private static String ldapsUrl(InMemoryDirectoryServer s) {
        return "ldaps://127.0.0.1:" + s.getListenPort();
    }

    @Test
    void groupsMapToRolesInTheGroupNamesFormAndTheMaskedRoleStandsAlone() throws Exception {
        try (LdapAuthenticator ldap = new LdapAuthenticator(config(plainUrl(plain), TlsMode.NONE, List.of(), BIND,
            bindings()))) {
            AuthenticatedUser user = ldap.authenticate("synthetic-person", USER_PASSWORD.toCharArray()).orElseThrow();
            assertEquals(Set.of(Roles.SECURITY_ADMIN, Roles.VIEWER), user.roles());
            assertEquals("ldap", user.source());
            assertTrue(ldap.authenticate("synthetic-person", "wrong".toCharArray()).isEmpty());
            assertTrue(ldap.authenticate("synthetic-person", new char[0]).isEmpty(), "never an anonymous bind");
            assertTrue(ldap.authenticate("synthetic-nobody", USER_PASSWORD.toCharArray()).isEmpty());
            // The directory gives the masked role with another: the identity service keeps the masked role alone.
            AuthenticatedUser masked = ldap.authenticate("synthetic-masked", USER_PASSWORD.toCharArray()).orElseThrow();
            assertTrue(masked.roles().contains(Roles.REPLAY_VIEWER));
            assertEquals(Set.of(Roles.REPLAY_VIEWER), IdentityService.exclusive(masked).roles());
            assertEquals(List.of(Roles.REPLAY_VIEWER), ldap.probe("synthetic-masked").roles());
        }
    }

    @Test
    void aGroupSearchAddsTheGroupsThatNameTheUser() throws Exception {
        DirectoryConfig config = new DirectoryConfig(List.of(new LDAPURL(plainUrl(plain))), TlsMode.NONE, List.of(),
            SERVICE, BIND.toCharArray(), PEOPLE, "(uid={0})", "memberOf", GROUPS, "(member={0})", 2_000, 2_000,
            bindings());
        try (LdapAuthenticator ldap = new LdapAuthenticator(config)) {
            assertEquals(Set.of(Roles.SECURITY_ADMIN, Roles.VIEWER, Roles.PRIVACY_OFFICER),
                ldap.authenticate("synthetic-person", USER_PASSWORD.toCharArray()).orElseThrow().roles());
            Probe p = ldap.probe("synthetic-person");
            assertEquals(TestResult.OK, p.result());
            assertEquals(3, p.groupsFound());
            assertEquals(2, p.groupsBound());
        }
    }

    @Test
    void theConnectionTestClassifiesEveryOutcomeWithoutAValue() throws Exception {
        Probe ok = probe(config(plainUrl(plain), TlsMode.NONE, List.of(), BIND, bindings()), null);
        assertEquals(TestResult.OK, ok.result());
        assertEquals(1, ok.server());
        assertNull(ok.groupsFound());

        Probe user = probe(config(plainUrl(plain), TlsMode.NONE, List.of(), BIND, bindings()), "synthetic-person");
        assertEquals(TestResult.OK, user.result());
        assertEquals(2, user.groupsFound());
        assertEquals(1, user.groupsBound());
        assertEquals(List.of(Roles.SECURITY_ADMIN, Roles.VIEWER), user.roles());

        assertEquals(TestResult.USER_NOT_FOUND, probe(config(plainUrl(plain), TlsMode.NONE, List.of(), BIND,
            bindings()), "synthetic-nobody").result());
        Probe refused = probe(config(plainUrl(plain), TlsMode.NONE, List.of(), "not-" + BIND, bindings()), null);
        assertEquals(TestResult.BIND_REFUSED, refused.result());
        assertEquals("INVALID_CREDENTIALS", refused.detail());

        for (String login : new String[] {null, "synthetic-person"}) {
            // A closed front clears its copy of the password, so every probe gets a config of its own.
            DirectoryConfig badBase = new DirectoryConfig(List.of(new LDAPURL(plainUrl(plain))), TlsMode.NONE,
                List.of(), SERVICE, BIND.toCharArray(), "ou=synthetic-missing," + BASE, "(uid={0})", "memberOf", null,
                null, 2_000, 2_000, Map.of());
            assertEquals(TestResult.SEARCH_FAILED, probe(badBase, login).result());
        }

        int closed;
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            closed = s.getLocalPort();
        }
        Probe unreachable = probe(config("ldap://127.0.0.1:" + closed, TlsMode.NONE, List.of(), BIND, bindings()),
            null);
        assertEquals(TestResult.UNREACHABLE, unreachable.result());
        assertEquals(0, unreachable.server());

        // The first URL does not answer, the second does: the test says which one.
        String dead = "ldap://127.0.0.1:" + closed;
        assertEquals(2, probe(failover(dead), null).server());
        try (LdapAuthenticator ldap = new LdapAuthenticator(failover(dead))) {
            assertTrue(ldap.authenticate("synthetic-person", USER_PASSWORD.toCharArray()).isPresent());
        }
    }

    private static DirectoryConfig failover(String dead) throws Exception {
        return new DirectoryConfig(List.of(new LDAPURL(dead), new LDAPURL(plainUrl(plain))), TlsMode.NONE, List.of(),
            SERVICE, BIND.toCharArray(), PEOPLE, "(uid={0})", "memberOf", null, null, 2_000, 2_000, bindings());
    }

    @Test
    void tlsIsVerifiedAgainstTheGivenCaAndTheHostName() throws Exception {
        List<X509Certificate> ca = List.of(pki.ca());
        assertEquals(TestResult.OK, probe(config(ldapsUrl(ldaps), TlsMode.LDAPS, ca, BIND, bindings()), null)
            .result());
        try (LdapAuthenticator ldap = new LdapAuthenticator(config(ldapsUrl(ldaps), TlsMode.LDAPS, ca, BIND,
            bindings()))) {
            assertTrue(ldap.authenticate("synthetic-person", USER_PASSWORD.toCharArray()).isPresent());
        }

        Probe untrusted = probe(config(ldapsUrl(ldaps), TlsMode.LDAPS, List.of(), BIND, bindings()), null);
        assertEquals(TestResult.TLS_FAILED, untrusted.result(), "ldaps without the CA");
        assertEquals("CERTIFICATE_UNTRUSTED", untrusted.detail());

        Probe otherName = probe(config(ldapsUrl(ldapsOtherName), TlsMode.LDAPS, ca, BIND, bindings()), null);
        assertEquals(TestResult.TLS_FAILED, otherName.result(), "ldaps other name");
        assertEquals("HOSTNAME_MISMATCH", otherName.detail());

        Probe startTlsOk = probe(config(plainUrl(startTls), TlsMode.STARTTLS, ca, BIND, bindings()),
            "synthetic-person");
        assertEquals(TestResult.OK, startTlsOk.result());
        try (LdapAuthenticator ldap = new LdapAuthenticator(config(plainUrl(startTls), TlsMode.STARTTLS, ca, BIND,
            bindings()))) {
            assertTrue(ldap.authenticate("synthetic-person", USER_PASSWORD.toCharArray()).isPresent());
        }
        Probe startTlsUntrusted = probe(config(plainUrl(startTls), TlsMode.STARTTLS, List.of(), BIND, bindings()),
            null);
        assertEquals(TestResult.TLS_FAILED, startTlsUntrusted.result(), "starttls without the CA");
        assertEquals("CERTIFICATE_UNTRUSTED", startTlsUntrusted.detail());

        // A server without StartTLS refuses it: never a fall-back to a clear-text bind.
        Probe refused = probe(config(plainUrl(plainOnly), TlsMode.STARTTLS, ca, BIND, bindings()), null);
        assertEquals(TestResult.TLS_FAILED, refused.result(), "starttls refused");
        assertEquals("STARTTLS_REFUSED", refused.detail());
    }

    @Test
    void plainLdapReachesLoopbackOnly() throws Exception {
        Probe p = probe(config("ldap://synthetic-dc.example.test:389", TlsMode.NONE, List.of(), BIND, bindings()),
            null);
        assertEquals(TestResult.TLS_FAILED, p.result());
        assertEquals("PLAIN_LDAP_REFUSED", p.detail());
        try (LdapAuthenticator ldap = new LdapAuthenticator(config("ldap://synthetic-dc.example.test:389",
            TlsMode.NONE, List.of(), BIND, bindings()))) {
            assertTrue(ldap.attempt("synthetic-person", USER_PASSWORD.toCharArray()).error());
        }
    }

    @Test
    void aClosedFrontAnswersAnErrorSoTheCallerCanRetryOnTheNewSettings() throws Exception {
        LdapAuthenticator ldap = new LdapAuthenticator(config(plainUrl(plain), TlsMode.NONE, List.of(), BIND,
            bindings()));
        assertFalse(ldap.attempt("synthetic-person", USER_PASSWORD.toCharArray()).error());
        ldap.close();
        assertTrue(ldap.attempt("synthetic-person", USER_PASSWORD.toCharArray()).error());
    }

    @Test
    void groupKeysTakeTheFirstRdnAndFoldTurkishLetters() {
        assertEquals("synthetic-idari", DirectoryConfig.groupKey("CN=Synthetic-İdari,OU=x,DC=example,DC=test"));
        assertEquals("synthetic-idari", DirectoryConfig.groupKey("SYNTHETIC-IDARI"));
        assertEquals("synthetic-idari", DirectoryConfig.groupKey("synthetic-ıdari"));
        assertNull(DirectoryConfig.groupKey(""));
        assertNull(DirectoryConfig.groupKey(null));
    }
}
