package io.rwsafe.control.identity;

import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPInterface;
import com.unboundid.ldap.sdk.LDAPURL;
import com.unboundid.ldap.sdk.NameResolver;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchRequest;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.ServerSet;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.ldap.sdk.extensions.StartTLSExtendedRequest;
import com.unboundid.util.ssl.SSLSocketVerifier;
import io.rwsafe.control.identity.DirectoryConfig.TlsMode;
import io.rwsafe.control.privacy.Pseudonymiser;
import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * LDAP/AD bind (Q-9) with the settings of one directory settings version (PO decision Q-47, decision 1.2): the service
 * account searches the login name (escaped into the configured filter), then the user's own credentials are bound on a
 * pooled connection and the pool reverts to the service account; the user's groups map to roles through the stored
 * bindings only, matched in one comparison form on both sides ({@link DirectoryConfig#nameKey},
 * {@link DirectoryConfig#valueKey}); with a group search base set, a {@code memberOf} group outside it counts for nothing
 * (PR 50 review D-04, Q-3), and the masked role, when a group gives it, is the only role.
 * One small pool, never a burst of connections (AGENTS.md section 14); the URLs are tried in order. An empty password is
 * refused before any bind, because a simple bind with an empty password is an anonymous bind that many directories
 * accept. Credentials never cross the network in clear text: TLS (LDAPS or StartTLS) with host-name verification, plain
 * LDAP only to a loopback test directory (D-08). Nothing here logs a distinguished name, a group or a login name.
 */
public final class LdapAuthenticator implements Authenticator, AutoCloseable {

    private static final Logger LOG = LoggerFactory.getLogger(LdapAuthenticator.class);
    private static final int GROUP_SEARCH_LIMIT = 1000;

    /** The classified outcome of a connection test (no value of the directory is ever part of it). */
    public enum TestResult { OK, UNREACHABLE, TLS_FAILED, BIND_REFUSED, SEARCH_FAILED, USER_NOT_FOUND }

    /**
     * A connection test's answer.
     *
     * @param detail       a fixed reason class ({@code CERTIFICATE_UNTRUSTED}, {@code TIMEOUT}, a result-code name ...)
     *                     or null
     * @param server       which URL answered, from 1; 0 when none did
     * @param groupsFound  the tested user's directory groups, counted; null without a user
     * @param groupsBound  how many of them a binding names; null without a user
     * @param roles        the roles the bindings give the tested user (the masked role alone when it is among them)
     */
    public record Probe(TestResult result, String detail, int server, Integer groupsFound, Integer groupsBound,
                        List<String> roles) {

        public Probe {
            roles = roles == null ? List.of() : List.copyOf(roles);
        }

        static Probe of(TestResult result, String detail, int server) {
            return new Probe(result, detail, server, null, null, List.of());
        }
    }

    /** One sign-in: a user, a refusal (unknown name or wrong password), or a directory error. */
    record Attempt(AuthenticatedUser user, boolean error) {

        static final Attempt REFUSED = new Attempt(null, false);
        static final Attempt ERROR = new Attempt(null, true);
    }

    /** The host-name check failed: the TLS session itself was established. */
    static final class HostNameMismatch extends LDAPException {

        private static final long serialVersionUID = 1L;

        HostNameMismatch() {
            super(ResultCode.CONNECT_ERROR, "the directory certificate does not name the host");
        }
    }

    /** The server answered the StartTLS request with a refusal. */
    static final class StartTlsRefused extends LDAPException {

        private static final long serialVersionUID = 1L;

        StartTlsRefused(ResultCode code) {
            super(code, "the directory refused StartTLS");
        }
    }

    private final DirectoryConfig config;
    private final SSLContext tls;
    private LDAPConnectionPool pool;
    /** The pool's service bind credential, kept for reconnects and wiped on close. */
    private byte[] poolCredential;
    private boolean closed;

    /** @throws IllegalArgumentException when the TLS context cannot be built from the CA certificates */
    public LdapAuthenticator(DirectoryConfig config) {
        this.config = config;
        if (config.tlsMode() != TlsMode.NONE) {
            try {
                this.tls = context(config);
            } catch (GeneralSecurityException | IOException e) {
                throw new IllegalArgumentException("the directory TLS context cannot be built", e);
            }
        } else {
            this.tls = null;
        }
    }

    @Override
    public Optional<AuthenticatedUser> authenticate(String loginName, char[] password) {
        return Optional.ofNullable(attempt(loginName, password).user());
    }

    Attempt attempt(String loginName, char[] password) {
        if (password.length == 0) {
            return Attempt.REFUSED;
        }
        try {
            LDAPConnectionPool p = pool();
            SearchResult found = p.search(userSearch(loginName));
            if (found.getEntryCount() != 1) {
                return Attempt.REFUSED;
            }
            SearchResultEntry entry = found.getSearchEntries().get(0);
            byte[] credential = utf8(password);
            BindResult bind;
            try {
                bind = p.bindAndRevertAuthentication(new SimpleBindRequest(entry.getDN(), credential));
            } finally {
                Arrays.fill(credential, (byte) 0);
            }
            if (bind.getResultCode() != ResultCode.SUCCESS) {
                return Attempt.REFUSED;
            }
            Set<String> roles = roles(groups(p, entry, loginName));
            return new Attempt(new AuthenticatedUser(loginName, roles, "ldap"), false);
        } catch (LDAPException e) {
            // A wrong password, or more than one entry for the name (the search asks for two at most): refused.
            if (e.getResultCode() == ResultCode.INVALID_CREDENTIALS || e.getResultCode() == ResultCode.SIZE_LIMIT_EXCEEDED) {
                return Attempt.REFUSED;
            }
            LOG.warn("directory sign-in failed with result {}", e.getResultCode().getName());
            return Attempt.ERROR;
        }
    }

    /**
     * Connects to the first URL that answers, binds with the service account and, with {@code loginName}, finds that one
     * user and counts its groups; nothing is changed in the directory. A fresh connection, never the pool's.
     */
    public Probe probe(String loginName) {
        LDAPConnection connection = null;
        Probe failure = Probe.of(TestResult.UNREACHABLE, "NO_URL", 0);
        int server = 0;
        for (int i = 0; i < config.urls().size() && connection == null; i++) {
            try {
                connection = connect(config.urls().get(i));
                server = i + 1;
            } catch (LDAPException e) {
                Probe p = connectFailure(e);
                // A TLS failure says more than an unreachable server further down the list.
                if (failure.result() != TestResult.TLS_FAILED) {
                    failure = p;
                }
            }
        }
        if (connection == null) {
            return failure;
        }
        try (LDAPConnection c = connection) {
            char[] password = config.bindPassword();
            byte[] credential = utf8(password);
            Arrays.fill(password, '\0');
            try {
                c.bind(new SimpleBindRequest(config.bindDn(), credential));
            } catch (LDAPException e) {
                return disconnected(e) ? Probe.of(TestResult.UNREACHABLE, code(e), server)
                    : Probe.of(TestResult.BIND_REFUSED, code(e), server);
            } finally {
                Arrays.fill(credential, (byte) 0);
            }
            if (loginName == null) {
                try {
                    return c.getEntry(config.userSearchBase(), SearchRequest.NO_ATTRIBUTES) == null
                        ? Probe.of(TestResult.SEARCH_FAILED, "BASE_NOT_FOUND", server)
                        : Probe.of(TestResult.OK, null, server);
                } catch (LDAPException e) {
                    return Probe.of(TestResult.SEARCH_FAILED, code(e), server);
                }
            }
            SearchResult found;
            try {
                found = c.search(userSearch(loginName));
            } catch (LDAPException e) {
                return e.getResultCode() == ResultCode.SIZE_LIMIT_EXCEEDED
                    ? Probe.of(TestResult.USER_NOT_FOUND, "AMBIGUOUS", server)
                    : Probe.of(TestResult.SEARCH_FAILED, code(e), server);
            }
            if (found.getEntryCount() != 1) {
                return Probe.of(TestResult.USER_NOT_FOUND, found.getEntryCount() == 0 ? null : "AMBIGUOUS", server);
            }
            List<String> groups;
            try {
                groups = groups(c, found.getSearchEntries().get(0), loginName);
            } catch (LDAPException e) {
                return Probe.of(TestResult.SEARCH_FAILED, "GROUP_SEARCH_" + code(e), server);
            }
            int bound = 0;
            for (String g : groups) {
                String key = DirectoryConfig.valueKey(g);
                if (key != null && config.groupRoles().containsKey(key)) {
                    bound++;
                }
            }
            Set<String> roles = roles(groups);
            List<String> ordered = Roles.ORDERED.stream().filter(roles::contains).toList();
            return new Probe(TestResult.OK, null, server, groups.size(), bound, ordered);
        }
    }

    /** The user search: at most two entries, so an ambiguous name is refused without reading the directory (D-05). */
    private SearchRequest userSearch(String loginName) throws LDAPException {
        SearchRequest request = new SearchRequest(config.userSearchBase(), SearchScope.SUB,
            Filter.create(config.userSearchFilter().replace("{0}", Filter.encodeValue(loginName))), attributes());
        request.setSizeLimit(2);
        return request;
    }

    private String[] attributes() {
        return config.groupAttribute() == null ? new String[] {SearchRequest.NO_ATTRIBUTES}
            : new String[] {config.groupAttribute()};
    }

    /**
     * The user's group values: the group attribute's values, then the group search's entries, each once. With a group
     * search base set, a group attribute value counts only when it is a distinguished name below that base (PR 50
     * review Q-3): a group of the same name elsewhere in the directory grants nothing.
     */
    private List<String> groups(LDAPInterface ldap, SearchResultEntry entry, String loginName) throws LDAPException {
        Set<String> out = new LinkedHashSet<>();
        DN base = config.groupSearchBase() == null ? null : new DN(config.groupSearchBase());
        if (config.groupAttribute() != null) {
            String[] values = entry.getAttributeValues(config.groupAttribute());
            if (values != null) {
                for (String v : values) {
                    if (base == null || below(v, base)) {
                        out.add(v);
                    }
                }
            }
        }
        if (config.groupSearchBase() != null && config.groupSearchFilter() != null) {
            Filter filter = Filter.create(config.groupSearchFilter()
                .replace("{0}", Filter.encodeValue(entry.getDN()))
                .replace("{1}", Filter.encodeValue(loginName)));
            SearchRequest request = new SearchRequest(config.groupSearchBase(), SearchScope.SUB, filter,
                SearchRequest.NO_ATTRIBUTES);
            request.setSizeLimit(GROUP_SEARCH_LIMIT);
            for (SearchResultEntry g : ldap.search(request).getSearchEntries()) {
                if (below(g.getDN(), base)) {
                    out.add(g.getDN());
                }
            }
        }
        return new ArrayList<>(out);
    }

    private static boolean below(String value, DN base) {
        try {
            return new DN(value).isDescendantOf(base, false);
        } catch (LDAPException notADn) {
            return false;
        }
    }

    /** The bound roles of {@code groups}; the masked role, when one of them gives it, alone (D-04). */
    private Set<String> roles(List<String> groups) {
        Set<String> roles = new TreeSet<>();
        for (String group : groups) {
            String key = DirectoryConfig.valueKey(group);
            Set<String> bound = key == null ? null : config.groupRoles().get(key);
            if (bound != null) {
                roles.addAll(bound);
            }
        }
        return roles.contains(Roles.REPLAY_VIEWER) ? Set.of(Roles.REPLAY_VIEWER) : roles;
    }

    private synchronized LDAPConnectionPool pool() throws LDAPException {
        if (closed) {
            throw new LDAPException(ResultCode.CONNECT_ERROR, "the directory settings were replaced");
        }
        if (pool != null) {
            return pool;
        }
        char[] password = config.bindPassword();
        poolCredential = utf8(password);
        Arrays.fill(password, '\0');
        try {
            pool = new LDAPConnectionPool(new Servers(), new SimpleBindRequest(config.bindDn(), poolCredential), 1, 2);
        } catch (LDAPException e) {
            Arrays.fill(poolCredential, (byte) 0);
            poolCredential = null;
            throw e;
        }
        pool.setRetryFailedOperationsDueToInvalidConnections(true);
        return pool;
    }

    /** The configured URLs in order: the first that connects (and, for StartTLS, secures) wins. */
    private final class Servers extends ServerSet {

        @Override
        public LDAPConnection getConnection() throws LDAPException {
            LDAPException last = new LDAPException(ResultCode.CONNECT_ERROR, "no directory URL");
            for (LDAPURL url : config.urls()) {
                try {
                    return connect(url);
                } catch (LDAPException e) {
                    last = e;
                }
            }
            throw last;
        }

        @Override
        public void toString(StringBuilder buffer) {
            buffer.append("DirectoryServers(").append(config.urls().size()).append(')');
        }
    }

    LDAPConnection connect(LDAPURL url) throws LDAPException {
        boolean ldaps = "ldaps".equals(url.getScheme());
        // Re-checked here as well as on save: never a clear-text bind, and plain LDAP only to a loopback test directory
        // under the test-only switch (PR 50 review Q-1).
        if (config.tlsMode() == TlsMode.NONE && !(config.localTargets() && loopback(url.getHost()))) {
            throw new LDAPException(ResultCode.CONFIDENTIALITY_REQUIRED, "plain LDAP is for a loopback test directory");
        }
        if (ldaps != (config.tlsMode() == TlsMode.LDAPS)) {
            throw new LDAPException(ResultCode.PARAM_ERROR, "the URL scheme does not match the TLS mode");
        }
        InetAddress[] addresses = targets(url.getHost(), url.getPort(), config.localTargets());
        LDAPConnectionOptions options = new LDAPConnectionOptions();
        options.setConnectTimeoutMillis(config.connectTimeoutMs());
        options.setResponseTimeoutMillis(config.responseTimeoutMs());
        options.setSSLSocketVerifier(new Verifier());
        // The name is resolved once, above, and the connection goes to those addresses only; the name itself stays the
        // one the certificate is checked against (D-03).
        options.setNameResolver(new Pinned(url.getHost(), addresses));
        LDAPConnection connection = ldaps
            ? new LDAPConnection(tls.getSocketFactory(), options, url.getHost(), url.getPort())
            : new LDAPConnection(options, url.getHost(), url.getPort());
        if (config.tlsMode() == TlsMode.STARTTLS) {
            try {
                ExtendedResult r = connection.processExtendedOperation(new StartTLSExtendedRequest(tls));
                if (r.getResultCode() != ResultCode.SUCCESS) {
                    throw new StartTlsRefused(r.getResultCode());
                }
            } catch (LDAPException e) {
                connection.close();
                // A TLS failure (a certificate, the host name, the handshake) is told as such; any other answer to the
                // request is the server refusing StartTLS. Never a fall-back to a clear-text bind.
                if (e instanceof StartTlsRefused || has(e, HostNameMismatch.class) || has(e, IOException.class)) {
                    throw e;
                }
                throw new StartTlsRefused(e.getResultCode());
            }
        }
        return connection;
    }

    /** A target the policy refuses: loopback, link-local, unspecified or multicast, or a port that is not a directory's. */
    static final class TargetRefused extends LDAPException {

        private static final long serialVersionUID = 1L;

        TargetRefused() {
            super(ResultCode.CONNECT_ERROR, "the directory target is not allowed");
        }
    }

    /**
     * Resolves {@code host} once and applies the target policy (PR 50 review D-03): every address must be routable (not
     * loopback, link-local, unspecified or multicast) and the port one of {@link DirectoryConfig#DIRECTORY_PORTS}; under
     * the test-only switch a loopback address is allowed on any port. One refused address refuses the name.
     */
    static InetAddress[] targets(String host, int port, boolean localTargets) throws LDAPException {
        InetAddress[] addresses;
        try {
            addresses = InetAddress.getAllByName(host);
        } catch (UnknownHostException e) {
            throw new LDAPException(ResultCode.CONNECT_ERROR, "the directory name is not known", e);
        }
        boolean allLoopback = addresses.length > 0;
        for (InetAddress a : addresses) {
            boolean loopback = a.isLoopbackAddress();
            allLoopback &= loopback;
            if ((loopback && !localTargets) || a.isLinkLocalAddress() || a.isAnyLocalAddress() || a.isMulticastAddress()) {
                throw new TargetRefused();
            }
        }
        if (!(localTargets && allLoopback) && !DirectoryConfig.DIRECTORY_PORTS.contains(port)) {
            throw new TargetRefused();
        }
        return addresses;
    }

    /** Answers only the one name resolved before the connection, with the addresses resolved then. */
    private static final class Pinned extends NameResolver {

        private final String host;
        private final InetAddress[] addresses;

        Pinned(String host, InetAddress[] addresses) {
            this.host = host;
            this.addresses = addresses.clone();
        }

        @Override
        public InetAddress getByName(String name) throws UnknownHostException {
            return getAllByName(name)[0];
        }

        @Override
        public InetAddress[] getAllByName(String name) throws UnknownHostException {
            if (name == null || !name.equalsIgnoreCase(host)) {
                throw new UnknownHostException("not the resolved directory name");
            }
            return addresses.clone();
        }

        @Override
        public void toString(StringBuilder buffer) {
            buffer.append("PinnedDirectoryName");
        }
    }

    /**
     * Completes the handshake first (so a certificate failure is told apart from a host-name mismatch), then requires
     * the leaf certificate's subject alternative names to name the host the URL names: an IP address against an
     * {@code iPAddress} entry, a host name against a {@code dNSName} entry (one leftmost {@code *} label allowed below at
     * least two further labels). The subject's common name is never used. The library's own host-name verifier is not
     * used because it accepted a loopback address that no name of the certificate held.
     */
    private static final class Verifier extends SSLSocketVerifier {

        @Override
        public void verifySSLSocket(String host, int port, SSLSocket socket) throws LDAPException {
            X509Certificate leaf;
            try {
                socket.startHandshake();
                java.security.cert.Certificate[] chain = socket.getSession().getPeerCertificates();
                if (chain.length == 0 || !(chain[0] instanceof X509Certificate x)) {
                    throw new HostNameMismatch();
                }
                leaf = x;
            } catch (IOException e) {
                throw new LDAPException(ResultCode.CONNECT_ERROR, "the TLS handshake failed", e);
            }
            if (!names(host, leaf)) {
                throw new HostNameMismatch();
            }
        }
    }

    /** True when {@code cert}'s subject alternative names hold {@code host} (see {@link Verifier}). */
    static boolean names(String host, X509Certificate cert) {
        if (host == null || host.isEmpty()) {
            return false;
        }
        String h = host.startsWith("[") && host.endsWith("]") ? host.substring(1, host.length() - 1) : host;
        boolean ip = Pseudonymiser.ipv4(h) != null || h.indexOf(':') >= 0;
        java.util.Collection<List<?>> sans;
        try {
            sans = cert.getSubjectAlternativeNames();
        } catch (java.security.cert.CertificateParsingException e) {
            return false;
        }
        if (sans == null) {
            return false;
        }
        for (List<?> san : sans) {
            if (san.size() < 2 || !(san.get(0) instanceof Integer type) || !(san.get(1) instanceof String value)) {
                continue;
            }
            if (ip && type == 7 && sameAddress(value, h) || !ip && type == 2 && dnsName(value, h)) {
                return true;
            }
        }
        return false;
    }

    private static boolean sameAddress(String a, String b) {
        if (a.equals(b)) {
            return true;
        }
        if (a.indexOf(':') < 0 || b.indexOf(':') < 0) {
            return false;
        }
        try {
            // Literals only (both contain ':'), so nothing is resolved.
            return java.net.InetAddress.getByName(a).equals(java.net.InetAddress.getByName(b));
        } catch (java.net.UnknownHostException e) {
            return false;
        }
    }

    private static boolean dnsName(String pattern, String host) {
        String p = pattern.toLowerCase(java.util.Locale.ROOT);
        String h = host.toLowerCase(java.util.Locale.ROOT);
        if (p.endsWith(".")) {
            p = p.substring(0, p.length() - 1);
        }
        if (h.endsWith(".")) {
            h = h.substring(0, h.length() - 1);
        }
        if (!p.startsWith("*.")) {
            return p.equals(h);
        }
        String suffix = p.substring(1);
        int firstDot = h.indexOf('.');
        return suffix.chars().filter(c -> c == '.').count() >= 2 && firstDot > 0 && h.substring(firstDot).equals(suffix)
            && !suffix.contains("*");
    }

    /** The class of a failed connect: TLS with its reason, or unreachable with its reason. Never the message. */
    static Probe connectFailure(LDAPException e) {
        if (has(e, TargetRefused.class)) {
            return Probe.of(TestResult.UNREACHABLE, "TARGET_NOT_ALLOWED", 0);
        }
        if (has(e, HostNameMismatch.class)) {
            return Probe.of(TestResult.TLS_FAILED, "HOSTNAME_MISMATCH", 0);
        }
        if (has(e, StartTlsRefused.class)) {
            return Probe.of(TestResult.TLS_FAILED, "STARTTLS_REFUSED", 0);
        }
        if (has(e, CertificateExpiredException.class) || has(e, CertificateNotYetValidException.class)) {
            return Probe.of(TestResult.TLS_FAILED, "CERTIFICATE_EXPIRED", 0);
        }
        if (has(e, CertPathValidatorException.class) || has(e, CertPathBuilderException.class)
            || has(e, CertificateException.class)) {
            return Probe.of(TestResult.TLS_FAILED, "CERTIFICATE_UNTRUSTED", 0);
        }
        if (has(e, SSLException.class)) {
            return Probe.of(TestResult.TLS_FAILED, "HANDSHAKE_FAILED", 0);
        }
        if (e.getResultCode() == ResultCode.CONFIDENTIALITY_REQUIRED) {
            return Probe.of(TestResult.TLS_FAILED, "PLAIN_LDAP_REFUSED", 0);
        }
        if (has(e, UnknownHostException.class)) {
            return Probe.of(TestResult.UNREACHABLE, "NAME_NOT_RESOLVED", 0);
        }
        if (has(e, SocketTimeoutException.class) || e.getResultCode() == ResultCode.TIMEOUT
            || e.getResultCode() == ResultCode.CONNECT_ERROR && String.valueOf(e.getMessage()).contains("timed out")) {
            return Probe.of(TestResult.UNREACHABLE, "TIMEOUT", 0);
        }
        return Probe.of(TestResult.UNREACHABLE, "CONNECTION_FAILED", 0);
    }

    private static boolean has(Throwable t, Class<? extends Throwable> type) {
        for (Throwable c = t; c != null; c = c.getCause() == c ? null : c.getCause()) {
            if (type.isInstance(c)) {
                return true;
            }
        }
        return false;
    }

    private static boolean disconnected(LDAPException e) {
        ResultCode c = e.getResultCode();
        return c == ResultCode.SERVER_DOWN || c == ResultCode.CONNECT_ERROR || c == ResultCode.TIMEOUT;
    }

    /** A result code as a fixed token ({@code INVALID_CREDENTIALS}); never the server's diagnostic message. */
    static String code(LDAPException e) {
        return e.getResultCode().getName().toUpperCase(java.util.Locale.ROOT).replaceAll("[^A-Z0-9]+", "_");
    }

    private static SSLContext context(DirectoryConfig config) throws GeneralSecurityException, IOException {
        SSLContext context = SSLContext.getInstance("TLS");
        if (config.caCertificates().isEmpty()) {
            context.init(null, null, null);
            return context;
        }
        KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
        trust.load(null, null);
        int i = 0;
        for (var c : config.caCertificates()) {
            trust.setCertificateEntry("directory-ca-" + i++, c);
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        tmf.init(trust);
        context.init(null, tmf.getTrustManagers(), null);
        return context;
    }

    private static byte[] utf8(char[] chars) {
        var b = StandardCharsets.UTF_8.encode(CharBuffer.wrap(chars));
        byte[] out = new byte[b.remaining()];
        b.get(out);
        return out;
    }

    /** A literal loopback address (127.0.0.0/8 dotted quad, ::1) or {@code localhost}; no name is resolved (N-03). */
    static boolean loopback(String host) {
        if (host == null) {
            return false;
        }
        int[] v4 = Pseudonymiser.ipv4(host);
        return (v4 != null && v4[0] == 127) || "localhost".equalsIgnoreCase(host) || "::1".equals(host)
            || "[::1]".equals(host);
    }

    @Override
    public synchronized void close() {
        closed = true;
        if (pool != null) {
            pool.close();
            pool = null;
        }
        if (poolCredential != null) {
            Arrays.fill(poolCredential, (byte) 0);
            poolCredential = null;
        }
        config.clear();
    }
}
