package io.rwsafe.control.identity;

import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPURL;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldap.sdk.SimpleBindRequest;
import com.unboundid.util.ssl.HostNameSSLSocketVerifier;
import com.unboundid.util.ssl.SSLUtil;
import io.rwsafe.control.config.ControlProperties;
import io.rwsafe.control.privacy.Pseudonymiser;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * LDAP/AD bind (Q-9): the service account searches the login name (escaped into the configured filter), then the user's
 * own credentials are bound on a pooled connection and the pool reverts to the service account; the user's groups map to
 * roles. One small pool, never a burst of connections (AGENTS.md section 14). An empty password is refused before any
 * bind, because a simple bind with an empty password is an anonymous bind that many directories accept.
 */
public final class LdapAuthenticator implements Authenticator, AutoCloseable {

    private static final Logger LOG = LoggerFactory.getLogger(LdapAuthenticator.class);

    private final ControlProperties.Ldap config;
    private final Map<String, String> groupRoles;
    private final String groupAttribute;
    private LDAPConnectionPool pool;

    public LdapAuthenticator(ControlProperties.Ldap config) {
        this.config = config;
        this.groupAttribute = config.groupAttribute() == null ? "memberOf" : config.groupAttribute();
        Map<String, String> roles = config.groupRoles() == null ? Map.of() : config.groupRoles();
        this.groupRoles = roles.entrySet().stream().collect(Collectors.toUnmodifiableMap(
            e -> e.getKey().toLowerCase(Locale.ROOT), Map.Entry::getValue));
        for (String role : groupRoles.values()) {
            if (!Roles.ALL.contains(role)) {
                throw new IllegalArgumentException("unknown role in rwsafe.identity.ldap.group-roles: " + role);
            }
        }
    }

    @Override
    public Optional<AuthenticatedUser> authenticate(String loginName, char[] password) {
        if (password.length == 0) {
            return Optional.empty();
        }
        try {
            LDAPConnectionPool p = pool();
            String filter = config.userSearchFilter().replace("{0}", Filter.encodeValue(loginName));
            SearchResult found = p.search(config.userSearchBase(), SearchScope.SUB, Filter.create(filter),
                groupAttribute);
            if (found.getEntryCount() != 1) {
                return Optional.empty();
            }
            SearchResultEntry entry = found.getSearchEntries().get(0);
            BindResult bind = p.bindAndRevertAuthentication(new SimpleBindRequest(entry.getDN(),
                new String(password).getBytes(StandardCharsets.UTF_8)));
            if (bind.getResultCode() != ResultCode.SUCCESS) {
                return Optional.empty();
            }
            Set<String> roles = new HashSet<>();
            String[] groups = entry.getAttributeValues(groupAttribute);
            if (groups != null) {
                for (String group : groups) {
                    String role = groupRoles.get(group.toLowerCase(Locale.ROOT));
                    if (role != null) {
                        roles.add(role);
                    }
                }
            }
            return Optional.of(new AuthenticatedUser(loginName, roles, "ldap"));
        } catch (LDAPException e) {
            if (e.getResultCode() != ResultCode.INVALID_CREDENTIALS) {
                LOG.warn("directory bind failed with result {}", e.getResultCode().getName());
            }
            return Optional.empty();
        }
    }

    private synchronized LDAPConnectionPool pool() throws LDAPException {
        if (pool != null) {
            return pool;
        }
        LDAPURL url = new LDAPURL(config.url());
        // Credentials never cross the network in clear text: plain LDAP only to a loopback test directory (D-08).
        if (!"ldaps".equals(url.getScheme()) && !loopback(url.getHost())) {
            throw new LDAPException(ResultCode.CONFIDENTIALITY_REQUIRED, "the directory URL must be ldaps");
        }
        if (config.bindDn() == null || config.bindDn().isBlank()) {
            throw new LDAPException(ResultCode.PARAM_ERROR, "the directory bind DN is missing");
        }
        LDAPConnectionOptions options = new LDAPConnectionOptions();
        options.setConnectTimeoutMillis(5_000);
        options.setResponseTimeoutMillis(10_000);
        LDAPConnection connection;
        if ("ldaps".equals(url.getScheme())) {
            options.setSSLSocketVerifier(new HostNameSSLSocketVerifier(true));
            try {
                connection = new LDAPConnection(new SSLUtil().createSSLSocketFactory(), options, url.getHost(),
                    url.getPort());
            } catch (GeneralSecurityException e) {
                throw new LDAPException(ResultCode.CONNECT_ERROR, "TLS setup failed", e);
            }
        } else {
            connection = new LDAPConnection(options, url.getHost(), url.getPort());
        }
        try {
            connection.bind(config.bindDn(), bindPassword());
            pool = new LDAPConnectionPool(connection, 1, 2);
        } catch (LDAPException e) {
            connection.close();
            throw e;
        }
        pool.setRetryFailedOperationsDueToInvalidConnections(true);
        return pool;
    }

    /** An empty service password would be an anonymous bind (D-08). */
    private String bindPassword() throws LDAPException {
        String password;
        try {
            password = Files.readString(config.bindPasswordFile(), StandardCharsets.UTF_8).strip();
        } catch (IOException | RuntimeException e) {
            throw new LDAPException(ResultCode.PARAM_ERROR, "the directory bind password file is unreadable");
        }
        if (password.isEmpty()) {
            throw new LDAPException(ResultCode.PARAM_ERROR, "the directory bind password file is empty");
        }
        return password;
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
        if (pool != null) {
            pool.close();
            pool = null;
        }
    }
}
