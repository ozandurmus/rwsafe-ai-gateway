package io.rwsafe.control.identity;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPURL;
import com.unboundid.ldap.sdk.RDN;
import io.rwsafe.policy.GroupNames;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The directory connection one {@link LdapAuthenticator} uses: validated settings (DirectorySettingsService) with the
 * opened bind password. Every value here is a directory identifier or a secret, so {@link #toString()} prints none.
 *
 * @param groupRoles   the group -> role bindings keyed by {@link #nameKey} of the group's name
 * @param localTargets the test-only switch ({@code rwsafe.identity.directory-loopback-for-tests}, PR 50 review Q-1 and
 *                     D-03): loopback targets on any port and plain LDAP to them. Off, a target must not be loopback,
 *                     link-local, unspecified or multicast, must use a directory port, and plain LDAP is refused
 */
public record DirectoryConfig(List<LDAPURL> urls, TlsMode tlsMode, List<X509Certificate> caCertificates, String bindDn,
                              char[] bindPassword, String userSearchBase, String userSearchFilter,
                              String groupAttribute, String groupSearchBase, String groupSearchFilter,
                              int connectTimeoutMs, int responseTimeoutMs, Map<String, Set<String>> groupRoles,
                              boolean localTargets) {

    /** LDAPS (TLS from the first byte), StartTLS on a plain port, or none (a loopback test directory only). */
    public enum TlsMode {
        LDAPS, STARTTLS, NONE;

        /** The stored spelling: {@code ldaps}, {@code starttls}, {@code none}. */
        public String stored() {
            return name().toLowerCase(java.util.Locale.ROOT);
        }

        public static TlsMode ofStored(String s) {
            return valueOf(s.toUpperCase(java.util.Locale.ROOT));
        }
    }

    public static final String DEFAULT_GROUP_ATTRIBUTE = "memberOf";
    /** LDAP, LDAPS and the global catalogue's two ports (PR 50 review D-03): the only ports a directory URL may name. */
    public static final Set<Integer> DIRECTORY_PORTS = Set.of(389, 636, 3268, 3269);

    public DirectoryConfig {
        urls = List.copyOf(urls);
        caCertificates = List.copyOf(caCertificates);
        bindPassword = bindPassword.clone();
        groupRoles = Map.copyOf(groupRoles);
    }

    @Override
    public char[] bindPassword() {
        return bindPassword.clone();
    }

    /** Clears this object's copy of the password (the authenticator is closing). */
    void clear() {
        Arrays.fill(bindPassword, '\0');
    }

    /**
     * The one comparison form of a group's <em>name</em>, used on both sides (PR 50 review D-04): the name an
     * administrator binds and the name taken from a directory value ({@link #valueKey}). A name holding {@code '='} is
     * refused (null), since it would read as a distinguished name; otherwise {@link GroupNames#normalise} (Turkish
     * İ/I/ı fold, no comma, no control character), null when that refuses it.
     */
    public static String nameKey(String name) {
        if (name == null || name.indexOf('=') >= 0) {
            return null;
        }
        return GroupNames.normalise(name);
    }

    /**
     * The comparison form of a group value the directory returns ({@code memberOf}, a group search entry's DN): the
     * value of the distinguished name's first RDN, which must have exactly one attribute value, through
     * {@link #nameKey}. A value without {@code '='} is a plain group name and goes to {@link #nameKey} as it is. A value
     * that does not parse, or whose first RDN is multi-valued, matches nothing (null).
     */
    public static String valueKey(String value) {
        if (value == null) {
            return null;
        }
        if (value.indexOf('=') < 0) {
            return nameKey(value);
        }
        try {
            RDN first = new DN(value).getRDN();
            if (first == null || first.isMultiValued() || first.getAttributeValues().length != 1) {
                return null;
            }
            return nameKey(first.getAttributeValues()[0]);
        } catch (LDAPException notADn) {
            return null;
        }
    }

    @Override
    public String toString() {
        return "DirectoryConfig[urls=" + urls.size() + ", tls=" + tlsMode + ", ca=" + caCertificates.size()
            + ", groups=" + groupRoles.size() + "]";
    }

    @Override
    public boolean equals(Object o) {
        return this == o;
    }

    @Override
    public int hashCode() {
        return System.identityHashCode(this);
    }
}
