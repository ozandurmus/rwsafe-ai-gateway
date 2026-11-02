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
 * @param groupRoles the group -> role bindings keyed by the {@link GroupNames} comparison form of the group's name
 */
public record DirectoryConfig(List<LDAPURL> urls, TlsMode tlsMode, List<X509Certificate> caCertificates, String bindDn,
                              char[] bindPassword, String userSearchBase, String userSearchFilter,
                              String groupAttribute, String groupSearchBase, String groupSearchFilter,
                              int connectTimeoutMs, int responseTimeoutMs, Map<String, Set<String>> groupRoles) {

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
     * The name a directory group value is matched by: a distinguished name ({@code memberOf}, a group search) gives
     * the value of its first RDN, which is the group's short name (the product's group names are short names without
     * commas, PO decision on PR 20 review Q-2); any other value is taken as the name itself. Then the {@link GroupNames}
     * comparison form (Turkish İ/I/ı fold); null when the result is not a valid group name.
     */
    public static String groupKey(String value) {
        if (value == null) {
            return null;
        }
        String name = value;
        if (value.indexOf('=') > 0) {
            try {
                RDN first = new DN(value).getRDN();
                if (first != null && first.getAttributeValues().length > 0) {
                    name = first.getAttributeValues()[0];
                }
            } catch (LDAPException notADn) {
                name = value;
            }
        }
        return GroupNames.normalise(name);
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
