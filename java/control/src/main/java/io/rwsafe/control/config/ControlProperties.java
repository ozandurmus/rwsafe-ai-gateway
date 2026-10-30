package io.rwsafe.control.config;

import java.nio.file.Path;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * The control plane's own settings ({@code rwsafe.*}). Key and password material is never a property value: every secret
 * is a file path to a mounted Secret (neXus C1 §6 rule, CORPORATE_TECHNOLOGY_STACK §2 secret management).
 */
@ConfigurationProperties(prefix = "rwsafe")
public record ControlProperties(CaptureSink captureSink, Privacy privacy, Identity identity, Sample sample) {

    public ControlProperties {
        captureSink = captureSink == null ? new CaptureSink(8092, "127.0.0.1") : captureSink;
        privacy = privacy == null ? new Privacy(null, null) : privacy;
        identity = identity == null ? new Identity(null, null, false) : identity;
        sample = sample == null ? new Sample(0, 1) : sample;
    }

    /** The internal connector (PORTS_AND_RESOURCES: 8092 capture sink): ingestion only, ClusterIP only. */
    public record CaptureSink(int port, String bindAddress) {
    }

    /**
     * @param hmacKeyFile          rwsafe's own privacy HMAC key (MASKING_AND_PRIVACY B3), at least 32 bytes
     * @param estateDictionaryFile the estate dictionary for masking layer 3, one term per line (may be empty, must exist)
     */
    public record Privacy(Path hmacKeyFile, Path estateDictionaryFile) {
    }

    public record Identity(Ldap ldap, BreakGlass breakGlass, boolean cookieSecure) {

        public Identity {
            ldap = ldap == null ? new Ldap(null, null, null, null, null, null, null) : ldap;
            breakGlass = breakGlass == null ? new BreakGlass(false, null) : breakGlass;
        }
    }

    /**
     * LDAP/AD bind (Q-9): search the user with the service account, then bind as the user; groups map to roles.
     *
     * @param url              {@code ldaps://host:636} (or {@code ldap://} for a local test directory only)
     * @param userSearchFilter with {@code {0}} for the escaped login name, for example {@code (sAMAccountName={0})}
     * @param groupRoles       group distinguished name (lower case) to role
     */
    public record Ldap(String url, String bindDn, Path bindPasswordFile, String userSearchBase, String userSearchFilter,
                       String groupAttribute, Map<String, String> groupRoles) {

        public boolean configured() {
            return url != null && !url.isBlank();
        }
    }

    /** The local break-glass account; its initial password is generated at first start and written to this file. */
    public record BreakGlass(boolean enabled, Path initialPasswordFile) {
    }

    /** Synthetic sample events at start (development profile only). */
    public record Sample(int events, long seed) {
    }
}
