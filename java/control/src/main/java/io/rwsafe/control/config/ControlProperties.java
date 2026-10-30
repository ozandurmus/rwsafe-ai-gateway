package io.rwsafe.control.config;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * The control plane's own settings ({@code rwsafe.*}). Key and password material is never a property value: every secret
 * is a file path to a mounted Secret (neXus C1 §6 rule, CORPORATE_TECHNOLOGY_STACK §2 secret management).
 */
@ConfigurationProperties(prefix = "rwsafe")
public record ControlProperties(CaptureSink captureSink, SnapshotFeed snapshotFeed, Privacy privacy, Identity identity,
                                Policy policy, Sample sample, Capture capture) {

    public ControlProperties {
        capture = capture == null ? new Capture(null, null, null, null) : capture;
        captureSink = captureSink == null ? new CaptureSink(8092, "127.0.0.1") : captureSink;
        snapshotFeed = snapshotFeed == null ? new SnapshotFeed(8091, "127.0.0.1") : snapshotFeed;
        privacy = privacy == null ? new Privacy(null, null) : privacy;
        identity = identity == null ? new Identity(null, null, false) : identity;
        policy = policy == null ? new Policy(null, null, null, null, null) : policy;
        sample = sample == null ? new Sample(0, 1) : sample;
    }

    /**
     * Redacted capture (PO decisions Q-3, Q-4 b, Q-5; ADR-009 C3).
     *
     * @param mode           {@code redacted} stores the redacted text of REDACT verdicts for users with a current notice
     *                       acknowledgement; anything else (the default {@code off}) stores metadata and verdicts only
     * @param keyDir         the mounted capture-key Secret: one {@code <key id>.key} file per key (base64 of 32 bytes) and
     *                       an {@code active} file naming the key new records are sealed under; never the privacy key
     * @param retention      how long a record lives, at most 90 days (Q-5)
     * @param watermarkPaths paths on the filesystems the breaker watches (the database volume's filesystem; on k3s
     *                       local-path any path of the node's root filesystem)
     */
    public record Capture(String mode, Path keyDir, Duration retention, List<Path> watermarkPaths) {

        public static final Duration MAX_RETENTION = Duration.ofDays(90);

        public Capture {
            mode = mode == null ? "off" : mode;
            retention = retention == null ? MAX_RETENTION : retention;
            watermarkPaths = watermarkPaths == null || watermarkPaths.isEmpty()
                ? List.of(Path.of(System.getProperty("java.io.tmpdir"))) : List.copyOf(watermarkPaths);
            if (retention.isNegative() || retention.isZero() || retention.compareTo(MAX_RETENTION) > 0) {
                throw new IllegalArgumentException("rwsafe.capture.retention is between 1 s and 90 days (Q-5)");
            }
        }

        public boolean redacted() {
            return "redacted".equals(mode);
        }
    }

    /** The internal connector (PORTS_AND_RESOURCES: 8092 capture sink): ingestion only, ClusterIP only. */
    public record CaptureSink(int port, String bindAddress) {
    }

    /**
     * The internal connector of the policy snapshot feed (PORTS_AND_RESOURCES: 8091, POLICY_SNAPSHOT_CONTRACT): the
     * snapshot route only, ClusterIP only.
     */
    public record SnapshotFeed(int port, String bindAddress) {
    }

    /**
     * The policy registry and the signed snapshot (AGENTS.md section 6, POLICY_SNAPSHOT_CONTRACT).
     *
     * @param seedFile         the committed fixture {@code policy/registry-seed.yaml}, imported once into an empty registry
     * @param signingKeyFile   the Ed25519 private key, PKCS#8 PEM, from a mounted Secret ({@code RWSAFE_SNAPSHOT_SIGNING_KEY})
     * @param signingKeyId     the id the data plane knows the matching public key by ({@code <key id>.pem}); when blank,
     *                         the key file's name without its extension
     * @param snapshotRefresh  a snapshot older than this is re-issued (re-signed) under the next version with a fresh
     *                         {@code issuedAt} even when no rule changed, at most 6 hours (POLICY_SNAPSHOT_CONTRACT: the
     *                         data plane stops serving a snapshot older than 24 hours and activates only higher versions)
     * @param simulationWindow how far back the simulation counts stored verdict events (at most 31 days)
     */
    public record Policy(Path seedFile, Path signingKeyFile, String signingKeyId, Duration snapshotRefresh,
                         Duration simulationWindow) {

        /** The contract's re-issue bound: the active policy is re-signed at least this often. */
        public static final Duration MAX_SNAPSHOT_AGE = Duration.ofHours(6);

        public Policy {
            snapshotRefresh = snapshotRefresh == null ? Duration.ofHours(6) : snapshotRefresh;
            simulationWindow = simulationWindow == null ? Duration.ofDays(7) : simulationWindow;
            if (snapshotRefresh.isNegative() || snapshotRefresh.isZero()
                || snapshotRefresh.compareTo(MAX_SNAPSHOT_AGE) > 0) {
                throw new IllegalArgumentException("rwsafe.policy.snapshot-refresh is between 1 s and 6 h");
            }
            if (simulationWindow.isNegative() || simulationWindow.isZero()
                || simulationWindow.compareTo(Duration.ofDays(31)) > 0) {
                throw new IllegalArgumentException("rwsafe.policy.simulation-window is between 1 s and 31 days");
            }
        }
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
