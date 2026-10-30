package io.rwsafe.control.config;

import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * The control plane's own settings ({@code rwsafe.*}). Key and password material is never a property value: every secret
 * is a file path to a mounted Secret (neXus C1 §6 rule, CORPORATE_TECHNOLOGY_STACK §2 secret management).
 */
@ConfigurationProperties(prefix = "rwsafe")
public record ControlProperties(CaptureSink captureSink, SnapshotFeed snapshotFeed, Privacy privacy, Identity identity,
                                Policy policy, Sample sample, Siem siem) {

    public ControlProperties {
        captureSink = captureSink == null ? new CaptureSink(8092, "127.0.0.1") : captureSink;
        snapshotFeed = snapshotFeed == null ? new SnapshotFeed(8091, "127.0.0.1") : snapshotFeed;
        privacy = privacy == null ? new Privacy(null, null) : privacy;
        identity = identity == null ? new Identity(null, null, false) : identity;
        policy = policy == null ? new Policy(null, null, null, null, null) : policy;
        sample = sample == null ? new Sample(0, 1) : sample;
        siem = siem == null ? new Siem(false, null, null, 0, 0, 0, null, null, null, null) : siem;
    }

    /**
     * SIEM export (ADR-009 C8, SR-SIEM-*; LOCAL_RUN.md "SIEM export"). Off unless {@code enabled}; each destination is on
     * when its address is set. Real destinations and the CA bundle come from the uncommitted ConfigMap
     * {@code rwsafe-siem-destination}, the HEC token from the Secret {@code rwsafe-siem-credentials} as a file
     * ({@code deploy/rwsafe/contracts/runtime-contracts.json}).
     *
     * @param startFrom {@code earliest} (default: everything stored reaches the SIEM) or {@code latest} (a destination
     *                  without a watermark skips the stored verdict events; audit-ledger rows always export from the
     *                  first one, PO decision Q-SIEM-1)
     */
    public record Siem(boolean enabled, String startFrom, Duration pollInterval, int queueCapacity,
                       int pageSize, int batchSize, Duration backoffInitial, Duration backoffMax, Syslog syslog,
                       Hec hec) {

        public Siem {
            startFrom = startFrom == null || startFrom.isBlank() ? "earliest" : startFrom.strip();
            pollInterval = pollInterval == null ? Duration.ofSeconds(2) : pollInterval;
            queueCapacity = queueCapacity == 0 ? 10_000 : queueCapacity;
            pageSize = pageSize == 0 ? 500 : pageSize;
            batchSize = batchSize == 0 ? 200 : batchSize;
            backoffInitial = backoffInitial == null ? Duration.ofSeconds(1) : backoffInitial;
            backoffMax = backoffMax == null ? Duration.ofMinutes(2) : backoffMax;
            syslog = syslog == null ? new Syslog(null, 0, null, null, null, 0, null, null) : syslog;
            hec = hec == null ? new Hec(null, null, null, null, null) : hec;
            if (!startFrom.equals("earliest") && !startFrom.equals("latest")) {
                throw new IllegalArgumentException("rwsafe.siem.start-from is earliest or latest");
            }
        }
    }

    /**
     * Syslog over TLS (RFC 5425) to {@code host:port}, payload CEF or LEEF. There is no UDP or plain-TCP setting
     * (SR-SIEM-3: UDP only by a recorded PO acceptance, and none exists).
     *
     * @param hostname the RFC 5424 HOSTNAME this exporter writes (a fixed product name, not the pod's)
     * @param facility RFC 5424 facility, default 13 (log audit)
     */
    public record Syslog(String host, int port, String format, Path caFile, String hostname, int facility,
                         Duration connectTimeout, Duration writeTimeout) {

        public Syslog {
            port = port == 0 ? 6514 : port;
            format = format == null || format.isBlank() ? "cef" : format.strip().toLowerCase(java.util.Locale.ROOT);
            hostname = hostname == null || hostname.isBlank() ? "rwsafe-control" : hostname.strip();
            facility = facility == 0 ? 13 : facility;
            connectTimeout = connectTimeout == null ? Duration.ofSeconds(5) : connectTimeout;
            writeTimeout = writeTimeout == null ? Duration.ofSeconds(10) : writeTimeout;
        }

        public boolean configured() {
            return host != null && !host.isBlank();
        }
    }

    /**
     * Splunk HTTP Event Collector over HTTPS.
     *
     * @param url       {@code https://host:port} (the event endpoint path is added) or the full endpoint URL
     * @param tokenFile the HEC token, a mounted Secret file
     * @param index     the target index; blank for the token's default
     */
    public record Hec(String url, Path tokenFile, Path caFile, String index, Duration timeout) {

        public Hec {
            timeout = timeout == null ? Duration.ofSeconds(10) : timeout;
        }

        public boolean configured() {
            return url != null && !url.isBlank();
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
