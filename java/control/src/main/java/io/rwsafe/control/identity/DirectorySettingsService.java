package io.rwsafe.control.identity;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPURL;
import io.rwsafe.control.config.ControlProperties;
import io.rwsafe.control.identity.DirectoryConfig.TlsMode;
import io.rwsafe.control.privacy.IdentifierCheck;
import io.rwsafe.control.privacy.PrivacyKeys;
import io.rwsafe.control.privacy.Pseudonymiser;
import io.rwsafe.persistence.AuditContext;
import io.rwsafe.persistence.Database;
import io.rwsafe.persistence.DirectorySettings;
import io.rwsafe.persistence.DirectorySettingsConflict;
import io.rwsafe.persistence.DirectorySettingsStore;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

/**
 * Administration -> Access part 2 (PO decision Q-47, decision 1.2): the directory connection and the group -> role
 * bindings, stored in the product's database ({@code directory_settings}, V12) and the one source the directory sign-in
 * reads.
 *
 * <ul>
 *   <li>Every save is a new version (the highest is active), ledgered with the administrator's pseudonym and reason; a
 *       save on a stale version is refused. After a save the directory front is rebuilt at once: the next sign-in
 *       connects with the new settings, no restart. A sign-in that was running on the replaced settings and failed for
 *       that reason is retried once on the new ones.</li>
 *   <li>The bind password is sealed under the directory key ({@link DirectoryKey}) and never returned: the API says
 *       only whether one is set, and a save without a new password keeps the stored one. Without the key nothing is
 *       sealed or opened, and the directory is unavailable with that reason (never a plaintext fallback).</li>
 *   <li>The deploy's {@code RWSAFE_LDAP_*} values seed an empty table once at start (system actor
 *       {@code system:deploy-seed}); afterwards they are never read again, so they never override a saved setting.</li>
 *   <li>The connection test connects, binds with the service account and optionally finds one login name, with a hard
 *       time limit, one test at a time and a few per minute per administrator; its answer is a class and counts.</li>
 * </ul>
 * No URL, distinguished name, group name, login name or password is ever logged.
 */
@Service
public class DirectorySettingsService implements Authenticator, InitializingBean, DisposableBean {

    private static final Logger LOG = LoggerFactory.getLogger(DirectorySettingsService.class);

    public static final String SEED_ACTOR = "system:deploy-seed";
    /** The profiles the test-only switch belongs to: the test suite's and the local development application's. */
    static final String TEST_PROFILES = "test | dev";
    static final String SEED_REASON = "Seeded once from the deploy configuration (RWSAFE_LDAP_*) into an empty table";
    public static final int MAX_URLS = 8;
    public static final int MAX_GROUPS = 500;
    public static final int MAX_CA_CERTIFICATES = 20;
    public static final int DEFAULT_CONNECT_MS = 5_000;
    public static final int DEFAULT_RESPONSE_MS = 10_000;
    public static final int TESTS_PER_MINUTE = 6;
    /** All administrators together (PR 50 review D-03). */
    public static final int TESTS_PER_MINUTE_GLOBAL = 20;
    /** A bind password's longest UTF-8 form (D-01). */
    public static final int MAX_PASSWORD_BYTES = 1024;
    static final int HISTORY = 50;
    private static final int MAX_TEXT = 1024;
    private static final long MAX_TEST_MS = 45_000;

    /** What the directory front is doing now; {@code reason} explains a status other than {@code ACTIVE}. */
    public record Status(String status, String reason, int version) {
    }

    /** The connection fields of a save or a test, as entered (validated here). */
    public record Connection(Boolean enabled, List<String> urls, String tlsMode, String caCertificatePem,
                             boolean clearCaCertificate, String bindDn, char[] newPassword, String userSearchBase,
                             String userSearchFilter, String groupAttribute, String groupSearchBase,
                             String groupSearchFilter, Integer connectTimeoutMs, Integer responseTimeoutMs) {

        @Override
        public String toString() {
            return "Connection[redacted]";
        }
    }

    /** One binding as entered. */
    public record GroupBinding(String group, Collection<String> roles) {

        @Override
        public String toString() {
            return "GroupBinding[" + roles + "]";
        }
    }

    /** The settings screen: the active version (if any), the front's status, the key's state and the history. */
    public record State(Optional<DirectorySettings> active, Status status, DirectoryKey.State key,
                        boolean deployValuesPresent, List<DirectorySettingsStore.HistoryEntry> history,
                        boolean localTargets) {
    }

    private record Active(int version, LdapAuthenticator ldap, Status status) {
    }

    private final Database database;
    private final ControlProperties.Ldap deploy;
    private final DirectoryKey key;
    private final LocalUsers users;
    private final Pseudonymiser pseudonymiser;
    private final PrivacyKeys keys;
    private final Clock clock;
    private final ActiveSessions sessions;
    private final boolean localTargets;
    private final boolean testProfile;
    private final Semaphore oneTest = new Semaphore(1);
    private final Map<String, Deque<Instant>> testsByActor = new HashMap<>();
    private final Deque<Instant> testsAll = new ArrayDeque<>();
    // One test in flight: the permit is released by the test's own task, so a test that outlives its time limit still
    // holds it and no second one overlaps it (D-03).
    private final ExecutorService testRunner = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "rwsafe-directory-test");
        t.setDaemon(true);
        return t;
    });
    private volatile Active active = new Active(0, null, new Status("NOT_CONFIGURED", null, 0));

    public DirectorySettingsService(Database database, ControlProperties properties, LocalUsers users,
                                    Pseudonymiser pseudonymiser, PrivacyKeys keys, ActiveSessions sessions,
                                    Environment environment) {
        this.database = database;
        this.deploy = properties.identity().ldap();
        this.key = new DirectoryKey(properties.identity().directoryKeyFile());
        this.users = users;
        this.pseudonymiser = pseudonymiser;
        this.keys = keys;
        this.clock = Clock.systemUTC();
        this.sessions = sessions;
        this.localTargets = properties.identity().directoryLoopbackForTests();
        this.testProfile = testProfile(environment);
    }

    /** True under the test-only switch: plain LDAP and loopback targets for a test directory (PR 50 review Q-1). */
    public boolean localTargets() {
        return localTargets;
    }

    @Override
    public void afterPropertiesSet() {
        testSwitchAlarm(localTargets, testProfile);
        seedFromDeploy();
        reload();
    }

    /**
     * Logs an ERROR line when the test-only switch is on outside the test (or local development) profile and says
     * whether it did. tools/deploy/manifest_check.py refuses every render that names the switch; this is the runtime's
     * own alarm should it be set some other way (PR 50 review Q-1).
     */
    /**
     * True under the test or local development profile: active, or declared in {@code spring.profiles.active} (a test
     * context declares it through its dynamic properties, which arrive after Boot has activated the profiles).
     */
    static boolean testProfile(Environment environment) {
        if (environment.matchesProfiles(TEST_PROFILES)) {
            return true;
        }
        for (String p : environment.getProperty("spring.profiles.active", "").split(",")) {
            if (p.strip().equals("test") || p.strip().equals("dev")) {
                return true;
            }
        }
        return false;
    }

    static boolean testSwitchAlarm(boolean on, boolean testProfile) {
        if (on && !testProfile) {
            LOG.error("rwsafe.identity.directory-loopback-for-tests is on outside the test profile: plain LDAP and "
                + "loopback directory targets are allowed; no deploy may set it");
            return true;
        }
        return false;
    }

    // ---- sign-in -------------------------------------------------------------------------------------------------

    @Override
    public Optional<AuthenticatedUser> authenticate(String loginName, char[] password) {
        Active a = active;
        if (a.ldap() == null) {
            return Optional.empty();
        }
        LdapAuthenticator.Attempt attempt = a.ldap().attempt(loginName, password);
        Active now = active;
        if (attempt.error() && now != a && now.ldap() != null) {
            // The settings were replaced while this sign-in ran on the old ones: once more on the new ones.
            attempt = now.ldap().attempt(loginName, password);
        }
        return Optional.ofNullable(attempt.user());
    }

    public Status status() {
        return active.status();
    }

    public State state() {
        return new State(database.directorySettings().active(), active.status(), key.state(), deploy.configured(),
            database.directorySettings().history(HISTORY), localTargets);
    }

    /** Rebuilds the directory front from the active stored version; the replaced one is closed. */
    public synchronized void reload() {
        Active next = build(database.directorySettings().active());
        Active old = active;
        active = next;
        if (old.ldap() != null) {
            old.ldap().close();
        }
        LOG.info("directory settings version {} loaded: {}{}", next.version(), next.status().status(),
            next.status().reason() == null ? "" : " (" + next.status().reason() + ")");
    }

    private Active build(Optional<DirectorySettings> stored) {
        if (stored.isEmpty()) {
            return new Active(0, null, new Status("NOT_CONFIGURED", key.state() == DirectoryKey.State.AVAILABLE ? null
                : keyReason(key.state()), 0));
        }
        DirectorySettings s = stored.get();
        if (!s.enabled()) {
            return new Active(s.version(), null, new Status("DISABLED", null, s.version()));
        }
        if (s.bindPasswordSealed() == null) {
            return new Active(s.version(), null, new Status("UNAVAILABLE", "BIND_PASSWORD_NOT_SET", s.version()));
        }
        char[] password = null;
        try {
            password = key.open(s.bindPasswordSealed(), context(s, s.version()));
            DirectoryConfig config = config(s, password);
            return new Active(s.version(), new LdapAuthenticator(config), new Status("ACTIVE", null, s.version()));
        } catch (DirectoryKey.Unavailable e) {
            return new Active(s.version(), null, new Status("UNAVAILABLE", e.reason(), s.version()));
        } catch (AccessRefusal | IllegalArgumentException e) {
            return new Active(s.version(), null, new Status("UNAVAILABLE", "SETTINGS_INVALID", s.version()));
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }

    private static String keyReason(DirectoryKey.State state) {
        return state == DirectoryKey.State.MISSING ? "DIRECTORY_KEY_MISSING" : "DIRECTORY_KEY_INVALID";
    }

    // ---- seed ----------------------------------------------------------------------------------------------------

    /**
     * Copies the deploy's directory values into an empty settings table, once. Skipped (with a log line that names no
     * value) when the deploy sets no directory, when a version exists, when the key is unusable (the password could
     * not be sealed; the next start tries again) or when a value is invalid.
     */
    void seedFromDeploy() {
        if (!deploy.configured() || database.directorySettings().active().isPresent()) {
            return;
        }
        if (key.state() != DirectoryKey.State.AVAILABLE) {
            LOG.warn("the deploy's directory values are not copied into the stored settings: {}",
                keyReason(key.state()));
            return;
        }
        char[] password = deployPassword();
        try {
            String url = deploy.url().strip();
            TlsMode mode = url.toLowerCase(Locale.ROOT).startsWith("ldaps://") ? TlsMode.LDAPS
                : loopbackUrl(url) ? TlsMode.NONE : TlsMode.STARTTLS;
            Connection c = new Connection(true, List.of(url), mode.stored(), null, false, deploy.bindDn(), null,
                deploy.userSearchBase(), deploy.userSearchFilter(), deploy.groupAttribute() == null
                ? DirectoryConfig.DEFAULT_GROUP_ATTRIBUTE : deploy.groupAttribute(), null, null, null, null);
            Map<String, DirectorySettings.GroupRoles> groups = new LinkedHashMap<>();
            int skipped = 0;
            if (deploy.groupRoles() != null) {
                for (Map.Entry<String, String> e : deploy.groupRoles().entrySet()) {
                    String name = shortName(e.getKey());
                    String k = DirectoryConfig.nameKey(name);
                    if (k == null || !Roles.ALL.contains(e.getValue())) {
                        skipped++;
                        continue;
                    }
                    DirectorySettings.GroupRoles before = groups.get(k);
                    Set<String> roles = new LinkedHashSet<>(before == null ? List.of() : before.roles());
                    roles.add(e.getValue());
                    groups.put(k, new DirectorySettings.GroupRoles(before == null ? name : before.group(),
                        orderedRoles(roles)));
                }
            }
            if (groups.size() > MAX_GROUPS) {
                LOG.warn("the deploy's directory values are not copied into the stored settings: TOO_MANY_GROUPS");
                return;
            }
            Validated v = validate(c, localTargets);
            byte[] sealed = password == null ? null : key.seal(password, DirectoryKey.context(1, v.tlsMode().stored(),
                v.bindDn(), v.urls(), null));
            DirectorySettings seed = settings(v, sealed, null, SEED_ACTOR, "seed", SEED_REASON,
                new ArrayList<>(groups.values()));
            boolean seeded = database.directorySettings().seedIfEmpty(seed,
                new AuditContext(SEED_ACTOR, "directory_settings.seed", SEED_REASON, UUID.randomUUID().toString()));
            if (seeded) {
                LOG.info("directory settings seeded once from the deploy values: {} group bindings, {} skipped, "
                    + "password {}", groups.size(), skipped, sealed != null ? "set" : "not set");
            }
        } catch (AccessRefusal e) {
            LOG.warn("the deploy's directory values are not copied into the stored settings: {}", e.reason());
        } catch (DirectoryKey.Unavailable e) {
            LOG.warn("the deploy's directory values are not copied into the stored settings: {}", e.reason());
        } catch (RuntimeException e) {
            // A value the database refuses (a check, the guard) never stops the start: the seed is skipped (D-07).
            LOG.warn("the deploy's directory values are not copied into the stored settings: SEED_REFUSED");
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }

    private char[] deployPassword() {
        if (deploy.bindPasswordFile() == null) {
            return null;
        }
        try {
            String p = Files.readString(deploy.bindPasswordFile(), StandardCharsets.UTF_8).strip();
            return p.isEmpty() ? null : p.toCharArray();
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    /**
     * A seeded binding's name: the value of a distinguished name's first, single-valued RDN, else the key as written
     * when it holds no {@code '='}; null when neither (the binding is skipped).
     */
    private static String shortName(String key) {
        if (key == null || key.indexOf('=') < 0) {
            return key;
        }
        try {
            var rdn = new DN(key).getRDN();
            return rdn == null || rdn.isMultiValued() || rdn.getAttributeValues().length != 1 ? null
                : rdn.getAttributeValues()[0];
        } catch (LDAPException notADn) {
            return null;
        }
    }

    private static boolean loopbackUrl(String url) {
        try {
            return LdapAuthenticator.loopback(new LDAPURL(url).getHost());
        } catch (LDAPException e) {
            return false;
        }
    }

    // ---- saves ---------------------------------------------------------------------------------------------------

    /**
     * Saves the connection fields as the next version; the group bindings are carried over. Without a new password the
     * stored one is kept only when the URLs, the bind DN, the TLS mode and the CA bundle are all the saved ones, and it
     * is sealed again under the new version's associated data (PR 50 review D-01); otherwise {@code PASSWORD_REQUIRED}.
     * Switching the directory off ends the open directory sessions but {@code keepHandle} (D-08).
     */
    public DirectorySettings saveConnection(LocalUsers.Actor by, int expectedVersion, Connection input, String reason,
                                            String keepHandle) {
        String actor = pseudonym(by.loginName());
        Validated v = validate(input, localTargets);
        Optional<DirectorySettings> current = database.directorySettings().active();
        String ca = input.clearCaCertificate() ? null : v.caPem() != null ? v.caPem()
            : current.map(DirectorySettings::caCertificatePem).orElse(null);
        List<String> identifiers = new ArrayList<>(List.of(v.bindDn(), v.userSearchBase()));
        if (v.groupSearchBase() != null) {
            identifiers.add(v.groupSearchBase());
        }
        String why = reason(reason, by, current, List.of(), identifiers);
        int next = expectedVersion + 1;
        byte[] sealed;
        char[] newPassword = input.newPassword();
        if (newPassword != null && newPassword.length > 0) {
            sealed = seal(newPassword, DirectoryKey.context(next, v.tlsMode().stored(), v.bindDn(), v.urls(), ca));
        } else if (current.isEmpty() || current.get().bindPasswordSealed() == null) {
            sealed = null;
        } else if (!sameConnection(current.get(), v, ca)) {
            throw passwordRequired();
        } else {
            sealed = reseal(current.get(), next);
        }
        DirectorySettings settings = settings(v, sealed, ca, actor, "connection", why,
            current.map(DirectorySettings::groupRoles).orElse(List.of()));
        DirectorySettings saved = conflicts(() -> database.directorySettings().save(settings, expectedVersion,
            audit(actor, "directory_settings.connection", why)));
        reload();
        if (current.map(DirectorySettings::enabled).orElse(false) && !saved.enabled()) {
            endDirectorySessions(keepHandle);
        }
        return saved;
    }

    /**
     * Saves the group -> role bindings as the next version; the connection is carried over, its password sealed again
     * under the new version. When the bindings change, the open directory sessions but {@code keepHandle} end, so a
     * removed role does not outlive the change (D-08).
     */
    public DirectorySettings saveGroupRoles(LocalUsers.Actor by, int expectedVersion, List<GroupBinding> bindings,
                                            String reason, String keepHandle) {
        String actor = pseudonym(by.loginName());
        List<DirectorySettings.GroupRoles> groups = groups(bindings);
        DirectorySettings current = database.directorySettings().active().orElseThrow(() -> new AccessRefusal(
            HttpStatus.CONFLICT, "DIRECTORY_NOT_CONFIGURED", "Save the directory connection before binding groups."));
        String why = reason(reason, by, Optional.of(current), groups, List.of());
        byte[] sealed = current.bindPasswordSealed() == null ? null : reseal(current, expectedVersion + 1);
        DirectorySettings next = new DirectorySettings(0, null, actor, "group_roles", why, current.enabled(),
            current.urls(), current.tlsMode(), current.caCertificatePem(), current.bindDn(), sealed,
            current.userSearchBase(), current.userSearchFilter(), current.groupAttribute(), current.groupSearchBase(),
            current.groupSearchFilter(), current.connectTimeoutMs(), current.responseTimeoutMs(), groups);
        DirectorySettings saved = conflicts(() -> database.directorySettings().save(next, expectedVersion,
            audit(actor, "directory_settings.group_roles", why)));
        reload();
        if (!bindingKeys(current.groupRoles()).equals(bindingKeys(saved.groupRoles()))) {
            endDirectorySessions(keepHandle);
        }
        return saved;
    }

    /** The bindings in their comparison form, to tell a change from a re-save. */
    private static Map<String, Set<String>> bindingKeys(List<DirectorySettings.GroupRoles> groups) {
        Map<String, Set<String>> out = new HashMap<>();
        for (DirectorySettings.GroupRoles g : groups) {
            out.computeIfAbsent(String.valueOf(DirectoryConfig.nameKey(g.group())), k -> new java.util.TreeSet<>())
                .addAll(g.roles());
        }
        return out;
    }

    private void endDirectorySessions(String keepHandle) {
        int ended = sessions.endSource("ldap", keepHandle);
        LOG.info("directory settings changed: {} open directory sessions ended", ended);
    }

    /** True when {@code v} (with the effective CA bundle {@code ca}) connects where {@code s} does, as {@code s} does. */
    private static boolean sameConnection(DirectorySettings s, Validated v, String ca) {
        return s.urls().equals(v.urls()) && s.bindDn().equals(v.bindDn()) && s.tlsMode().equals(v.tlsMode().stored())
            && java.util.Objects.equals(s.caCertificatePem(), ca);
    }

    /** The associated data of {@code s}'s connection under {@code version}. */
    private static byte[] context(DirectorySettings s, int version) {
        return DirectoryKey.context(version, s.tlsMode(), s.bindDn(), s.urls(), s.caCertificatePem());
    }

    /** Opens {@code s}'s password and seals it for the same connection under {@code version}. */
    private byte[] reseal(DirectorySettings s, int version) {
        char[] password = storedPassword(s);
        try {
            return seal(password, context(s, version));
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static AccessRefusal passwordRequired() {
        return new AccessRefusal(HttpStatus.BAD_REQUEST, "PASSWORD_REQUIRED", "Enter the bind password: the stored one "
            + "is used only with the saved URLs, bind DN, TLS mode and CA certificate.");
    }

    // ---- connection test -----------------------------------------------------------------------------------------

    /**
     * Tests {@code input} (unsaved fields) or, when null, the saved settings; with {@code loginName} it also finds that
     * user and counts its groups under the saved bindings. A test of unsaved fields uses the stored password only when
     * the URLs and the bind DN are the saved ones: the stored password never goes to a server it was not saved for.
     */
    public LdapAuthenticator.Probe test(LocalUsers.Actor by, Connection input, String loginName) {
        String login = testLogin(loginName);
        // Validated before a rate-limit token is spent (D-03).
        DirectoryConfig config = testConfig(input);
        try {
            admit(by.loginName());
        } catch (AccessRefusal e) {
            config.clear();
            throw e;
        }
        LdapAuthenticator.Probe probe = run(config, login);
        LOG.info("directory connection test: {}{}", probe.result(), probe.detail() == null ? ""
            : " (" + probe.detail() + ")");
        return probe;
    }

    private DirectoryConfig testConfig(Connection input) {
        Optional<DirectorySettings> stored = database.directorySettings().active();
        DirectoryConfig config;
        char[] password = null;
        try {
            if (input == null) {
                DirectorySettings s = stored.orElseThrow(() -> new AccessRefusal(HttpStatus.CONFLICT,
                    "DIRECTORY_NOT_CONFIGURED", "No directory settings are saved; enter them to test."));
                password = storedPassword(s);
                config = config(s, password);
            } else {
                Validated v = validate(input, localTargets);
                String ca = input.clearCaCertificate() ? null : v.caPem() != null ? v.caPem()
                    : stored.map(DirectorySettings::caCertificatePem).orElse(null);
                if (input.newPassword() != null && input.newPassword().length > 0) {
                    password = input.newPassword().clone();
                } else {
                    DirectorySettings s = stored.filter(x -> x.bindPasswordSealed() != null && sameConnection(x, v, ca))
                        .orElseThrow(DirectorySettingsService::passwordRequired);
                    password = storedPassword(s);
                }
                config = config(settings(v, null, ca, SEED_ACTOR, "connection", "test",
                    stored.map(DirectorySettings::groupRoles).orElse(List.of())), password);
            }
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
        return config;
    }

    private LdapAuthenticator.Probe run(DirectoryConfig config, String login) {
        LdapAuthenticator ldap;
        try {
            ldap = new LdapAuthenticator(config);
        } catch (IllegalArgumentException e) {
            config.clear();
            oneTest.release();
            return LdapAuthenticator.Probe.of(LdapAuthenticator.TestResult.TLS_FAILED, "TLS_SETUP_FAILED", 0);
        }
        long limit = Math.min(MAX_TEST_MS, (long) config.connectTimeoutMs() * config.urls().size()
            + 3L * config.responseTimeoutMs() + 1_000);
        Future<LdapAuthenticator.Probe> f;
        try {
            f = testRunner.submit(() -> {
                try {
                    return ldap.probe(login);
                } finally {
                    ldap.close();
                    oneTest.release();
                }
            });
        } catch (RuntimeException rejected) {
            ldap.close();
            oneTest.release();
            return LdapAuthenticator.Probe.of(LdapAuthenticator.TestResult.UNREACHABLE, "TEST_FAILED", 0);
        }
        try {
            return f.get(limit, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            f.cancel(true);
            return LdapAuthenticator.Probe.of(LdapAuthenticator.TestResult.UNREACHABLE, "TIMEOUT", 0);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            f.cancel(true);
            return LdapAuthenticator.Probe.of(LdapAuthenticator.TestResult.UNREACHABLE, "INTERRUPTED", 0);
        } catch (ExecutionException e) {
            return LdapAuthenticator.Probe.of(LdapAuthenticator.TestResult.UNREACHABLE, "TEST_FAILED", 0);
        }
    }

    /**
     * One test at a time, at most {@value #TESTS_PER_MINUTE} a minute per administrator and
     * {@value #TESTS_PER_MINUTE_GLOBAL} a minute in all. The permit is released by the test's task ({@link #run}).
     */
    private void admit(String actorLogin) {
        String who = actorLogin == null ? "" : actorLogin.toLowerCase(Locale.ROOT);
        Instant now = clock.instant();
        synchronized (testsByActor) {
            Deque<Instant> recent = testsByActor.computeIfAbsent(who, k -> new ArrayDeque<>());
            for (Deque<Instant> d : List.of(recent, testsAll)) {
                while (!d.isEmpty() && d.peekFirst().isBefore(now.minusSeconds(60))) {
                    d.pollFirst();
                }
            }
            if (recent.size() >= TESTS_PER_MINUTE || testsAll.size() >= TESTS_PER_MINUTE_GLOBAL) {
                throw new AccessRefusal(HttpStatus.TOO_MANY_REQUESTS, "DIRECTORY_TEST_RATE_LIMITED",
                    "Too many connection tests in the last minute; wait a moment.");
            }
            if (!oneTest.tryAcquire()) {
                throw new AccessRefusal(HttpStatus.TOO_MANY_REQUESTS, "DIRECTORY_TEST_BUSY",
                    "Another connection test is running; try again when it ends.");
            }
            recent.addLast(now);
            testsAll.addLast(now);
        }
    }

    /**
     * The local users' reason rule ({@link LocalUsers#reason}: no identifier, no estate term, no name a person on the
     * screens is known by), and no directory identifier (PR 50 review D-06): not a group name of the saved or the new
     * bindings, not a value of an RDN of the bind DN or a search base, saved or entered. Matched word by word as
     * {@link LocalUsers#namesPerson} does (tokens of 3 or more letters, Turkish folding, a Turkish suffix after a token
     * of 4 or more), and as a whole name. The ledger and the SIEM read the reason as written; the refusal never echoes
     * it.
     */
    private String reason(String raw, LocalUsers.Actor by, Optional<DirectorySettings> current,
                          List<DirectorySettings.GroupRoles> groups, List<String> distinguishedNames) {
        String why = users.reason(raw, by);
        List<String> names = new ArrayList<>();
        List<String> dns = new ArrayList<>(distinguishedNames);
        current.ifPresent(c -> {
            c.groupRoles().forEach(g -> names.add(g.group()));
            dns.add(c.bindDn());
            dns.add(c.userSearchBase());
            if (c.groupSearchBase() != null) {
                dns.add(c.groupSearchBase());
            }
        });
        groups.forEach(g -> names.add(g.group()));
        for (String dn : dns) {
            names.addAll(rdnValues(dn));
        }
        String folded = IdentifierCheck.fold(why);
        boolean whole = names.stream().map(n -> IdentifierCheck.fold(n)).anyMatch(n -> n.length() >= 3
            && folded.contains(n));
        if (whole || LocalUsers.namesPerson(why, names)) {
            throw invalid("REASON_HOLDS_IDENTIFIER", "The reason names a directory group, account or location; describe "
                + "the change without it.");
        }
        return why;
    }

    /** Every attribute value of every RDN of {@code dn}; nothing when it does not parse. */
    static List<String> rdnValues(String dn) {
        List<String> out = new ArrayList<>();
        if (dn == null) {
            return out;
        }
        try {
            for (com.unboundid.ldap.sdk.RDN rdn : new DN(dn).getRDNs()) {
                out.addAll(Arrays.asList(rdn.getAttributeValues()));
            }
        } catch (LDAPException notADn) {
            return out;
        }
        return out;
    }

    private static String testLogin(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String login = raw.strip();
        if (login.length() > 256 || login.chars().anyMatch(Character::isISOControl)) {
            throw invalid("INVALID_TEST_LOGIN", "A test login name is 1 to 256 characters on one line.");
        }
        return login;
    }

    private char[] storedPassword(DirectorySettings s) {
        if (s.bindPasswordSealed() == null) {
            throw new AccessRefusal(HttpStatus.CONFLICT, "BIND_PASSWORD_NOT_SET",
                "No bind password is stored; enter one to test.");
        }
        try {
            return key.open(s.bindPasswordSealed(), context(s, s.version()));
        } catch (DirectoryKey.Unavailable e) {
            throw new AccessRefusal(HttpStatus.SERVICE_UNAVAILABLE, e.reason(), e.getMessage());
        }
    }

    private byte[] seal(char[] password, byte[] context) {
        try {
            return key.seal(password, context);
        } catch (DirectoryKey.Unavailable e) {
            throw new AccessRefusal(HttpStatus.SERVICE_UNAVAILABLE, e.reason(), e.getMessage()
                + " The bind password cannot be stored without it; nothing changed.");
        }
    }

    // ---- validation ----------------------------------------------------------------------------------------------

    /** Validated connection fields; {@code caPem} is the re-encoded bundle as entered, or null when none was. */
    record Validated(boolean enabled, List<String> urls, TlsMode tlsMode, String caPem, String bindDn,
                     String userSearchBase, String userSearchFilter, String groupAttribute, String groupSearchBase,
                     String groupSearchFilter, int connectTimeoutMs, int responseTimeoutMs) {
    }

    /**
     * @param localTargets the test-only switch: plain LDAP ({@code none}) and loopback targets on any port; off, the
     *                     TLS mode is LDAPS or StartTLS and every literal target is a routable address on a directory
     *                     port (names are checked again, resolved, at connect time)
     */
    static Validated validate(Connection c, boolean localTargets) {
        if (c == null) {
            throw invalid("INVALID_DIRECTORY_SETTINGS", "The directory settings are missing.");
        }
        TlsMode mode;
        try {
            mode = TlsMode.ofStored(c.tlsMode() == null ? "" : c.tlsMode().strip());
        } catch (IllegalArgumentException e) {
            throw invalid("INVALID_TLS_MODE", "The TLS mode is LDAPS or StartTLS.");
        }
        if (mode == TlsMode.NONE && !localTargets) {
            throw invalid("PLAIN_LDAP_REFUSED", "Without TLS the password would cross the network in clear text: the "
                + "TLS mode is LDAPS or StartTLS.");
        }
        if (c.newPassword() != null && utf8Length(c.newPassword()) > MAX_PASSWORD_BYTES) {
            throw invalid("PASSWORD_TOO_LONG", "The bind password may hold at most " + MAX_PASSWORD_BYTES + " bytes.");
        }
        List<String> urls = urls(c.urls(), mode, localTargets);
        String caPem = c.caCertificatePem() == null || c.caCertificatePem().isBlank() ? null
            : caBundle(c.caCertificatePem());
        if (caPem != null && mode == TlsMode.NONE) {
            throw invalid("CA_WITHOUT_TLS", "A CA certificate needs LDAPS or StartTLS.");
        }
        String bindDn = dn(c.bindDn(), "INVALID_BIND_DN", "The bind DN is not a distinguished name.");
        String userBase = dn(c.userSearchBase(), "INVALID_USER_SEARCH_BASE",
            "The user search base is not a distinguished name.");
        String userFilter = filter(c.userSearchFilter(), "INVALID_USER_SEARCH_FILTER",
            "The user search filter is an LDAP filter with {0} where the login name goes.", true);
        String attribute = blank(c.groupAttribute()) ? null : c.groupAttribute().strip();
        if (attribute != null && !attribute.matches("[A-Za-z][A-Za-z0-9-]{0,63}")) {
            throw invalid("INVALID_GROUP_ATTRIBUTE", "The group attribute is an attribute name such as memberOf.");
        }
        String groupBase = null;
        String groupFilter = null;
        if (!blank(c.groupSearchBase()) || !blank(c.groupSearchFilter())) {
            groupBase = dn(c.groupSearchBase(), "INVALID_GROUP_SEARCH", "A group search needs a base DN and a filter.");
            groupFilter = filter(c.groupSearchFilter(), "INVALID_GROUP_SEARCH",
                "The group search filter is an LDAP filter with {0} (the user's DN) or {1} (the login name).", false);
        }
        int connect = timeout(c.connectTimeoutMs(), DEFAULT_CONNECT_MS, 500, 30_000, "connect");
        int response = timeout(c.responseTimeoutMs(), DEFAULT_RESPONSE_MS, 500, 60_000, "response");
        return new Validated(c.enabled() == null || c.enabled(), urls, mode, caPem, bindDn, userBase, userFilter,
            attribute, groupBase, groupFilter, connect, response);
    }

    private static int utf8Length(char[] chars) {
        java.nio.ByteBuffer b = StandardCharsets.UTF_8.encode(java.nio.CharBuffer.wrap(chars));
        int n = b.remaining();
        if (b.hasArray()) {
            Arrays.fill(b.array(), (byte) 0);
        }
        return n;
    }

    private static List<String> urls(List<String> raw, TlsMode mode, boolean localTargets) {
        List<String> out = new ArrayList<>();
        for (String r : raw == null ? List.<String>of() : raw) {
            if (blank(r)) {
                continue;
            }
            LDAPURL url;
            try {
                url = new LDAPURL(r.strip());
            } catch (LDAPException e) {
                throw invalid("INVALID_URL", "A directory URL is ldaps://host:port or ldap://host:port.");
            }
            String host = url.getHost();
            if (host == null || host.isBlank() || url.baseDNProvided() || url.attributesProvided()
                || url.scopeProvided() || url.filterProvided()) {
                throw invalid("INVALID_URL", "A directory URL is ldaps://host:port or ldap://host:port, nothing more.");
            }
            boolean ldaps = "ldaps".equals(url.getScheme());
            if (mode == TlsMode.LDAPS && !ldaps || mode != TlsMode.LDAPS && ldaps) {
                throw invalid("URL_TLS_MISMATCH", "LDAPS takes ldaps:// URLs; StartTLS takes ldap:// URLs.");
            }
            boolean loopback = LdapAuthenticator.loopback(host);
            if (mode == TlsMode.NONE && !loopback) {
                throw invalid("PLAIN_LDAP_REFUSED", "Without TLS the password would cross the network in clear text: "
                    + "plain LDAP is allowed only to a loopback test directory.");
            }
            if (literalNotRoutable(host) && !(localTargets && loopback)) {
                throw invalid("TARGET_NOT_ALLOWED", "A directory URL names a routable server: not this machine, a "
                    + "link-local, unspecified or multicast address.");
            }
            if (!(localTargets && loopback) && !DirectoryConfig.DIRECTORY_PORTS.contains(url.getPort())) {
                throw invalid("PORT_NOT_ALLOWED", "A directory URL uses a directory port: 389 or 3268 (StartTLS), 636 or "
                    + "3269 (LDAPS).");
            }
            String normalised = url.getScheme() + "://" + (host.contains(":") && !host.startsWith("[") ? "[" + host
                + "]" : host) + ":" + url.getPort();
            if (!out.contains(normalised)) {
                out.add(normalised);
            }
        }
        if (out.isEmpty() || out.size() > MAX_URLS) {
            throw invalid("INVALID_URL", "Enter 1 to " + MAX_URLS + " directory URLs.");
        }
        return out;
    }

    /** A literal address (never a name: nothing is resolved here) that is loopback, link-local, unspecified or multicast. */
    private static boolean literalNotRoutable(String host) {
        String h = host.startsWith("[") && host.endsWith("]") ? host.substring(1, host.length() - 1) : host;
        if ("localhost".equalsIgnoreCase(h)) {
            return true;
        }
        if (io.rwsafe.control.privacy.Pseudonymiser.ipv4(h) == null && h.indexOf(':') < 0) {
            return false;
        }
        try {
            java.net.InetAddress a = java.net.InetAddress.getByName(h);
            return a.isLoopbackAddress() || a.isLinkLocalAddress() || a.isAnyLocalAddress() || a.isMulticastAddress();
        } catch (java.net.UnknownHostException e) {
            return true;
        }
    }

    /** The bundle re-encoded certificate by certificate (comments and keys dropped; a key in it is refused). */
    static String caBundle(String pem) {
        if (pem.length() > 65_536) {
            throw invalid("INVALID_CA_CERTIFICATE", "The CA bundle is larger than 64 KiB.");
        }
        if (pem.contains("PRIVATE KEY")) {
            throw invalid("CA_HOLDS_KEY", "The CA bundle holds a private key; paste only the CA certificate(s).");
        }
        List<X509Certificate> certs = certificates(pem);
        StringBuilder out = new StringBuilder();
        Base64.Encoder b64 = Base64.getMimeEncoder(64, new byte[] {'\n'});
        for (X509Certificate c : certs) {
            try {
                out.append("-----BEGIN CERTIFICATE-----\n").append(b64.encodeToString(c.getEncoded()))
                    .append("\n-----END CERTIFICATE-----\n");
            } catch (java.security.cert.CertificateEncodingException e) {
                throw invalid("INVALID_CA_CERTIFICATE", "A CA certificate cannot be encoded.");
            }
        }
        return out.toString();
    }

    /** The X.509 certificates of a PEM bundle (1 to 20); refused with {@code INVALID_CA_CERTIFICATE}. */
    public static List<X509Certificate> certificates(String pem) {
        try {
            Collection<? extends java.security.cert.Certificate> certs = CertificateFactory.getInstance("X.509")
                .generateCertificates(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
            List<X509Certificate> out = new ArrayList<>();
            for (var c : certs) {
                if (c instanceof X509Certificate x) {
                    out.add(x);
                }
            }
            if (out.isEmpty() || out.size() > MAX_CA_CERTIFICATES) {
                throw invalid("INVALID_CA_CERTIFICATE", "The CA bundle holds 1 to " + MAX_CA_CERTIFICATES
                    + " PEM certificates.");
            }
            return out;
        } catch (CertificateException e) {
            throw invalid("INVALID_CA_CERTIFICATE", "The CA bundle is not PEM certificates.");
        }
    }

    private static String dn(String raw, String reason, String message) {
        String s = raw == null ? "" : raw.strip();
        if (s.isEmpty() || s.length() > MAX_TEXT || s.chars().anyMatch(Character::isISOControl) || !DN.isValidDN(s)) {
            throw invalid(reason, message);
        }
        return s;
    }

    private static String filter(String raw, String reason, String message, boolean user) {
        String s = raw == null ? "" : raw.strip();
        boolean placeholder = user ? s.contains("{0}") : s.contains("{0}") || s.contains("{1}");
        if (s.isEmpty() || s.length() > MAX_TEXT || !placeholder || s.chars().anyMatch(Character::isISOControl)) {
            throw invalid(reason, message);
        }
        try {
            Filter.create(s.replace("{0}", "synthetic").replace("{1}", "synthetic"));
        } catch (LDAPException e) {
            throw invalid(reason, message);
        }
        return s;
    }

    private static int timeout(Integer raw, int fallback, int min, int max, String which) {
        int v = raw == null || raw == 0 ? fallback : raw;
        if (v < min || v > max) {
            throw invalid("INVALID_TIMEOUT", "The " + which + " timeout is " + min + " to " + max + " milliseconds.");
        }
        return v;
    }

    /**
     * The bindings as entered: a group's name (the value of its cn, never a distinguished name), unique in the
     * {@link io.rwsafe.policy.GroupNames} comparison form, and one or more known roles with the masked role alone.
     */
    static List<DirectorySettings.GroupRoles> groups(List<GroupBinding> raw) {
        List<GroupBinding> list = raw == null ? List.of() : raw;
        if (list.size() > MAX_GROUPS) {
            throw invalid("TOO_MANY_GROUPS", "At most " + MAX_GROUPS + " group bindings.");
        }
        Set<String> seen = new java.util.HashSet<>();
        List<DirectorySettings.GroupRoles> out = new ArrayList<>();
        for (GroupBinding b : list) {
            String name = b == null || b.group() == null ? "" : b.group().strip();
            String k = DirectoryConfig.nameKey(name);
            if (k == null) {
                throw invalid("INVALID_GROUP_NAME", "A group is named by its name (the value of its cn), 1 to 256 "
                    + "characters without a comma or '='; not by its distinguished name.");
            }
            if (!seen.add(k)) {
                throw invalid("DUPLICATE_GROUP", "A group is bound once; put all its roles on one line.");
            }
            out.add(new DirectorySettings.GroupRoles(name, LocalUsers.roles(b.roles())));
        }
        return out;
    }

    private static List<String> orderedRoles(Set<String> roles) {
        if (roles.contains(Roles.REPLAY_VIEWER)) {
            return List.of(Roles.REPLAY_VIEWER);
        }
        return Roles.ORDERED.stream().filter(roles::contains).toList();
    }

    private static DirectorySettings settings(Validated v, byte[] sealed, String ca, String actor, String kind,
                                              String reason, List<DirectorySettings.GroupRoles> groups) {
        return new DirectorySettings(0, null, actor, kind, reason, v.enabled(), v.urls(), v.tlsMode().stored(),
            ca != null ? ca : v.caPem(), v.bindDn(), sealed, v.userSearchBase(), v.userSearchFilter(),
            v.groupAttribute(), v.groupSearchBase(), v.groupSearchFilter(), v.connectTimeoutMs(),
            v.responseTimeoutMs(), groups);
    }

    /** The connection one authenticator uses: the stored (or entered) fields re-validated, and the opened password. */
    private DirectoryConfig config(DirectorySettings s, char[] password) {
        return config(s, password, localTargets);
    }

    static DirectoryConfig config(DirectorySettings s, char[] password, boolean localTargets) {
        if (password == null || password.length == 0) {
            throw invalid("BIND_PASSWORD_NOT_SET", "No bind password is set.");
        }
        TlsMode mode = TlsMode.ofStored(s.tlsMode());
        List<LDAPURL> urls = new ArrayList<>();
        for (String u : urls(s.urls(), mode, localTargets)) {
            try {
                urls.add(new LDAPURL(u));
            } catch (LDAPException e) {
                throw invalid("INVALID_URL", "A stored directory URL does not parse.");
            }
        }
        Map<String, Set<String>> roles = new HashMap<>();
        for (DirectorySettings.GroupRoles g : s.groupRoles()) {
            String k = DirectoryConfig.nameKey(g.group());
            if (k != null) {
                roles.computeIfAbsent(k, x -> new LinkedHashSet<>()).addAll(g.roles());
            }
        }
        Map<String, Set<String>> frozen = new HashMap<>();
        roles.forEach((k, r) -> frozen.put(k, Set.copyOf(r)));
        return new DirectoryConfig(urls, mode, s.caCertificatePem() == null ? List.of()
            : certificates(s.caCertificatePem()), s.bindDn(), password, s.userSearchBase(), s.userSearchFilter(),
            s.groupAttribute(), s.groupSearchBase(), s.groupSearchFilter(), s.connectTimeoutMs(),
            s.responseTimeoutMs(), frozen, localTargets);
    }

    private static boolean blank(String s) {
        return s == null || s.isBlank();
    }

    private String pseudonym(String loginName) {
        if (!keys.keyAvailable()) {
            throw new AccessRefusal(HttpStatus.SERVICE_UNAVAILABLE, "PRIVACY_KEY_UNAVAILABLE",
                "Directory changes are recorded under pseudonyms and the privacy key is missing; nothing changed.");
        }
        return pseudonymiser.user(loginName);
    }

    private static AuditContext audit(String actor, String action, String reason) {
        return new AuditContext(actor, action, reason, UUID.randomUUID().toString());
    }

    private static <T> T conflicts(java.util.function.Supplier<T> change) {
        try {
            return change.get();
        } catch (DirectorySettingsConflict e) {
            throw new AccessRefusal(HttpStatus.CONFLICT, e.reason(), e.getMessage());
        }
    }

    private static AccessRefusal invalid(String reason, String message) {
        return new AccessRefusal(HttpStatus.BAD_REQUEST, reason, message);
    }

    @Override
    public synchronized void destroy() {
        testRunner.shutdownNow();
        if (active.ldap() != null) {
            active.ldap().close();
        }
    }
}
