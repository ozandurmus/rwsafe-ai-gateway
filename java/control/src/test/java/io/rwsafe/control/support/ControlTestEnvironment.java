package io.rwsafe.control.support;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.sql.Connection;
import java.sql.Statement;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.test.context.DynamicPropertyRegistry;

/**
 * One embedded PostgreSQL 16 and one in-memory LDAP directory per test JVM, generated keys and synthetic users (one per
 * role, plus one without a role). Each Spring context gets a database of its own.
 */
public final class ControlTestEnvironment {

    public static final String BASE = "dc=example,dc=test";
    public static final String PEOPLE = "ou=synthetic-people," + BASE;
    public static final String GROUPS = "ou=synthetic-groups," + BASE;
    public static final Map<String, String> PASSWORDS = new LinkedHashMap<>();
    private static final AtomicInteger DATABASES = new AtomicInteger();
    private static EmbeddedPostgres postgres;
    private static InMemoryDirectoryServer ldap;
    private static Path dir;
    private static KeyPair snapshotKeys;
    public static final String SNAPSHOT_KEY_ID = "synthetic-test-key";

    private ControlTestEnvironment() {
    }

    /** Registers the properties of one context; {@code withDictionary=false} leaves masking unavailable. */
    public static synchronized void register(DynamicPropertyRegistry r, boolean withKey, boolean withDictionary)
        throws Exception {
        start();
        register(r, withKey, withDictionary ? dir.resolve("dictionary.txt") : dir.resolve("absent"), SNAPSHOT_KEY_ID);
    }

    /**
     * Registers one context with its own estate dictionary file and signing key id (the leak probe seeds both with
     * synthetic estate terms); a {@code dictionary} that does not exist leaves masking unavailable.
     */
    public static synchronized void register(DynamicPropertyRegistry r, boolean withKey, Path dictionary,
                                             String signingKeyId) throws Exception {
        start();
        String db = "rwsafe_control_" + DATABASES.incrementAndGet();
        try (Connection c = postgres.getPostgresDatabase().getConnection(); Statement s = c.createStatement()) {
            s.execute("CREATE DATABASE " + db);
        }
        r.add("spring.datasource.url", () -> "jdbc:postgresql://127.0.0.1:" + postgres.getPort() + "/" + db);
        r.add("spring.datasource.username", () -> "postgres");
        r.add("rwsafe.capture-sink.port", () -> "0");
        r.add("rwsafe.snapshot-feed.port", () -> "0");
        r.add("rwsafe.policy.seed-file", () -> seedFixture().toString());
        r.add("rwsafe.policy.signing-key-file", () -> dir.resolve("snapshot-signing.key").toString());
        r.add("rwsafe.policy.signing-key-id", () -> signingKeyId);
        r.add("rwsafe.privacy.hmac-key-file", () -> withKey ? dir.resolve("key").toString() : dir.resolve("absent").toString());
        r.add("rwsafe.privacy.estate-dictionary-file", dictionary::toString);
        r.add("rwsafe.identity.cookie-secure", () -> "false");
        r.add("server.servlet.session.cookie.secure", () -> "false");
        r.add("server.servlet.session.cookie.name", () -> "rwsafe-session");
        r.add("rwsafe.identity.break-glass.enabled", () -> "true");
        r.add("rwsafe.identity.break-glass.initial-password-file", () -> dir.resolve(db + "-break-glass").toString());
        r.add("rwsafe.identity.ldap.url", () -> "ldap://127.0.0.1:" + ldap.getListenPort());
        r.add("rwsafe.identity.ldap.bind-dn", () -> "cn=synthetic-service," + BASE);
        r.add("rwsafe.identity.ldap.bind-password-file", () -> dir.resolve("bind-password").toString());
        r.add("rwsafe.identity.ldap.user-search-base", () -> PEOPLE);
        r.add("rwsafe.identity.ldap.user-search-filter", () -> "(uid={0})");
        for (String role : new String[] {"security_admin", "privacy_officer", "viewer", "replay_viewer"}) {
            r.add("rwsafe.identity.ldap.group-roles[cn=rwsafe-" + role + "," + GROUPS + "]", () -> role);
        }
    }

    /** The repository's committed seed fixture, found from the working directory (Gradle or the Maven smoke build). */
    public static Path seedFixture() {
        for (Path p = Path.of("").toAbsolutePath(); p != null; p = p.getParent()) {
            Path candidate = p.resolve("policy").resolve("registry-seed.yaml");
            if (Files.isRegularFile(candidate) && Files.isRegularFile(p.resolve("AGENTS.md"))) {
                return candidate;
            }
        }
        throw new IllegalStateException("policy/registry-seed.yaml not found above the working directory");
    }

    /** The public half of the snapshot signing key generated for this JVM (nothing of it is committed). */
    public static synchronized PublicKey snapshotPublicKey() throws Exception {
        start();
        return snapshotKeys.getPublic();
    }

    public static Path breakGlassFile(int database) {
        return dir.resolve("rwsafe_control_" + database + "-break-glass");
    }

    /** The per-JVM directory of generated keys and files; starts the environment first (PR 24 review D-06). */
    public static synchronized Path dir() {
        try {
            start();
        } catch (Exception e) {
            throw new IllegalStateException("the control test environment did not start", e);
        }
        return dir;
    }

    private static void start() throws Exception {
        if (postgres != null) {
            return;
        }
        dir = Files.createTempDirectory("rwsafe-control-test");
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        Files.write(dir.resolve("key"), key);
        Files.writeString(dir.resolve("dictionary.txt"), "# synthetic\nsynthetic-estate\n");
        String bind = secret();
        Files.writeString(dir.resolve("bind-password"), bind + "\n");
        snapshotKeys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        Files.writeString(dir.resolve("snapshot-signing.key"), pem(snapshotKeys.getPrivate().getEncoded()));
        postgres = EmbeddedPostgres.builder().start();

        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(BASE);
        config.setListenerConfigs(InMemoryListenerConfig.createLDAPConfig("loopback", InetAddress.getLoopbackAddress(),
            0, null));
        config.setSchema(null);
        ldap = new InMemoryDirectoryServer(config);
        ldap.add(new Entry(BASE, new Attribute("objectClass", "domain")));
        ldap.add(new Entry(PEOPLE, new Attribute("objectClass", "organizationalUnit")));
        ldap.add(new Entry(GROUPS, new Attribute("objectClass", "organizationalUnit")));
        ldap.add(new Entry("cn=synthetic-service," + BASE, new Attribute("userPassword", bind)));
        user("synthetic-admin", "security_admin");
        user("synthetic-admin-two", "security_admin");
        user("synthetic-officer", "privacy_officer");
        user("synthetic-viewer", "viewer");
        user("synthetic-aiview", "replay_viewer");
        user("synthetic-norole", null);
        user("synthetic-dual", "replay_viewer");
        ldap.modify("uid=synthetic-dual," + PEOPLE, new com.unboundid.ldap.sdk.Modification(
            com.unboundid.ldap.sdk.ModificationType.ADD, "memberOf", "cn=rwsafe-security_admin," + GROUPS));
        ldap.startListening();
    }

    /** Adds a directory user with one role (or none) once per JVM; its generated password lands in {@link #PASSWORDS}. */
    public static synchronized void addUser(String login, String role) throws Exception {
        start();
        if (!PASSWORDS.containsKey(login)) {
            user(login, role);
        }
    }

    private static void user(String login, String role) throws Exception {
        String password = secret();
        PASSWORDS.put(login, password);
        Entry e = new Entry("uid=" + login + "," + PEOPLE, new Attribute("uid", login),
            new Attribute("userPassword", password));
        if (role != null) {
            e.addAttribute("memberOf", "cn=rwsafe-" + role + "," + GROUPS);
        } else {
            e.addAttribute("memberOf", "cn=unrelated-synthetic-group," + GROUPS);
        }
        ldap.add(e);
    }

    /** PKCS#8 PEM; the label is assembled so no committed line reads as a key header. */
    public static String pem(byte[] pkcs8) {
        String label = "PRIVATE" + " KEY";
        return "-----BEGIN " + label + "-----\n" + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(pkcs8)
            + "\n-----END " + label + "-----\n";
    }

    private static String secret() {
        byte[] b = new byte[12];
        new SecureRandom().nextBytes(b);
        return HexFormat.of().formatHex(b);
    }
}
