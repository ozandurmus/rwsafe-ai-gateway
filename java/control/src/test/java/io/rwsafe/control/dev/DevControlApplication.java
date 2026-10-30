package io.rwsafe.control.dev;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import io.rwsafe.control.ControlApplication;
import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import org.springframework.boot.SpringApplication;

/**
 * Development runner ({@code ./java/gradlew -p java :control:runDev}, LOCAL_RUN.md): an embedded PostgreSQL 16 whose
 * data stays under {@code build/dev/postgres}, a development privacy key and an empty estate dictionary generated on first
 * start, an in-memory LDAP directory with three synthetic users (one per role) on loopback, the break-glass account, and
 * synthetic sample events. Every credential is generated at start and written to {@code build/dev/credentials.txt}
 * (owner-only); nothing is printed and nothing is committed. Test classpath only: none of this reaches an image.
 */
public final class DevControlApplication {

    static final String BASE = "dc=example,dc=test";
    static final String PEOPLE = "ou=synthetic-people," + BASE;
    static final String GROUPS = "ou=synthetic-groups," + BASE;

    private record DevUser(String login, String role) {
    }

    private static final List<DevUser> USERS = List.of(
        new DevUser("synthetic-admin", "security_admin"),
        new DevUser("synthetic-viewer", "viewer"),
        new DevUser("synthetic-aiview", "replay_viewer"));

    private DevControlApplication() {
    }

    public static void main(String[] args) throws Exception {
        Path dir = Path.of(System.getProperty("rwsafe.dev.dir", "build/dev")).toAbsolutePath();
        Files.createDirectories(dir);
        Path key = dir.resolve("privacy-hmac.key");
        if (!Files.exists(key)) {
            byte[] bytes = new byte[32];
            new SecureRandom().nextBytes(bytes);
            ownerOnly(key, bytes);
        }
        Path dictionary = dir.resolve("estate-dictionary.txt");
        if (!Files.exists(dictionary)) {
            Files.writeString(dictionary, "# Development estate dictionary: synthetic terms only, one per line.\n"
                + "synthetic-estate-term\n");
        }
        int pgPort = Integer.parseInt(env("RWSAFE_DEV_PG_PORT", "54329"));
        EmbeddedPostgres postgres = EmbeddedPostgres.builder()
            .setDataDirectory(dir.resolve("postgres"))
            .setCleanDataDirectory(false)
            .setPort(pgPort)
            .start();

        StringBuilder credentials = new StringBuilder("# rwsafe development credentials, generated at start (synthetic "
            + "accounts only; never commit, never share).\n");
        String bindPassword = password();
        Path bindPasswordFile = dir.resolve("ldap-bind-password");
        ownerOnly(bindPasswordFile, bindPassword.getBytes(StandardCharsets.UTF_8));
        InMemoryDirectoryServer ldap = directory(bindPassword, credentials);
        Path breakGlassFile = dir.resolve("break-glass-initial-password");
        credentials.append("breakglass  <see ").append(breakGlassFile.getFileName())
            .append(", written at first start>  security_admin (local)\n");
        ownerOnly(dir.resolve("credentials.txt"), credentials.toString().getBytes(StandardCharsets.UTF_8));

        set("spring.datasource.url", "jdbc:postgresql://127.0.0.1:" + pgPort + "/postgres");
        set("spring.datasource.username", "postgres");
        set("rwsafe.privacy.hmac-key-file", key.toString());
        set("rwsafe.privacy.estate-dictionary-file", dictionary.toString());
        set("rwsafe.identity.cookie-secure", "false");
        set("server.servlet.session.cookie.secure", "false");
        set("server.servlet.session.cookie.name", "rwsafe-session");
        set("rwsafe.identity.break-glass.enabled", "true");
        set("rwsafe.identity.break-glass.initial-password-file", breakGlassFile.toString());
        set("rwsafe.identity.ldap.url", "ldap://127.0.0.1:" + ldap.getListenPort());
        set("rwsafe.identity.ldap.bind-dn", "cn=synthetic-service," + BASE);
        set("rwsafe.identity.ldap.bind-password-file", bindPasswordFile.toString());
        set("rwsafe.identity.ldap.user-search-base", PEOPLE);
        set("rwsafe.identity.ldap.user-search-filter", "(uid={0})");
        for (DevUser u : USERS) {
            set("rwsafe.identity.ldap.group-roles[cn=rwsafe-" + u.role() + "," + GROUPS + "]", u.role());
        }
        set("rwsafe.sample.events", env("RWSAFE_SAMPLE_EVENTS", "6000"));

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            ldap.shutDown(true);
            try {
                postgres.close();
            } catch (IOException e) {
                // the process is ending
            }
        }));
        SpringApplication app = new SpringApplication(ControlApplication.class);
        app.setAdditionalProfiles("dev");
        app.run(args);
    }

    private static InMemoryDirectoryServer directory(String bindPassword, StringBuilder credentials) throws Exception {
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(BASE);
        config.setListenerConfigs(InMemoryListenerConfig.createLDAPConfig("loopback",
            InetAddress.getLoopbackAddress(), 0, null));
        config.setSchema(null);
        InMemoryDirectoryServer server = new InMemoryDirectoryServer(config);
        server.add(new Entry(BASE, new Attribute("objectClass", "top", "domain"), new Attribute("dc", "example")));
        server.add(new Entry(PEOPLE, new Attribute("objectClass", "organizationalUnit")));
        server.add(new Entry(GROUPS, new Attribute("objectClass", "organizationalUnit")));
        server.add(new Entry("cn=synthetic-service," + BASE, new Attribute("objectClass", "person"),
            new Attribute("userPassword", bindPassword)));
        List<String> lines = new ArrayList<>();
        for (DevUser u : USERS) {
            String pw = password();
            server.add(new Entry("uid=" + u.login() + "," + PEOPLE, new Attribute("objectClass", "inetOrgPerson"),
                new Attribute("uid", u.login()), new Attribute("userPassword", pw),
                new Attribute("memberOf", "cn=rwsafe-" + u.role() + "," + GROUPS)));
            lines.add(u.login() + "  " + pw + "  " + u.role() + " (LDAP" + (u.role().equals("replay_viewer")
                ? ", masked session)" : ")"));
        }
        lines.forEach(l -> credentials.append(l).append('\n'));
        server.startListening();
        return server;
    }

    private static String password() {
        byte[] bytes = new byte[12];
        new SecureRandom().nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }

    private static void ownerOnly(Path file, byte[] content) throws IOException {
        Files.deleteIfExists(file);
        Files.createFile(file, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        Files.write(file, content);
    }

    private static void set(String name, String value) {
        if (System.getProperty(name) == null) {
            System.setProperty(name, value);
        }
    }

    private static String env(String name, String fallback) {
        String v = System.getenv(name);
        return v == null || v.isBlank() ? fallback : v;
    }
}
