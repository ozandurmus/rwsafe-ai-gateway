package io.rwsafe.control.identity;

import io.rwsafe.control.config.ControlProperties;
import io.rwsafe.persistence.AuditContext;
import io.rwsafe.persistence.Database;
import io.rwsafe.persistence.LocalAccount;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * The local break-glass account (ARCHITECTURE.md §3.2): created at first start with a generated password that is written
 * once to a file readable by the process owner only, stored as a BCrypt hash, and never committed, logged or printed.
 * The creation is ledgered by the audit trigger.
 */
public final class BreakGlassAccounts implements Authenticator {

    public static final String BREAK_GLASS = "breakglass";
    private static final Logger LOG = LoggerFactory.getLogger(BreakGlassAccounts.class);
    private static final char[] ALPHABET =
        "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789".toCharArray();

    private final Database database;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
    /** Compared against when the account does not exist, so the answer takes as long either way. */
    private final String decoyHash = encoder.encode(UUID.randomUUID().toString());

    public BreakGlassAccounts(Database database) {
        this.database = database;
    }

    /** Creates the account unless it exists; true when a new initial password was written. */
    public boolean bootstrap(ControlProperties.BreakGlass config) {
        if (database.localAccounts().find(BREAK_GLASS).isPresent()) {
            return false;
        }
        Path file = config.initialPasswordFile();
        if (file == null) {
            throw new IllegalStateException("rwsafe.identity.break-glass.initial-password-file is required");
        }
        char[] password = generate(24);
        String hash = encoder.encode(new String(password));
        // Written beside the target first and moved into place only after the account row commits, so the file never
        // names a password the database does not hold (PR 12 review D-09).
        Path staged = file.resolveSibling(file.getFileName() + ".staged");
        writeOwnerOnly(staged, password);
        boolean created;
        try {
            created = database.localAccounts().createIfAbsent(
                new LocalAccount(BREAK_GLASS, hash, List.of(Roles.SECURITY_ADMIN), true),
                new AuditContext("system:bootstrap", "local_account.create", "BREAK_GLASS_FIRST_START",
                    UUID.randomUUID().toString()));
            if (created) {
                Files.move(staged, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
                LOG.info("break-glass account created; its initial password is in the configured file");
            }
        } catch (IOException e) {
            throw new UncheckedIOException("the break-glass initial password file cannot be moved into place", e);
        } finally {
            try {
                Files.deleteIfExists(staged);
            } catch (IOException e) {
                LOG.warn("the staged break-glass password file could not be removed");
            }
        }
        return created;
    }

    @Override
    public Optional<AuthenticatedUser> authenticate(String loginName, char[] password) {
        // The break-glass name is fixed and public, so answering other names at once reveals nothing (D-09).
        if (!BREAK_GLASS.equals(loginName)) {
            return Optional.empty();
        }
        Optional<LocalAccount> account = database.localAccounts().find(BREAK_GLASS);
        String hash = account.filter(LocalAccount::enabled).map(LocalAccount::passwordHash).orElse(decoyHash);
        boolean matches = encoder.matches(new String(password), hash);
        if (!matches || account.isEmpty() || !account.get().enabled()) {
            return Optional.empty();
        }
        return Optional.of(new AuthenticatedUser(loginName, Set.copyOf(account.get().roles()), "local"));
    }

    static char[] generate(int length) {
        SecureRandom random = new SecureRandom();
        char[] out = new char[length];
        for (int i = 0; i < length; i++) {
            out[i] = ALPHABET[random.nextInt(ALPHABET.length)];
        }
        return out;
    }

    private static void writeOwnerOnly(Path file, char[] password) {
        try {
            Path parent = file.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.deleteIfExists(file);
            try {
                Files.createFile(file, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
            } catch (UnsupportedOperationException e) {
                Files.createFile(file);
            }
            Files.writeString(file, new String(password) + "\n", StandardCharsets.UTF_8, StandardOpenOption.WRITE);
        } catch (IOException e) {
            throw new UncheckedIOException("the break-glass initial password file cannot be written", e);
        }
    }
}
