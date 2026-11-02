package io.rwsafe.control.identity;

import io.rwsafe.control.config.ControlProperties;
import io.rwsafe.control.privacy.IdentifierCheck;
import io.rwsafe.control.privacy.Masking;
import io.rwsafe.control.privacy.PrivacyKeys;
import io.rwsafe.control.privacy.Pseudonymiser;
import io.rwsafe.persistence.AuditContext;
import io.rwsafe.persistence.Database;
import io.rwsafe.persistence.LocalAccount;
import io.rwsafe.persistence.LocalUser;
import io.rwsafe.persistence.LocalUserConflict;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * Administration -> Access part 1 (PO decision Q-47, decision 1.1): local users and the sessions an administrator ends.
 *
 * <ul>
 *   <li>A {@code security_admin} creates a local user, changes its roles, disables, enables it and resets its password.
 *       The control plane generates the initial and every reset password (as for the break-glass account), returns it
 *       once to the administrator and stores only its BCrypt hash; the user must replace it at the next sign-in.</li>
 *   <li>An administrator never disables, demotes or resets themself, and no change leaves the product without an
 *       enabled {@code security_admin} (local users, plus the break-glass account when break-glass sign-in is on).</li>
 *   <li>Every change carries the administrator's reason and is written to the audit ledger by the table trigger, with
 *       the administrator's pseudonym as actor and the user's pseudonym as the row; login names, display names and
 *       passwords are never logged.</li>
 * </ul>
 */
@Service
public class LocalUsers {

    /** The break-glass cost (BreakGlassAccounts), shared with the authenticator. */
    static final BCryptPasswordEncoder ENCODER = new BCryptPasswordEncoder(12);
    /** The V11 table's own check: lower-case letters, digits, {@code .}, {@code _} and {@code -}, 3 to 32. */
    public static final Pattern LOGIN_NAME = Pattern.compile("[a-z][a-z0-9._-]{2,31}");
    public static final int GENERATED_LENGTH = 20;
    public static final int MIN_PASSWORD = 14;
    public static final int MAX_PASSWORD = 128;
    /** BCrypt reads 72 bytes; a longer password would be cut silently, so it is refused. */
    public static final int MAX_PASSWORD_BYTES = 72;
    public static final int MIN_DISTINCT = 6;
    public static final int MAX_REASON = 500;
    public static final int MAX_DISPLAY_NAME = 128;

    /** A created user or a reset: the one-time password is in this object only, never stored or logged. */
    public record Issued(LocalUser user, char[] oneTimePassword) {

        @Override
        public String toString() {
            return "Issued[" + user + "]";
        }
    }

    private final Database database;
    private final Pseudonymiser pseudonymiser;
    private final PrivacyKeys keys;
    private final Masking masking;
    private final IdentifierCheck identifiers;
    private final ActiveSessions sessions;
    private final boolean breakGlassEnabled;

    public LocalUsers(Database database, Pseudonymiser pseudonymiser, PrivacyKeys keys, Masking masking,
                      IdentifierCheck identifiers, ActiveSessions sessions, ControlProperties properties) {
        this.database = database;
        this.pseudonymiser = pseudonymiser;
        this.keys = keys;
        this.masking = masking;
        this.identifiers = identifiers;
        this.sessions = sessions;
        this.breakGlassEnabled = properties.identity().breakGlass().enabled();
    }

    public List<LocalUser> list() {
        return database.localUsers().list();
    }

    /** The break-glass accounts, listed read-only. */
    public List<LocalAccount> breakGlassAccounts() {
        return database.localAccounts().list();
    }

    public boolean breakGlassEnabled() {
        return breakGlassEnabled;
    }

    public int enabledAdmins() {
        return database.localUsers().enabledAdmins(breakGlassEnabled);
    }

    public Issued create(String actorLogin, String loginName, String displayName, Collection<String> roles,
                         String reason) {
        String actor = pseudonym(actorLogin);
        String name = loginName(loginName);
        String display = displayName(displayName);
        List<String> granted = roles(roles);
        String why = reason(reason);
        char[] password = BreakGlassAccounts.generate(GENERATED_LENGTH);
        LocalUser created = conflicts(() -> database.localUsers().create(new LocalUser(name, pseudonym(name), display,
            ENCODER.encode(new String(password)), granted, true, true, null, null, null),
            audit(actor, "local_user.create", why)));
        return new Issued(created, password);
    }

    public LocalUser changeRoles(String actorLogin, String subject, Collection<String> roles, String reason) {
        String actor = pseudonym(actorLogin);
        LocalUser target = bySubject(subject);
        List<String> granted = roles(roles);
        String why = reason(reason);
        if (self(actorLogin, target) && !granted.contains(Roles.SECURITY_ADMIN)) {
            throw new AccessRefusal(HttpStatus.CONFLICT, "SELF_DEMOTION_REFUSED",
                "You cannot remove your own security administrator role.");
        }
        LocalUser changed = conflicts(() -> database.localUsers().update(target.loginName(), u -> with(u, granted,
            u.enabled(), u.passwordHash(), u.mustChangePassword(), u.passwordChangedAt()), breakGlassEnabled,
            audit(actor, "local_user.roles_change", why)));
        sessions.endAll(target.loginName(), LocalUserAuthenticator.SOURCE);
        return changed;
    }

    public LocalUser setEnabled(String actorLogin, String subject, boolean enabled, String reason) {
        String actor = pseudonym(actorLogin);
        LocalUser target = bySubject(subject);
        String why = reason(reason);
        if (!enabled && self(actorLogin, target)) {
            throw new AccessRefusal(HttpStatus.CONFLICT, "SELF_DISABLE_REFUSED", "You cannot disable your own account.");
        }
        LocalUser changed = conflicts(() -> database.localUsers().update(target.loginName(), u -> with(u, u.roles(),
            enabled, u.passwordHash(), u.mustChangePassword(), u.passwordChangedAt()), breakGlassEnabled,
            audit(actor, enabled ? "local_user.enable" : "local_user.disable", why)));
        if (!enabled) {
            sessions.endAll(target.loginName(), LocalUserAuthenticator.SOURCE);
        }
        return changed;
    }

    public Issued resetPassword(String actorLogin, String subject, String reason) {
        String actor = pseudonym(actorLogin);
        LocalUser target = bySubject(subject);
        String why = reason(reason);
        if (self(actorLogin, target)) {
            throw new AccessRefusal(HttpStatus.CONFLICT, "SELF_RESET_REFUSED",
                "Change your own password from the user menu instead.");
        }
        char[] password = BreakGlassAccounts.generate(GENERATED_LENGTH);
        String hash = ENCODER.encode(new String(password));
        LocalUser changed = conflicts(() -> database.localUsers().update(target.loginName(), u -> with(u, u.roles(),
            u.enabled(), hash, true, u.passwordChangedAt()), breakGlassEnabled,
            audit(actor, "local_user.password_reset", why)));
        sessions.endAll(target.loginName(), LocalUserAuthenticator.SOURCE);
        return new Issued(changed, password);
    }

    /**
     * The signed-in local user replaces their password (after a generated one, or at any time); false when the current
     * password is wrong. The caller counts a false answer in the login throttle.
     */
    public boolean changeOwnPassword(String loginName, char[] current, char[] next) {
        LocalUser user = database.localUsers().find(loginName.toLowerCase(Locale.ROOT))
            .filter(LocalUser::enabled)
            .orElseThrow(() -> new AccessRefusal(HttpStatus.CONFLICT, "NOT_A_LOCAL_USER",
                "Only a local user changes the password here; directory passwords are changed in the directory."));
        String actor = pseudonym(user.loginName());
        if (!ENCODER.matches(new String(current), user.passwordHash())) {
            return false;
        }
        checkNewPassword(user.loginName(), current, next);
        String hash = ENCODER.encode(new String(next));
        conflicts(() -> database.localUsers().update(user.loginName(), u -> with(u, u.roles(), u.enabled(), hash, false,
            Instant.now()), breakGlassEnabled, audit(actor, "local_user.password_change", "OWN_PASSWORD_CHANGE")));
        return true;
    }

    /** Ends another person's session with a reason; the end is ledgered under both pseudonyms. */
    public void endSession(String actorLogin, String handle, String currentHandle, String reason) {
        String actor = pseudonym(actorLogin);
        String why = reason(reason);
        ActiveSessions.Entry entry = sessions.find(handle).orElseThrow(() -> new AccessRefusal(HttpStatus.NOT_FOUND,
            "SESSION_NOT_FOUND", "No such session is open (it may have ended already)."));
        if (handle.equals(currentHandle)) {
            throw new AccessRefusal(HttpStatus.CONFLICT, "SELF_SESSION_REFUSED",
                "This is your own session; sign out instead.");
        }
        database.localUsers().recordSessionEnd(pseudonym(entry.loginName()), actor, entry.source(),
            audit(actor, "session.end", why));
        sessions.end(handle);
    }

    /** A new password: 14 to 128 characters within 72 bytes, six different characters, not the login name, not the old. */
    static void checkNewPassword(String loginName, char[] current, char[] next) {
        String p = new String(next);
        if (p.codePointCount(0, p.length()) < MIN_PASSWORD) {
            throw invalid("PASSWORD_TOO_SHORT", "The new password needs at least " + MIN_PASSWORD + " characters.");
        }
        if (p.length() > MAX_PASSWORD || p.getBytes(StandardCharsets.UTF_8).length > MAX_PASSWORD_BYTES) {
            throw invalid("PASSWORD_TOO_LONG", "The new password may hold at most " + MAX_PASSWORD_BYTES + " bytes.");
        }
        if (p.chars().anyMatch(Character::isISOControl)) {
            throw invalid("PASSWORD_TOO_SIMPLE", "The new password may not contain control characters.");
        }
        if (p.codePoints().distinct().count() < MIN_DISTINCT) {
            throw invalid("PASSWORD_TOO_SIMPLE", "The new password needs at least " + MIN_DISTINCT
                + " different characters.");
        }
        if (p.toLowerCase(Locale.ROOT).contains(loginName.toLowerCase(Locale.ROOT))) {
            throw invalid("PASSWORD_CONTAINS_LOGIN", "The new password may not contain the login name.");
        }
        if (p.equals(new String(current))) {
            throw invalid("PASSWORD_UNCHANGED", "The new password must differ from the current one.");
        }
    }

    private LocalUser bySubject(String subject) {
        if (subject == null || !subject.matches("USR-[0-9a-f]{10}")) {
            throw new AccessRefusal(HttpStatus.NOT_FOUND, "LOCAL_USER_NOT_FOUND", "No local user has this pseudonym.");
        }
        return list().stream().filter(u -> u.subjectFingerprint().equals(subject)).findFirst()
            .orElseThrow(() -> new AccessRefusal(HttpStatus.NOT_FOUND, "LOCAL_USER_NOT_FOUND",
                "No local user has this pseudonym."));
    }

    private static boolean self(String actorLogin, LocalUser target) {
        return actorLogin != null && actorLogin.toLowerCase(Locale.ROOT).equals(target.loginName());
    }

    static String loginName(String raw) {
        String name = raw == null ? "" : raw.strip().toLowerCase(Locale.ROOT);
        if (!LOGIN_NAME.matcher(name).matches() || name.equals(BreakGlassAccounts.BREAK_GLASS)) {
            throw invalid("INVALID_USER_LOGIN", "A login name is 3 to 32 lower-case letters, digits, '.', '_' or '-', "
                + "starts with a letter and is not the break-glass name.");
        }
        return name;
    }

    static String displayName(String raw) {
        String name = raw == null ? "" : raw.strip();
        if (name.isEmpty() || name.length() > MAX_DISPLAY_NAME || name.chars().anyMatch(Character::isISOControl)) {
            throw invalid("INVALID_DISPLAY_NAME", "A display name is 1 to " + MAX_DISPLAY_NAME
                + " characters on one line.");
        }
        return name;
    }

    /** Known roles, at least one, the masked role alone (MASKING_AND_PRIVACY B1), in display order. */
    static List<String> roles(Collection<String> raw) {
        Set<String> set = raw == null ? Set.of() : new LinkedHashSet<>(raw);
        if (set.isEmpty() || !Roles.ALL.containsAll(set) || (set.contains(Roles.REPLAY_VIEWER) && set.size() > 1)) {
            throw invalid("INVALID_ROLES", "Choose one or more known roles; the masked viewer role stands alone.");
        }
        List<String> ordered = new ArrayList<>();
        for (String r : Roles.ORDERED) {
            if (set.contains(r)) {
                ordered.add(r);
            }
        }
        return ordered;
    }

    /**
     * The administrator's reason, written to the ledger as it is (as a policy retirement's): 1 to 500 characters on one
     * line, no estate term and no identifier (nothing the detectors or the free-text masking layers would change), since
     * every unmasked reader of the ledger and the SIEM reads it. The refusal never echoes the text.
     */
    String reason(String raw) {
        String reason = raw == null ? "" : raw.strip();
        if (reason.isEmpty() || reason.length() > MAX_REASON || reason.chars().anyMatch(Character::isISOControl)) {
            throw invalid("INVALID_REASON", "A reason of 1 to " + MAX_REASON + " characters on one line is required.");
        }
        if (!masking.available()) {
            throw new AccessRefusal(HttpStatus.SERVICE_UNAVAILABLE, "MASKING_UNAVAILABLE",
                "The reason cannot be checked for identifiers without the masking key and dictionary; nothing changed.");
        }
        if (identifiers.namesEstate(reason)) {
            throw invalid("ESTATE_NAME_REFUSED", "The reason names the estate; describe it without that name.");
        }
        if (IdentifierCheck.identifierShape(reason) || !masking.masker().maskFreeText(reason).equals(reason)) {
            throw invalid("REASON_HOLDS_IDENTIFIER", "The reason holds an identifier (an address, a number or a name the "
                + "masking rules recognise); describe the reason without it.");
        }
        return reason;
    }

    private String pseudonym(String loginName) {
        if (!keys.keyAvailable()) {
            throw new AccessRefusal(HttpStatus.SERVICE_UNAVAILABLE, "PRIVACY_KEY_UNAVAILABLE",
                "Access changes are recorded under pseudonyms and the privacy key is missing; nothing changed.");
        }
        return pseudonymiser.user(loginName);
    }

    private static AuditContext audit(String actor, String action, String reason) {
        return new AuditContext(actor, action, reason, UUID.randomUUID().toString());
    }

    private static LocalUser with(LocalUser u, List<String> roles, boolean enabled, String hash, boolean mustChange,
                                  Instant passwordChangedAt) {
        return new LocalUser(u.loginName(), u.subjectFingerprint(), u.displayName(), hash, roles, enabled, mustChange,
            u.createdAt(), u.updatedAt(), passwordChangedAt);
    }

    private static <T> T conflicts(java.util.function.Supplier<T> change) {
        try {
            return change.get();
        } catch (LocalUserConflict e) {
            throw new AccessRefusal(HttpStatus.CONFLICT, e.reason(), e.getMessage());
        }
    }

    private static AccessRefusal invalid(String reason, String message) {
        return new AccessRefusal(HttpStatus.BAD_REQUEST, reason, message);
    }
}
