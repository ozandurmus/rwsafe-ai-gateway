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
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * Administration -> Access part 1 (PO decision Q-47, decision 1.1): local users and the sessions an administrator ends.
 *
 * <ul>
 *   <li>A {@code security_admin} creates a local user, changes its roles, disables, enables it and resets its password.
 *       The control plane generates the initial and every reset password (as for the break-glass account), returns it
 *       once to the administrator and stores only its BCrypt hash; the user must replace it at the next sign-in.</li>
 *   <li>A local administrator never changes their own roles, disables or resets themself (PR 48 review D-01: "self" is
 *       the same login name signed in as a local user), and no change leaves the product without an enabled
 *       {@code security_admin} (local users, plus the break-glass account when break-glass sign-in is on).</li>
 *   <li>Every change carries the administrator's reason and is written to the audit ledger by the table trigger, with
 *       the administrator's pseudonym as actor and the user's pseudonym as the row; login names, display names and
 *       passwords are never logged, and a reason naming a person this screen knows is refused (D-05).</li>
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
    /** A name token this long matches a reason word that starts with it (a Turkish suffix); shorter ones match whole. */
    static final int PREFIX_TOKEN = 4;
    private static final Pattern NON_WORD = Pattern.compile("[^a-z0-9]+");

    /** A created user or a reset: the one-time password is in this object only, never stored or logged. */
    public record Issued(LocalUser user, char[] oneTimePassword) {

        @Override
        public String toString() {
            return "Issued[" + user + "]";
        }
    }

    /** Who acts: the session's login name and its source ({@code ldap}, {@code local}, {@code local_user}). */
    public record Actor(String loginName, String source) {

        public static Actor of(Authentication auth) {
            String source = auth.getDetails() instanceof AuthController.SessionDetails d ? d.source() : null;
            return new Actor(auth.getName(), source);
        }

        /** The same person as {@code target}: a local user's session with its login name (D-01). */
        boolean is(LocalUser target) {
            return LocalUserAuthenticator.SOURCE.equals(source) && loginName != null
                && loginName.toLowerCase(Locale.ROOT).equals(target.loginName());
        }

        @Override
        public String toString() {
            return "Actor[" + source + "]";
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

    public Issued create(Actor by, String loginName, String displayName, Collection<String> roles, String reason) {
        String actor = pseudonym(by.loginName());
        String name = loginName(loginName);
        String display = displayName(displayName);
        List<String> granted = roles(roles);
        String why = reason(reason, by, name, display);
        char[] password = BreakGlassAccounts.generate(GENERATED_LENGTH);
        LocalUser created = conflicts(() -> database.localUsers().create(new LocalUser(name, pseudonym(name), display,
            ENCODER.encode(new String(password)), granted, true, true, null, null, null),
            audit(actor, "local_user.create", why)));
        return new Issued(created, password);
    }

    public LocalUser changeRoles(Actor by, String subject, Collection<String> roles, String reason) {
        String actor = pseudonym(by.loginName());
        LocalUser target = bySubject(subject);
        List<String> granted = roles(roles);
        // D-01: no role change on oneself at all, neither a demotion nor a self-granted privacy officer role.
        if (by.is(target)) {
            throw new AccessRefusal(HttpStatus.CONFLICT, "SELF_ROLES_CHANGE_REFUSED",
                "You cannot change your own roles; another security administrator does it.");
        }
        String why = reason(reason, by, target.loginName(), target.displayName());
        LocalUser changed = conflicts(() -> database.localUsers().update(target.loginName(), u -> with(u, granted,
            u.enabled(), u.passwordHash(), u.mustChangePassword(), u.passwordChangedAt()), breakGlassEnabled,
            audit(actor, "local_user.roles_change", why)));
        sessions.endAll(target.loginName(), LocalUserAuthenticator.SOURCE);
        return changed;
    }

    public LocalUser setEnabled(Actor by, String subject, boolean enabled, String reason) {
        String actor = pseudonym(by.loginName());
        LocalUser target = bySubject(subject);
        if (!enabled && by.is(target)) {
            throw new AccessRefusal(HttpStatus.CONFLICT, "SELF_DISABLE_REFUSED", "You cannot disable your own account.");
        }
        String why = reason(reason, by, target.loginName(), target.displayName());
        LocalUser changed = conflicts(() -> database.localUsers().update(target.loginName(), u -> with(u, u.roles(),
            enabled, u.passwordHash(), u.mustChangePassword(), u.passwordChangedAt()), breakGlassEnabled,
            audit(actor, enabled ? "local_user.enable" : "local_user.disable", why)));
        if (!enabled) {
            sessions.endAll(target.loginName(), LocalUserAuthenticator.SOURCE);
        }
        return changed;
    }

    public Issued resetPassword(Actor by, String subject, String reason) {
        String actor = pseudonym(by.loginName());
        LocalUser target = bySubject(subject);
        if (by.is(target)) {
            throw new AccessRefusal(HttpStatus.CONFLICT, "SELF_RESET_REFUSED",
                "Change your own password from the user menu instead.");
        }
        String why = reason(reason, by, target.loginName(), target.displayName());
        char[] password = BreakGlassAccounts.generate(GENERATED_LENGTH);
        String hash = ENCODER.encode(new String(password));
        LocalUser changed = conflicts(() -> database.localUsers().update(target.loginName(), u -> with(u, u.roles(),
            u.enabled(), hash, true, u.passwordChangedAt()), breakGlassEnabled,
            audit(actor, "local_user.password_reset", why)));
        sessions.endAll(target.loginName(), LocalUserAuthenticator.SOURCE);
        return new Issued(changed, password);
    }

    /**
     * The signed-in local user replaces their password (after a generated one, or at any time) and gets the stored user
     * back; empty when the current password is wrong (the caller counts that in the login throttle). Inside the update
     * the row must still be enabled and hold the hash the current password was checked against, so a reset or a
     * disable that lands meanwhile is never overwritten (PR 48 review D-02).
     */
    public Optional<LocalUser> changeOwnPassword(String loginName, char[] current, char[] next) {
        LocalUser user = database.localUsers().find(loginName.toLowerCase(Locale.ROOT))
            .filter(LocalUser::enabled)
            .orElseThrow(() -> new AccessRefusal(HttpStatus.CONFLICT, "NOT_A_LOCAL_USER",
                "Only a local user changes the password here; directory passwords are changed in the directory."));
        String actor = pseudonym(user.loginName());
        if (!ENCODER.matches(new String(current), user.passwordHash())) {
            return Optional.empty();
        }
        checkNewPassword(user.loginName(), current, next);
        String hash = ENCODER.encode(new String(next));
        return Optional.of(conflicts(() -> database.localUsers().update(user.loginName(), u -> ownChange(user, u, hash),
            breakGlassEnabled, audit(actor, "local_user.password_change", "OWN_PASSWORD_CHANGE"))));
    }

    /**
     * The own change applied to the row locked for update: refused when that row is no longer enabled or no longer holds
     * the hash the current password was checked against ({@code checked}).
     */
    static LocalUser ownChange(LocalUser checked, LocalUser locked, String hash) {
        if (!locked.enabled() || !locked.passwordHash().equals(checked.passwordHash())) {
            throw new LocalUserConflict("ACCOUNT_CHANGED",
                "The account was changed by an administrator meanwhile; sign in again.");
        }
        return with(locked, locked.roles(), true, hash, false, Instant.now());
    }

    /**
     * True when the stored local user still matches what a sign-in authenticated: enabled, the same roles and the same
     * change mark (PR 48 review D-03: a disable, reset or role change that lands during the sign-in ends that session).
     */
    public boolean stillMatches(AuthenticatedUser user) {
        return database.localUsers().find(user.loginName().toLowerCase(Locale.ROOT))
            .filter(LocalUser::enabled)
            .filter(u -> Set.copyOf(u.roles()).equals(user.roles()))
            .filter(u -> u.mustChangePassword() == user.passwordChangeRequired())
            .isPresent();
    }

    /**
     * Ends another person's session with a reason: the session is invalidated first, and the end is ledgered under both
     * pseudonyms only when a live session actually ended (PR 48 review D-06).
     */
    public void endSession(Actor by, String handle, String currentHandle, String reason) {
        String actor = pseudonym(by.loginName());
        ActiveSessions.Entry entry = sessions.find(handle).orElseThrow(LocalUsers::sessionNotFound);
        if (handle.equals(currentHandle)) {
            throw new AccessRefusal(HttpStatus.CONFLICT, "SELF_SESSION_REFUSED",
                "This is your own session; sign out instead.");
        }
        String why = reason(reason, by, entry.loginName());
        String subject = pseudonym(entry.loginName());
        ActiveSessions.Entry ended = sessions.end(handle).orElseThrow(LocalUsers::sessionNotFound);
        database.localUsers().recordSessionEnd(subject, actor, ended.source(), audit(actor, "session.end", why));
    }

    private static AccessRefusal sessionNotFound() {
        return new AccessRefusal(HttpStatus.NOT_FOUND, "SESSION_NOT_FOUND",
            "No such session is open (it may have ended already).");
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

    /** The shape, then no identifier and no estate term (PR 48 review D-08; fails closed without the dictionary). */
    String loginName(String raw) {
        String name = raw == null ? "" : raw.strip().toLowerCase(Locale.ROOT);
        if (!LOGIN_NAME.matcher(name).matches() || name.equals(BreakGlassAccounts.BREAK_GLASS)) {
            throw invalid("INVALID_USER_LOGIN", "A login name is 3 to 32 lower-case letters, digits, '.', '_' or '-', "
                + "starts with a letter and is not the break-glass name.");
        }
        return noIdentifier(name);
    }

    String displayName(String raw) {
        String name = raw == null ? "" : raw.strip();
        if (name.isEmpty() || name.length() > MAX_DISPLAY_NAME || name.chars().anyMatch(Character::isISOControl)) {
            throw invalid("INVALID_DISPLAY_NAME", "A display name is 1 to " + MAX_DISPLAY_NAME
                + " characters on one line.");
        }
        return noIdentifier(name);
    }

    /** A person's name may be a name, never a number, an address, a secret or an estate term. */
    private String noIdentifier(String value) {
        requireMasking("The name cannot be checked for identifiers without the masking key and dictionary; nothing "
            + "changed.");
        if (IdentifierCheck.identifierShape(value) || identifiers.namesEstate(value)) {
            throw invalid("NAME_HOLDS_IDENTIFIER", "The name holds an identifier (a number, an address, a secret or "
                + "an estate name); choose another.");
        }
        return value;
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
     * every unmasked reader of the ledger and the SIEM reads it. It also may not name a person this screen knows (PR 48
     * review D-05): a word of the reason equal to a token of 3 or more letters of the actor's login name, of
     * {@code names} (the target's login and display name), or of any stored local user's login or display name, or
     * starting with such a token of {@value #PREFIX_TOKEN} or more letters (a Turkish suffix), after Turkish folding.
     * The refusal never echoes the text.
     */
    String reason(String raw, Actor by, String... names) {
        String reason = raw == null ? "" : raw.strip();
        if (reason.isEmpty() || reason.length() > MAX_REASON || reason.chars().anyMatch(Character::isISOControl)) {
            throw invalid("INVALID_REASON", "A reason of 1 to " + MAX_REASON + " characters on one line is required.");
        }
        requireMasking("The reason cannot be checked for identifiers without the masking key and dictionary; nothing "
            + "changed.");
        if (identifiers.namesEstate(reason)) {
            throw invalid("ESTATE_NAME_REFUSED", "The reason names the estate; describe it without that name.");
        }
        List<String> known = new ArrayList<>(List.of(names));
        known.add(by.loginName());
        for (LocalUser u : list()) {
            known.add(u.loginName());
            known.add(u.displayName());
        }
        if (IdentifierCheck.identifierShape(reason) || !masking.masker().maskFreeText(reason).equals(reason)
            || namesPerson(reason, known)) {
            throw invalid("REASON_HOLDS_IDENTIFIER", "The reason holds an identifier (an address, a number or a name "
                + "the masking rules or this screen recognise); describe the reason without it.");
        }
        return reason;
    }

    /** True when a word of {@code text} is a token of one of {@code names} (see {@link #reason}). */
    static boolean namesPerson(String text, Collection<String> names) {
        Set<String> tokens = new LinkedHashSet<>();
        for (String name : names) {
            if (name != null) {
                for (String t : NON_WORD.split(IdentifierCheck.fold(name))) {
                    if (t.length() >= 3) {
                        tokens.add(t);
                    }
                }
            }
        }
        for (String word : NON_WORD.split(IdentifierCheck.fold(text))) {
            for (String t : tokens) {
                if (word.equals(t) || (t.length() >= PREFIX_TOKEN && word.startsWith(t))) {
                    return true;
                }
            }
        }
        return false;
    }

    private void requireMasking(String message) {
        if (!masking.available()) {
            throw new AccessRefusal(HttpStatus.SERVICE_UNAVAILABLE, "MASKING_UNAVAILABLE", message);
        }
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
