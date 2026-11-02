package io.rwsafe.control.identity;

import io.rwsafe.control.api.ApiError;
import io.rwsafe.control.privacy.MaskedView;
import io.rwsafe.control.privacy.PrivacyKeys;
import io.rwsafe.control.privacy.Pseudonymiser;
import io.rwsafe.control.privacy.TextMasker;
import io.rwsafe.persistence.Database;
import io.rwsafe.persistence.LocalUser;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Session login for the SPA (ARCHITECTURE.md §4.4): JSON credentials, a new session id on success (no fixation), the
 * {@code __Host-} session cookie and the CSRF cookie. Failures name a reason class and never which part was wrong.
 * A local user signed in with a generated password holds {@link Roles#PASSWORD_CHANGE_PENDING} and reaches only these
 * routes until {@code POST /api/v1/auth/password} replaces it (PO decision Q-47).
 */
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private static final Logger LOG = LoggerFactory.getLogger(AuthController.class);
    private static final int MAX_LOGIN_NAME = 64;
    private static final int MAX_PASSWORD = 256;

    private final IdentityService identity;
    private final CookieCsrfTokenRepository csrfTokens;
    private final PrivacyKeys keys;
    private final Pseudonymiser pseudonymiser;
    private final Database database;
    private final ActiveSessions sessions;
    private final LocalUsers localUsers;
    private final SecurityContextRepository contexts = new HttpSessionSecurityContextRepository();

    public AuthController(IdentityService identity, CookieCsrfTokenRepository csrfTokens, PrivacyKeys keys,
                          Pseudonymiser pseudonymiser, Database database, ActiveSessions sessions,
                          LocalUsers localUsers) {
        this.identity = identity;
        this.csrfTokens = csrfTokens;
        this.keys = keys;
        this.pseudonymiser = pseudonymiser;
        this.database = database;
        this.sessions = sessions;
        this.localUsers = localUsers;
    }

    /** Never printed: the record's own toString would show the password. */
    public record LoginRequest(String loginName, String password) {

        @Override
        public String toString() {
            return "LoginRequest[redacted]";
        }
    }

    /** Never printed: the record's own toString would show both passwords. */
    public record PasswordChangeRequest(String currentPassword, String newPassword) {

        @Override
        public String toString() {
            return "PasswordChangeRequest[redacted]";
        }
    }

    /**
     * The signed-in user as the SPA shows it; the masked projection hides the login name. {@code passwordChangeRequired}:
     * a local user signed in with a generated password and reaches nothing but the password change until it is done.
     */
    public record MeView(String displayName, List<String> roles, boolean masked, String source,
                         boolean passwordChangeRequired) implements MaskedView {

        @Override
        public MaskedView masked(TextMasker masker) {
            return new MeView("masked session", roles, true, source, passwordChangeRequired);
        }
    }

    /** The session's source ({@code ldap}, {@code local}, {@code local_user}), kept as the authentication's details. */
    public record SessionDetails(String source) implements java.io.Serializable {
    }

    public record CsrfView(String headerName, String token) implements MaskedView {

        @Override
        public MaskedView masked(TextMasker masker) {
            return this;
        }
    }

    @GetMapping("/csrf")
    public CsrfView csrf(CsrfToken token) {
        return new CsrfView(token.getHeaderName(), token.getToken());
    }

    @PostMapping("/login")
    public ResponseEntity<MaskedView> login(@RequestBody LoginRequest body, HttpServletRequest request,
                                            HttpServletResponse response) {
        String name = body == null || body.loginName() == null ? "" : body.loginName();
        String password = body == null || body.password() == null ? "" : body.password();
        // A name is taken as typed: surrounding white space is refused, never stripped, so no spelling of a local
        // user's name can differ from the one the local row is looked up by (PR 50 review D-05).
        if (name.isEmpty() || !name.equals(name.strip()) || name.length() > MAX_LOGIN_NAME || password.isEmpty()
            || password.length() > MAX_PASSWORD || name.chars().anyMatch(Character::isISOControl)) {
            return error(HttpStatus.BAD_REQUEST, "INVALID_LOGIN_REQUEST", "A login name and a password are required.");
        }
        IdentityService.Result result = identity.login(name, password.toCharArray(), request.getRemoteAddr());
        switch (result.outcome()) {
            case THROTTLED:
                return error(HttpStatus.TOO_MANY_REQUESTS, "LOGIN_THROTTLED",
                    "Too many failed logins for this name; try again in 15 minutes.");
            case INVALID:
                LOG.info("login refused: invalid credentials");
                return error(HttpStatus.UNAUTHORIZED, "INVALID_CREDENTIALS", "The login name or password is wrong.");
            case NO_ROLE:
                LOG.info("login refused: no rwsafe role is bound to the user's groups");
                return error(HttpStatus.FORBIDDEN, "NO_ROLE", "Your account has no rwsafe role.");
            default:
                break;
        }
        AuthenticatedUser user = result.user();
        boolean masked = user.roles().contains(Roles.REPLAY_VIEWER);
        // A masked session that cannot be served is not opened, recorded or ledgered (PR 12 review N-02).
        if (masked && !keys.maskingAvailable()) {
            return error(HttpStatus.SERVICE_UNAVAILABLE, "MASKING_UNAVAILABLE",
                "The masking key or dictionary is missing; a masked session cannot be opened.");
        }
        // Every accepted sign-in is ledgered under the login name's pseudonym (ARCHITECTURE.md §4.4, D-02, D-09). Without
        // the privacy key no pseudonym exists: only break-glass may sign in then, recorded under its system actor.
        String actor;
        if (keys.keyAvailable()) {
            actor = pseudonymiser.user(user.loginName());
        } else if ("local".equals(user.source())) {
            actor = "system:break-glass";
        } else {
            return error(HttpStatus.SERVICE_UNAVAILABLE, "PRIVACY_KEY_UNAVAILABLE",
                "Sign-ins are recorded under a pseudonym and the privacy key is missing; use the break-glass account.");
        }
        database.loginRecords().record(actor, user.source(), masked);
        Authentication auth = authentication(user.loginName(), user.roles(), user.source(),
            user.passwordChangeRequired());
        // A new session every time, never a reused one (D-09), and a new CSRF token with it.
        HttpSession existing = request.getSession(false);
        if (existing != null) {
            existing.invalidate();
        }
        HttpSession session = request.getSession(true);
        csrfTokens.saveToken(csrfTokens.generateToken(request), request, response);
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(auth);
        SecurityContextHolder.setContext(context);
        contexts.saveContext(context, request, response);
        sessions.register(session, user, user.roles());
        // PR 48 review D-03: a disable, reset or role change that landed while this sign-in ran has already ended the
        // user's registered sessions; this one is checked against the stored row once it is registered.
        if (LocalUserAuthenticator.SOURCE.equals(user.source()) && !localUsers.stillMatches(user)) {
            sessions.handle(session).ifPresent(sessions::end);
            SecurityContextHolder.clearContext();
            csrfTokens.saveToken(null, request, response);
            LOG.info("login refused: the local user changed during the sign-in");
            return error(HttpStatus.UNAUTHORIZED, "INVALID_CREDENTIALS", "The login name or password is wrong.");
        }
        LOG.info("login accepted: source={} roles={} masked={} passwordChangeRequired={}", user.source(),
            new TreeSet<>(user.roles()), masked, user.passwordChangeRequired());
        return ResponseEntity.ok(me(auth));
    }

    @GetMapping("/me")
    public MeView me(Authentication auth) {
        Set<String> roles = roles(auth);
        boolean pending = auth.getAuthorities().stream()
            .anyMatch(a -> Roles.PASSWORD_CHANGE_PENDING.equals(a.getAuthority()));
        String source = auth.getDetails() instanceof SessionDetails d ? d.source() : null;
        return new MeView(auth.getName(), List.copyOf(roles), roles.contains(Roles.REPLAY_VIEWER), source, pending);
    }

    /**
     * A local user replaces their password (PO decision Q-47): required after a generated one, allowed at any time. The
     * current password is checked under the login throttle; on success the session keeps its roles without the pending
     * mark, under a new session id and a new CSRF token. Neither password is logged or echoed.
     */
    @PostMapping("/password")
    public ResponseEntity<MaskedView> changePassword(@RequestBody PasswordChangeRequest body, Authentication auth,
                                                     HttpServletRequest request, HttpServletResponse response) {
        // A masked session changes nothing it could not be served afterwards (PR 48 review D-02, AGENTS.md 4.10).
        if (roles(auth).contains(Roles.REPLAY_VIEWER) && !keys.maskingAvailable()) {
            return error(HttpStatus.SERVICE_UNAVAILABLE, "MASKING_UNAVAILABLE",
                "The masking key or dictionary is missing; nothing changed.");
        }
        if (!(auth.getDetails() instanceof SessionDetails details)
            || !LocalUserAuthenticator.SOURCE.equals(details.source())) {
            return error(HttpStatus.CONFLICT, "NOT_A_LOCAL_USER",
                "Only a local user changes the password here; directory passwords are changed in the directory.");
        }
        String current = body == null || body.currentPassword() == null ? "" : body.currentPassword();
        String next = body == null || body.newPassword() == null ? "" : body.newPassword();
        if (current.isEmpty() || current.length() > MAX_PASSWORD || next.isEmpty() || next.length() > MAX_PASSWORD) {
            return error(HttpStatus.BAD_REQUEST, "INVALID_PASSWORD_REQUEST",
                "The current and the new password are required.");
        }
        String name = auth.getName();
        if (identity.throttled(name, request.getRemoteAddr())) {
            return error(HttpStatus.TOO_MANY_REQUESTS, "LOGIN_THROTTLED",
                "Too many failed logins for this name; try again in 15 minutes.");
        }
        Optional<LocalUser> stored = localUsers.changeOwnPassword(name, current.toCharArray(), next.toCharArray());
        if (stored.isEmpty()) {
            identity.failed(name, request.getRemoteAddr());
            LOG.info("password change refused: the current password is wrong");
            return error(HttpStatus.FORBIDDEN, "CURRENT_PASSWORD_WRONG", "The current password is wrong.");
        }
        // The session goes on with the stored roles, and every other session of the user ends (D-02).
        Authentication changed = authentication(name, Set.copyOf(stored.get().roles()), details.source(), false);
        sessions.endAllExcept(name, details.source(), sessions.handle(request.getSession(false)).orElse(null));
        request.changeSessionId();
        csrfTokens.saveToken(csrfTokens.generateToken(request), request, response);
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(changed);
        SecurityContextHolder.setContext(context);
        contexts.saveContext(context, request, response);
        sessions.passwordChanged(request.getSession(false));
        LOG.info("password changed by a local user");
        return ResponseEntity.ok(me(changed));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        SecurityContextHolder.clearContext();
        csrfTokens.saveToken(null, request, response);
        return ResponseEntity.noContent().build();
    }

    /** The session's authentication: the roles, the source as details and, until the password change, the mark. */
    private static Authentication authentication(String loginName, Set<String> roles, String source, boolean pending) {
        List<GrantedAuthority> authorities = new ArrayList<>();
        new TreeSet<>(roles).forEach(r -> authorities.add(new SimpleGrantedAuthority(Roles.authority(r))));
        if (pending) {
            authorities.add(new SimpleGrantedAuthority(Roles.PASSWORD_CHANGE_PENDING));
        }
        UsernamePasswordAuthenticationToken auth = UsernamePasswordAuthenticationToken.authenticated(loginName, null,
            authorities);
        auth.setDetails(new SessionDetails(source));
        return auth;
    }

    private static Set<String> roles(Authentication auth) {
        Set<String> roles = new TreeSet<>();
        for (GrantedAuthority a : auth.getAuthorities()) {
            if (a.getAuthority().startsWith("ROLE_")) {
                roles.add(a.getAuthority().substring("ROLE_".length()));
            }
        }
        return roles;
    }

    private static ResponseEntity<MaskedView> error(HttpStatus status, String reason, String message) {
        return ResponseEntity.status(status).body(ApiError.of(reason, message));
    }
}
