package io.rwsafe.control.identity;

import io.rwsafe.control.api.ApiError;
import io.rwsafe.control.privacy.MaskedView;
import io.rwsafe.control.privacy.TextMasker;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.util.List;
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
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Session login for the SPA (ARCHITECTURE.md §4.4): JSON credentials, a new session id on success (no fixation), the
 * {@code __Host-} session cookie and the CSRF cookie. Failures name a reason class and never which part was wrong.
 */
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private static final Logger LOG = LoggerFactory.getLogger(AuthController.class);
    private static final int MAX_LOGIN_NAME = 64;
    private static final int MAX_PASSWORD = 256;

    private final IdentityService identity;
    private final SecurityContextRepository contexts = new HttpSessionSecurityContextRepository();

    public AuthController(IdentityService identity) {
        this.identity = identity;
    }

    /** Never printed: the record's own toString would show the password. */
    public record LoginRequest(String loginName, String password) {

        @Override
        public String toString() {
            return "LoginRequest[redacted]";
        }
    }

    /** The signed-in user as the SPA shows it; the masked projection hides the login name. */
    public record MeView(String displayName, List<String> roles, boolean masked, String source) implements MaskedView {

        @Override
        public MaskedView masked(TextMasker masker) {
            return new MeView("masked session", roles, true, source);
        }
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
        String name = body == null || body.loginName() == null ? "" : body.loginName().strip();
        String password = body == null || body.password() == null ? "" : body.password();
        if (name.isEmpty() || name.length() > MAX_LOGIN_NAME || password.isEmpty() || password.length() > MAX_PASSWORD
            || name.chars().anyMatch(Character::isISOControl)) {
            return error(HttpStatus.BAD_REQUEST, "INVALID_LOGIN_REQUEST", "A login name and a password are required.");
        }
        IdentityService.Result result = identity.login(name, password.toCharArray());
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
        List<GrantedAuthority> authorities = user.roles().stream()
            .map(r -> (GrantedAuthority) new SimpleGrantedAuthority(Roles.authority(r))).toList();
        Authentication auth = UsernamePasswordAuthenticationToken.authenticated(user.loginName(), null, authorities);
        HttpSession existing = request.getSession(false);
        if (existing != null) {
            request.changeSessionId();
        } else {
            request.getSession(true);
        }
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(auth);
        SecurityContextHolder.setContext(context);
        contexts.saveContext(context, request, response);
        LOG.info("login accepted: source={} roles={}", user.source(), new TreeSet<>(user.roles()));
        return ResponseEntity.ok(me(auth, user.source()));
    }

    @GetMapping("/me")
    public MeView me(Authentication auth) {
        return me(auth, null);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        SecurityContextHolder.clearContext();
        return ResponseEntity.noContent().build();
    }

    private static MeView me(Authentication auth, String source) {
        Set<String> roles = new TreeSet<>();
        for (GrantedAuthority a : auth.getAuthorities()) {
            roles.add(a.getAuthority().substring("ROLE_".length()));
        }
        return new MeView(auth.getName(), List.copyOf(roles), roles.contains(Roles.REPLAY_VIEWER), source);
    }

    private static ResponseEntity<MaskedView> error(HttpStatus status, String reason, String message) {
        return ResponseEntity.status(status).body(ApiError.of(reason, message));
    }
}
