package io.rwsafe.control.identity;

import io.rwsafe.control.config.ControlProperties;
import io.rwsafe.persistence.Database;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Service;

/** The authentication fronts in order: the local break-glass account (when enabled), then the directory (when set). */
@Service
public class IdentityService implements ApplicationRunner, DisposableBean {

    public enum Outcome { AUTHENTICATED, INVALID, THROTTLED, NO_ROLE }

    public record Result(Outcome outcome, AuthenticatedUser user) {
    }

    private final ControlProperties properties;
    private final BreakGlassAccounts breakGlass;
    private final LdapAuthenticator ldap;
    private final List<Authenticator> fronts = new ArrayList<>();
    private final LoginThrottle throttle = new LoginThrottle(Clock.systemUTC());

    public IdentityService(ControlProperties properties, Database database) {
        this.properties = properties;
        this.breakGlass = properties.identity().breakGlass().enabled() ? new BreakGlassAccounts(database) : null;
        this.ldap = properties.identity().ldap().configured() ? new LdapAuthenticator(properties.identity().ldap()) : null;
        if (breakGlass != null) {
            fronts.add(breakGlass);
        }
        if (ldap != null) {
            fronts.add(ldap);
        }
    }

    @Override
    public void run(ApplicationArguments args) {
        if (breakGlass != null) {
            breakGlass.bootstrap(properties.identity().breakGlass());
        }
    }

    /**
     * @param source the client the attempt came from, for the throttle only (never stored or logged)
     */
    public Result login(String loginName, char[] password, String source) {
        if (throttle.locked(loginName, source)) {
            return new Result(Outcome.THROTTLED, null);
        }
        for (Authenticator front : fronts) {
            Optional<AuthenticatedUser> user = front.authenticate(loginName, password);
            if (user.isPresent()) {
                if (user.get().roles().isEmpty()) {
                    // Counted as a failure, so the gateway cannot be used to test directory passwords (PR 12 review Q-1).
                    throttle.failure(loginName, source);
                    return new Result(Outcome.NO_ROLE, user.get());
                }
                throttle.success(loginName, source);
                return new Result(Outcome.AUTHENTICATED, exclusive(user.get()));
            }
        }
        throttle.failure(loginName, source);
        return new Result(Outcome.INVALID, null);
    }

    /**
     * The masked role is an exclusive session mode (MASKING_AND_PRIVACY B1): a user who holds it is signed in with it
     * alone, whatever other groups the directory names (PR 12 review D-02).
     */
    static AuthenticatedUser exclusive(AuthenticatedUser user) {
        if (user.roles().contains(Roles.REPLAY_VIEWER) && user.roles().size() > 1) {
            return new AuthenticatedUser(user.loginName(), java.util.Set.of(Roles.REPLAY_VIEWER), user.source());
        }
        return user;
    }

    @Override
    public void destroy() {
        if (ldap != null) {
            ldap.close();
        }
    }
}
