package io.rwsafe.control.identity;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

class LoginThrottleTest {

    private final Clock clock = Clock.fixed(Instant.parse("2026-10-30T09:00:00Z"), ZoneOffset.UTC);

    @Test
    void fiveFailuresLockThePairNotTheNameEverywhere() {
        LoginThrottle t = new LoginThrottle(clock);
        for (int i = 0; i < LoginThrottle.MAX_PER_SOURCE; i++) {
            t.failure("breakglass", "source-a");
        }
        assertTrue(t.locked("breakglass", "source-a"));
        assertFalse(t.locked("breakglass", "source-b"), "a third party cannot lock the administrator out");
    }

    @Test
    void manySourcesLockTheName() {
        LoginThrottle t = new LoginThrottle(clock);
        for (int i = 0; i < LoginThrottle.MAX_PER_NAME; i++) {
            t.failure("synthetic-admin", "source-" + i);
        }
        assertTrue(t.locked("synthetic-admin", "source-new"));
    }

    @Test
    void locksAreNeverEvictedByAFloodOfNewNames() {
        LoginThrottle t = new LoginThrottle(clock);
        for (int i = 0; i < LoginThrottle.MAX_PER_SOURCE; i++) {
            t.failure("synthetic-admin", "source-a");
        }
        for (int i = 0; i < LoginThrottle.MAX_ENTRIES; i++) {
            t.failure("synthetic-dummy-" + i, "source-a");
        }
        assertTrue(t.locked("synthetic-admin", "source-a"));
        assertTrue(t.locked("synthetic-never-seen", "source-z"), "a full throttle refuses unknown names");
    }

    @Test
    void theMaskedRoleIsExclusive() {
        AuthenticatedUser dual = new AuthenticatedUser("synthetic-dual",
            java.util.Set.of(Roles.REPLAY_VIEWER, Roles.SECURITY_ADMIN), "ldap");
        assertTrue(IdentityService.exclusive(dual).roles().equals(java.util.Set.of(Roles.REPLAY_VIEWER)));
    }

    @Test
    void plainLdapIsOnlyForLoopback() {
        assertTrue(LdapAuthenticator.loopback("127.0.0.1"));
        assertTrue(LdapAuthenticator.loopback("localhost"));
        assertFalse(LdapAuthenticator.loopback("synthetic.example.test"));
        LdapAuthenticator remote = new LdapAuthenticator(new io.rwsafe.control.config.ControlProperties.Ldap(
            "ldap://synthetic.example.test:389", "cn=synthetic-service,dc=example,dc=test", null,
            "dc=example,dc=test", "(uid={0})", null, null));
        assertTrue(remote.authenticate("synthetic-admin", "synthetic-password".toCharArray()).isEmpty());
        remote.close();
    }
}
