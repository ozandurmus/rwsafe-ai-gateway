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
        for (int i = 0; i < LoginThrottle.MAX_PER_PAIR; i++) {
            t.failure("breakglass", "source-a");
        }
        assertTrue(t.locked("breakglass", "source-a"));
        assertFalse(t.locked("breakglass", "source-b"), "a third party cannot lock the administrator out");
    }

    @Test
    void aSprayFromOneClientLocksThatClientOnly() {
        LoginThrottle t = new LoginThrottle(clock);
        for (int i = 0; i < LoginThrottle.MAX_PER_SOURCE; i++) {
            t.failure("synthetic-name-" + i, "source-a");
        }
        assertTrue(t.locked("synthetic-admin", "source-a"));
        assertFalse(t.locked("synthetic-admin", "source-b"));
    }

    @Test
    void aFloodNeitherEvictsLocksNorLocksOutCleanClients() {
        LoginThrottle t = new LoginThrottle(clock);
        for (int i = 0; i < LoginThrottle.MAX_PER_PAIR; i++) {
            t.failure("synthetic-admin", "source-a");
        }
        for (int i = 0; i < LoginThrottle.MAX_ENTRIES; i++) {
            t.failure("synthetic-dummy-" + i, "source-flood-" + i);
        }
        assertTrue(t.locked("synthetic-admin", "source-a"), "the lock survives the flood");
        assertFalse(t.locked("breakglass", "source-clean"), "a clean client still signs in");
        assertFalse(t.locked("synthetic-admin", "source-clean"));
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
        assertFalse(LdapAuthenticator.loopback("127.synthetic.example.test"));
        assertFalse(LdapAuthenticator.loopback(null));
        LdapAuthenticator remote = new LdapAuthenticator(new io.rwsafe.control.config.ControlProperties.Ldap(
            "ldap://synthetic.example.test:389", "cn=synthetic-service,dc=example,dc=test", null,
            "dc=example,dc=test", "(uid={0})", null, null));
        assertTrue(remote.authenticate("synthetic-admin", "synthetic-password".toCharArray()).isEmpty());
        remote.close();
    }
}
