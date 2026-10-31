package io.rwsafe.control.identity;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

/** The session and CSRF cookie settings agree (CookiePolicy): secure by default, plain only without a prefix. */
class CookiePolicyTest {

    @Test
    void theDeploySettingAndThePlainLocalRunAreAccepted() {
        assertDoesNotThrow(() -> CookiePolicy.check("__Host-rwsafe-session", true, true));
        assertDoesNotThrow(() -> CookiePolicy.check("rwsafe-session", false, false));
    }

    @Test
    void aHalfAppliedSettingIsRefused() {
        assertThrows(IllegalStateException.class, () -> CookiePolicy.check("__Host-rwsafe-session", false, false),
            "a browser drops a __Host- cookie without Secure: sign-in would loop silently");
        assertThrows(IllegalStateException.class, () -> CookiePolicy.check("__Secure-rwsafe-session", false, false));
        assertThrows(IllegalStateException.class, () -> CookiePolicy.check("rwsafe-session", true, false));
        assertThrows(IllegalStateException.class, () -> CookiePolicy.check("rwsafe-session", false, true));
    }
}
