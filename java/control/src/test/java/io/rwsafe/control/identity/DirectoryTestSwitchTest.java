package io.rwsafe.control.identity;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.mock.env.MockEnvironment;

/**
 * PR 50 review Q-1 (confirmation): the directory's test-only switch on outside the test (or local development) profile
 * raises an ERROR line at start; inside them, or off, nothing.
 */
@ExtendWith(OutputCaptureExtension.class)
class DirectoryTestSwitchTest {

    private static boolean testProfile(String... active) {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles(active);
        return DirectorySettingsService.testProfile(env);
    }

    @Test
    void aDeclaredTestProfileCounts() {
        MockEnvironment declared = new MockEnvironment().withProperty("spring.profiles.active", "other, test");
        assertTrue(DirectorySettingsService.testProfile(declared));
        assertFalse(DirectorySettingsService.testProfile(new MockEnvironment()
            .withProperty("spring.profiles.active", "production")));
    }

    @Test
    void theSwitchOnOutsideTheTestProfileLogsAnError(CapturedOutput output) {
        assertFalse(testProfile());
        assertFalse(testProfile("prod"));
        assertTrue(testProfile("test"));
        assertTrue(testProfile("dev"));

        assertTrue(DirectorySettingsService.testSwitchAlarm(true, testProfile()));
        assertTrue(output.getAll().contains("ERROR"));
        assertTrue(output.getAll().contains("directory-loopback-for-tests is on outside the test profile"));
    }

    @Test
    void insideTheTestProfileOrOffNothingIsLogged(CapturedOutput output) {
        assertFalse(DirectorySettingsService.testSwitchAlarm(true, testProfile("test")));
        assertFalse(DirectorySettingsService.testSwitchAlarm(true, testProfile("dev")));
        assertFalse(DirectorySettingsService.testSwitchAlarm(false, testProfile()));
        assertFalse(output.getAll().contains("directory-loopback-for-tests"));
    }
}
