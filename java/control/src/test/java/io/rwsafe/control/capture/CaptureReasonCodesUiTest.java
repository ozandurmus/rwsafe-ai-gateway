package io.rwsafe.control.capture;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.control.identity.Roles;
import io.rwsafe.control.support.ApiInventory;
import java.nio.file.Files;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * The admin UI offers exactly what the C3 read route takes (admin UI slice 3, PR 28 review Q-1 and Q-2): the reason codes
 * per reader role ({@code CAPTURE_REASONS_BY_ROLE} in {@code frontend/src/api.ts} against
 * {@link CaptureReadController#REASONS_BY_ROLE}), and the case-id shape both sides check.
 */
class CaptureReasonCodesUiTest {

    private static final Pattern CODE = Pattern.compile("'([A-Z_]+)'");

    private static String api() throws Exception {
        return Files.readString(ApiInventory.repositoryRoot().resolve("frontend").resolve("src").resolve("api.ts"));
    }

    private static Set<String> list(String source, String name) {
        Matcher m = Pattern.compile(Pattern.quote(name) + "\\s*[:=]\\s*\\[([^\\]]*)\\]").matcher(source);
        if (!m.find()) {
            throw new AssertionError(name + " not found in frontend/src/api.ts");
        }
        Set<String> out = new TreeSet<>();
        Matcher code = CODE.matcher(m.group(1));
        while (code.find()) {
            out.add(code.group(1));
        }
        return out;
    }

    @Test
    void theUiOffersEachRoleTheServersReasonCodes() throws Exception {
        String source = api();
        assertEquals(new TreeSet<>(CaptureReadController.REASONS), list(source, "CAPTURE_REASON_CODES"));
        assertEquals(new TreeSet<>(CaptureReadController.REASONS_BY_ROLE.get(Roles.SECURITY_ADMIN)),
            list(source, Roles.SECURITY_ADMIN));
        assertEquals(new TreeSet<>(CaptureReadController.REASONS_BY_ROLE.get(Roles.PRIVACY_OFFICER)),
            list(source, Roles.PRIVACY_OFFICER));
        assertEquals(Set.of(Roles.SECURITY_ADMIN, Roles.PRIVACY_OFFICER), CaptureReadController.REASONS_BY_ROLE.keySet());
    }

    @Test
    void eachRoleGivesItsOwnReasonsAndBothRolesGiveBoth() {
        assertEquals(Set.of("DSAR"), CaptureReadController.permittedReasons(auth(Roles.PRIVACY_OFFICER)));
        assertEquals(Set.of("INCIDENT_INVESTIGATION", "FALSE_POSITIVE_REVIEW", "LEGAL_HOLD_REVIEW", "REGULATOR_REQUEST"),
            CaptureReadController.permittedReasons(auth(Roles.SECURITY_ADMIN)));
        assertEquals(CaptureReadController.REASONS,
            CaptureReadController.permittedReasons(auth(Roles.SECURITY_ADMIN, Roles.PRIVACY_OFFICER)));
        assertTrue(CaptureReadController.permittedReasons(auth(Roles.VIEWER)).isEmpty());
    }

    @Test
    void aCaseIdIsAReferenceWithALetterAndNoIdentifier() {
        for (String ok : List.of("INC-42", "CASE-A-0001", "DSAR-7", "REG-2026-A1", "abc", "x_12345")) {
            assertTrue(CaptureReadController.caseIdShape(ok), ok);
        }
        // No letter, too short or long, a character outside the set, six or more digits (also across a separator).
        for (String refused : List.of("123", "12345", "ab", "a".repeat(65), "INC 42", "INC/42", "INC.42",
            "CASE-2026-0001", "REF123456", "INC-12-34-56", "x_123456")) {
            assertFalse(CaptureReadController.caseIdShape(refused), refused);
        }
    }

    private static UsernamePasswordAuthenticationToken auth(String... roles) {
        return UsernamePasswordAuthenticationToken.authenticated("synthetic-reader", null,
            java.util.Arrays.stream(roles).map(r -> new SimpleGrantedAuthority(Roles.authority(r))).toList());
    }
}
