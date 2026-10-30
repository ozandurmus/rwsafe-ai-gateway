package io.rwsafe.control.capture;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.rwsafe.control.support.ApiInventory;
import java.nio.file.Files;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/**
 * The admin UI offers exactly the reason codes the C3 read route takes (admin UI slice 3): a code the server adds or
 * drops fails here until the UI's {@code CAPTURE_REASON_CODES} in {@code frontend/src/api.ts} follows.
 */
class CaptureReasonCodesUiTest {

    private static final Pattern LIST = Pattern.compile("CAPTURE_REASON_CODES = \\[([^\\]]*)\\]");
    private static final Pattern CODE = Pattern.compile("'([A-Z_]+)'");

    @Test
    void theUiOffersTheServersReasonCodes() throws Exception {
        String source = Files.readString(ApiInventory.repositoryRoot().resolve("frontend").resolve("src")
            .resolve("api.ts"));
        Matcher list = LIST.matcher(source);
        if (!list.find()) {
            throw new AssertionError("CAPTURE_REASON_CODES not found in frontend/src/api.ts");
        }
        Set<String> ui = new TreeSet<>();
        Matcher code = CODE.matcher(list.group(1));
        while (code.find()) {
            ui.add(code.group(1));
        }
        assertEquals(new TreeSet<>(CaptureReadController.REASONS), ui);
    }
}
