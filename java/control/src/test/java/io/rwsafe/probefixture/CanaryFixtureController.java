package io.rwsafe.probefixture;

import io.rwsafe.control.privacy.MaskedView;
import io.rwsafe.control.privacy.TextMasker;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Test-only route of the leak probe's positive control (PR 24 review D-03), imported by {@code MaskedRoleLeakProbeTest}
 * alone (this package is outside the application's component scan, so no other context has it). It serves every canary
 * class in clear to an unmasked viewer, so the viewer walk must see each class: the masked walk's zero hits then mean
 * something. Through the real funnel, the masked role reads each field the text masker claims to handle as its masked
 * form (so every masking layer is proven against the probe) and every other field withheld.
 */
@RestController
public class CanaryFixtureController {

    public static final String PATH = "/api/v1/test-fixture/canaries";

    /**
     * One seeded value; {@code maskable} when the text masker's layers recognise this form; {@code freeText} when it sits
     * in a sentence and goes through the free-text layers (names, layer 5) rather than the per-value ones.
     */
    public record Field(String canaryClass, String value, boolean maskable, boolean freeText) {
    }

    public record FixtureView(List<Field> fields) implements MaskedView {

        @Override
        public FixtureView masked(TextMasker m) {
            return new FixtureView(fields.stream().map(f -> new Field(f.canaryClass(),
                !f.maskable() ? TextMasker.WITHHELD : f.freeText() ? m.maskFreeText(f.value()) : m.mask(f.value()),
                f.maskable(), f.freeText())).toList());
        }
    }

    /** Set by the probe before its context starts. */
    public static volatile List<Field> fields = List.of();

    @GetMapping(PATH)
    public FixtureView canaries() {
        return new FixtureView(fields);
    }
}
