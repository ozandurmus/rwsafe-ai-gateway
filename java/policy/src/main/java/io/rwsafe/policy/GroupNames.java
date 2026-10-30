package io.rwsafe.policy;

import java.text.Normalizer;
import java.util.Locale;

/**
 * The one comparison form of a directory group name, shared by the snapshot codec, {@link ScopedRule} and the data plane's
 * reading of {@code X-Authenticated-Groups} (PR 20 review D-02, Q-2). Group names are short names without commas (PO
 * decision on review question Q-2, 2026-10-30), never distinguished names.
 *
 * <p>The rule, in order:
 * <ol>
 *   <li>strip leading and trailing white space ({@link String#strip()});</li>
 *   <li>valid only with 1 to {@value #MAX_LENGTH} characters, no comma and no control character
 *       ({@code c < 0x20} or {@code c == 0x7f});</li>
 *   <li>Unicode NFC;</li>
 *   <li>Turkish fold: {@code İ} (U+0130), {@code I} (U+0049) and {@code ı} (U+0131) become {@code i} (U+0069), so the four
 *       letters compare equal;</li>
 *   <li>lower case with {@link Locale#ROOT};</li>
 *   <li>a combining dot above (U+0307) directly after an {@code i} is removed (the residue of a decomposed dotted capital
 *       I);</li>
 *   <li>Unicode NFC again.</li>
 * </ol>
 * The result is identity data: never logged, never a metrics label, never on a verdict event.
 */
public final class GroupNames {

    public static final int MAX_LENGTH = 256;

    private GroupNames() {
    }

    /** The comparison form, or null when the name is not a valid group name (step 2). */
    public static String normalise(String name) {
        if (name == null) {
            return null;
        }
        String s = name.strip();
        if (s.isEmpty() || s.length() > MAX_LENGTH) {
            return null;
        }
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == ',' || c < 0x20 || c == 0x7f) {
                return null;
            }
        }
        s = Normalizer.normalize(s, Normalizer.Form.NFC);
        StringBuilder folded = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            folded.append(c == 'İ' || c == 'I' || c == 'ı' ? 'i' : c);
        }
        String lower = folded.toString().toLowerCase(Locale.ROOT);
        StringBuilder out = new StringBuilder(lower.length());
        for (int i = 0; i < lower.length(); i++) {
            char c = lower.charAt(i);
            if (c == '̇' && out.length() > 0 && out.charAt(out.length() - 1) == 'i') {
                continue;
            }
            out.append(c);
        }
        return Normalizer.normalize(out, Normalizer.Form.NFC);
    }
}
