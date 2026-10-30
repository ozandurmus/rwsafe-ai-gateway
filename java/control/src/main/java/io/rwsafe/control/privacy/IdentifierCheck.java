package io.rwsafe.control.privacy;

import io.rwsafe.detect.DetectorSet;
import java.text.Normalizer;
import java.util.Locale;
import org.springframework.stereotype.Component;

/**
 * The one identifier check for every free value the control plane stores and shows (PR 24 review D-01, D-04): registry
 * platform ids, reason codes and host labels, retirement and withdrawal reasons, ingestion's free tokens. A value carries
 * an identifier when, after NFC normalisation and Turkish folding:
 * <ul>
 *   <li>a Tier-1 detector recognises it (secret shapes, TCKN, TR IBAN, payment cards), on the value or its folded form;</li>
 *   <li>it holds {@value #MAX_DIGIT_RUN_EXCLUSIVE} or more digits in a row, even glued to letters (a TCKN, phone, card,
 *       customer or account number written as {@code ref<digits>} escapes the detectors' word boundary), counting
 *       across a single space, hyphen, dot or underscore between digits (a number written in groups);</li>
 *   <li>it names an estate-dictionary term, compared on folded letters and digits only (so {@code Şube-X},
 *       {@code SUBE_X} and {@code sube.x} are one term).</li>
 * </ul>
 * Without the estate dictionary nothing can be checked and the check refuses ({@link MaskingUnavailableException}, 503;
 * AGENTS.md 4.10). A person's name is not recognisable without the layer-4 name dictionary, which is why free text is
 * withheld from the masked role ({@link TextMasker#WITHHELD}).
 */
@Component
public class IdentifierCheck {

    /** A digit run this long or longer is refused. */
    public static final int MAX_DIGIT_RUN_EXCLUSIVE = 6;
    private static final DetectorSet DETECTORS = DetectorSet.standard();

    private final PrivacyKeys keys;

    public IdentifierCheck(PrivacyKeys keys) {
        this.keys = keys;
    }

    /** True when {@code value} carries an identifier shape or names the estate. */
    public boolean carriesIdentifier(String value) {
        return value != null && (identifierShape(value) || namesEstate(value));
    }

    /** True when {@code value} names an estate-dictionary term (folded letters and digits). */
    public boolean namesEstate(String value) {
        if (!keys.maskingAvailable()) {
            throw new MaskingUnavailableException("estate dictionary");
        }
        if (value == null) {
            return false;
        }
        String v = letters(value);
        for (String term : keys.estateTerms()) {
            String t = letters(term);
            if (!t.isEmpty() && v.contains(t)) {
                return true;
            }
        }
        return false;
    }

    /** A detector hit on the value or its folded form, or a run of six or more digits. */
    public static boolean identifierShape(String value) {
        if (value == null) {
            return false;
        }
        String nfc = Normalizer.normalize(value, Normalizer.Form.NFC);
        String folded = fold(nfc);
        return !DETECTORS.scan(nfc).isEmpty() || !DETECTORS.scan(folded).isEmpty()
            || !DETECTORS.scan(folded.toUpperCase(Locale.ROOT)).isEmpty()
            || longestDigitRun(nfc) >= MAX_DIGIT_RUN_EXCLUSIVE;
    }

    /**
     * The longest run of digits, joined across one space, hyphen, dot or underscore that has a digit on both sides (the
     * same joins the leak probe makes; PR 24 confirmation review N-02).
     */
    public static int longestDigitRun(String value) {
        int run = 0;
        int longest = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isDigit(c)) {
                run++;
                longest = Math.max(longest, run);
            } else if (!(GROUP_SEPARATORS.indexOf(c) >= 0 && i > 0 && Character.isDigit(value.charAt(i - 1))
                && i + 1 < value.length() && Character.isDigit(value.charAt(i + 1)))) {
                run = 0;
            }
        }
        return longest;
    }

    private static final String GROUP_SEPARATORS = " -._";

    /** NFC, Turkish letters folded to ASCII, lower case, combining marks dropped. */
    public static String fold(String s) {
        String nfc = Normalizer.normalize(s, Normalizer.Form.NFC);
        StringBuilder b = new StringBuilder(nfc.length());
        for (int i = 0; i < nfc.length(); i++) {
            char c = nfc.charAt(i);
            switch (c) {
                case 'ş', 'Ş' -> b.append('s');
                case 'ğ', 'Ğ' -> b.append('g');
                case 'ü', 'Ü' -> b.append('u');
                case 'ö', 'Ö' -> b.append('o');
                case 'ç', 'Ç' -> b.append('c');
                case 'ı', 'İ', 'I' -> b.append('i');
                default -> {
                    if (Character.getType(c) != Character.NON_SPACING_MARK) {
                        b.append(Character.toLowerCase(c));
                    }
                }
            }
        }
        return b.toString();
    }

    /** The folded letters and digits of {@code s}, nothing else. */
    static String letters(String s) {
        String f = fold(s);
        StringBuilder out = new StringBuilder(f.length());
        for (int i = 0; i < f.length(); i++) {
            if (Character.isLetterOrDigit(f.charAt(i))) {
                out.append(f.charAt(i));
            }
        }
        return out.toString();
    }
}
