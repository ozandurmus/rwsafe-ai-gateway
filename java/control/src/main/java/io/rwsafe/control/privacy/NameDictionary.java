package io.rwsafe.control.privacy;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The Turkish given-name and family-name dictionary of masking layer 4 (MASKING_AND_PRIVACY B2, PO decision Q-23), read
 * once from the committed resources under {@code names/} (source and licence in their README). Words are compared in a
 * folded form: NFC, lower case, the Turkish dotted and dotless i and the Latin i as one letter, and the Turkish
 * diacritics dropped, so {@code AYŞE}, {@code Ayse} and {@code ayşe} are one name. A missing resource leaves the
 * dictionary unavailable and the masked role is refused (fail closed).
 */
final class NameDictionary {

    static final int GIVEN = 1;
    static final int SURNAME = 2;
    /** A name that is also an everyday word: never masked alone (the false-positive allow list). */
    static final int COMMON = 4;

    /**
     * Case and possessive endings written without an apostrophe, in folded form (vowel harmony folds to these). Plural
     * and derivational endings are not here on purpose: they turn names into ordinary words (Osmanlı).
     */
    private static final List<String> SUFFIXES = List.of(
        "ndan", "nden", "nin", "nun", "dan", "den", "tan", "ten", "nda", "nde", "yla", "yle", "gil",
        "in", "un", "ya", "ye", "yi", "yu", "ni", "nu", "da", "de", "ta", "te", "la", "le");
    private static final String SINGLE_VOWEL_SUFFIXES = "aeiu";

    private static final NameDictionary STANDARD = load(NameDictionary.class.getClassLoader(),
        "io/rwsafe/control/privacy/names/");

    private final Map<String, Integer> flags;

    NameDictionary(Map<String, Integer> flags) {
        this.flags = Map.copyOf(flags);
    }

    /** The committed dictionary, or null when a resource is missing (masking is then unavailable). */
    static NameDictionary standard() {
        return STANDARD;
    }

    static NameDictionary load(ClassLoader loader, String base) {
        Map<String, Integer> flags = new HashMap<>();
        try {
            add(flags, loader, base + "given-names.txt", GIVEN);
            add(flags, loader, base + "surnames.txt", SURNAME);
            add(flags, loader, base + "common-words.txt", COMMON);
        } catch (IOException e) {
            return null;
        }
        return flags.isEmpty() ? null : new NameDictionary(flags);
    }

    private static void add(Map<String, Integer> flags, ClassLoader loader, String resource, int flag)
        throws IOException {
        try (InputStream in = loader.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IOException("missing name resource");
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            String line;
            while ((line = reader.readLine()) != null) {
                String word = line.strip();
                if (!word.isEmpty() && !word.startsWith("#")) {
                    flags.merge(fold(word), flag, (a, b) -> a | b);
                }
            }
        }
    }

    int size() {
        return flags.size();
    }

    /** The flags of a folded word, 0 when it is not a name ({@link #COMMON} alone is not a name either). */
    int flags(String folded) {
        Integer f = flags.get(folded);
        return f == null || (f & (GIVEN | SURNAME)) == 0 ? 0 : f;
    }

    /**
     * The name stem of a folded word written with a case ending and no apostrophe ({@code ayşenin}, {@code mehmete}),
     * or null. A stem keeps at least three letters, four before a one-vowel ending, so short words stay words.
     */
    String stem(String folded) {
        for (String suffix : SUFFIXES) {
            if (folded.length() - suffix.length() >= 3 && folded.endsWith(suffix)) {
                String stem = folded.substring(0, folded.length() - suffix.length());
                if (flags(stem) != 0) {
                    return stem;
                }
            }
        }
        int last = folded.length() - 1;
        if (last >= 4 && SINGLE_VOWEL_SUFFIXES.indexOf(folded.charAt(last)) >= 0) {
            String stem = folded.substring(0, last);
            if (flags(stem) != 0) {
                return stem;
            }
        }
        return null;
    }

    /** The folded form: NFC, lower case, every i form as {@code i}, Turkish diacritics and combining marks dropped. */
    static String fold(String word) {
        String w = Normalizer.normalize(word, Normalizer.Form.NFC);
        StringBuilder out = new StringBuilder(w.length());
        for (int i = 0; i < w.length(); i++) {
            char c = w.charAt(i);
            int type = Character.getType(c);
            if (type == Character.NON_SPACING_MARK || type == Character.COMBINING_SPACING_MARK) {
                continue;
            }
            out.append(switch (c) {
                case 'I', 'İ', 'ı' -> 'i';
                default -> plain(Character.toLowerCase(c));
            });
        }
        return out.toString();
    }

    private static char plain(char c) {
        return switch (c) {
            case 'ç' -> 'c';
            case 'ğ' -> 'g';
            case 'ö' -> 'o';
            case 'ş' -> 's';
            case 'ü' -> 'u';
            case 'â' -> 'a';
            case 'î' -> 'i';
            case 'û' -> 'u';
            default -> c;
        };
    }
}
