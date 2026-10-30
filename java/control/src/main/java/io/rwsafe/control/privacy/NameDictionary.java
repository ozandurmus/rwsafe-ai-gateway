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
    /**
     * A name that is also an everyday word (the false-positive allow list): in lower case and alone it stays a word; in a
     * name position (capitalised, next to another name word, after or before a title) it is a name.
     */
    static final int COMMON = 4;

    /**
     * Case and possessive endings written without an apostrophe, in folded form (vowel harmony folds to these), simple
     * and compound (possessive plus case: {@code -ına}, {@code -ından}, {@code -ıyla}, {@code -ninki}). Plural and
     * derivational endings are not here on purpose: they turn names into ordinary words (Osmanlı).
     */
    private static final List<String> SUFFIXES = List.of(
        "ninki", "nunki", "inki", "unki", "indan", "inden", "undan", "ndan", "nden", "inda", "inde", "unda", "iyla",
        "iyle", "uyla", "ina", "ine", "una", "ini", "unu", "nin", "nun", "dan", "den", "tan", "ten", "nda", "nde", "yla",
        "yle", "gil", "in", "un", "ya", "ye", "yi", "yu", "ni", "nu", "da", "de", "ta", "te", "la", "le", "a", "e", "i",
        "u");
    /** A stem this short (two or three letters) counts only next to another name word or capitalised. */
    static final int SHORT_STEM = 3;

    /**
     * A dictionary word found in a folded word: its key (the folded name), its flags, whether a case ending was cut
     * without an apostrophe, and whether the name is {@link #SHORT_STEM} letters or fewer.
     */
    record Match(String key, int flags, boolean suffixed, boolean shortStem) {
    }

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
     * The name in a folded word. The word itself first (also with a softened final consonant restored: {@code mehmed},
     * {@code burag}); with {@code apostrophe} the ending was already cut, so nothing more is stripped. Otherwise every
     * case ending that leaves a stem of two letters or more is tried and the best stem wins: a name that is not an
     * everyday word before one that is, then the longest ({@code gülaya} is Gülay, not Gül; {@code aysele} is Aysel).
     */
    Match match(String folded, boolean apostrophe) {
        String exact = lookup(folded);
        if (exact != null) {
            return new Match(exact, flags(exact), false, exact.length() <= SHORT_STEM);
        }
        if (apostrophe) {
            return null;
        }
        String best = null;
        for (String suffix : SUFFIXES) {
            int stemLength = folded.length() - suffix.length();
            if (stemLength < 2 || !folded.endsWith(suffix)) {
                continue;
            }
            String stem = lookup(folded.substring(0, stemLength));
            if (stem != null && better(stem, best)) {
                best = stem;
            }
        }
        return best == null ? null : new Match(best, flags(best), true, best.length() <= SHORT_STEM);
    }

    /** The dictionary key for {@code stem}, trying a softened final consonant (b, d, g for p, t, k) as well. */
    private String lookup(String stem) {
        if (flags(stem) != 0) {
            return stem;
        }
        if (stem.length() < 2) {
            return null;
        }
        char last = stem.charAt(stem.length() - 1);
        char hard = switch (last) {
            case 'b' -> 'p';
            case 'd' -> 't';
            case 'g' -> 'k';
            default -> 0;
        };
        if (hard == 0) {
            return null;
        }
        String restored = stem.substring(0, stem.length() - 1) + hard;
        return flags(restored) != 0 ? restored : null;
    }

    private boolean better(String candidate, String best) {
        if (best == null) {
            return true;
        }
        boolean candidateCommon = (flags(candidate) & COMMON) != 0;
        boolean bestCommon = (flags(best) & COMMON) != 0;
        if (candidateCommon != bestCommon) {
            return !candidateCommon;
        }
        return candidate.length() > best.length();
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
