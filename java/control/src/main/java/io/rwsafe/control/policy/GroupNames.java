package io.rwsafe.control.policy;

import java.text.Normalizer;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Directory group names of a scoped rule version (PO decision Q-39, POLICY_SNAPSHOT_CONTRACT format 2), in the one
 * normal form the registry stores, the snapshot carries and the data plane compares: strip, Unicode NFC, the Turkish
 * capital dotted I (U+0130), capital I, dotless i (U+0131) and i all folded to {@code i}, lower case under
 * {@link Locale#ROOT}, any leftover combining dot above (U+0307) removed, NFC again. A name is the short directory group
 * name: 1 to 256 characters after normalisation, no comma, no control character; a version names 1 to 32 groups, none
 * twice after normalisation.
 *
 * <p>The data plane applies the same rule through a shared function in {@code java/policy} (developed in a parallel
 * lane); once both are merged this class should delegate to it. Group names are operator data: nothing here logs or
 * echoes one.
 */
public final class GroupNames {

    public static final int MAX_GROUPS = 32;
    public static final int MAX_LENGTH = 256;

    private GroupNames() {
    }

    /** The normal form of one name, or null when the name is empty after normalisation or breaks the shape. */
    public static String normalise(String raw) {
        if (raw == null) {
            return null;
        }
        String s = Normalizer.normalize(raw.strip(), Normalizer.Form.NFC);
        StringBuilder folded = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            folded.append(c == 'İ' || c == 'I' || c == 'ı' ? 'i' : c);
        }
        String lower = folded.toString().toLowerCase(Locale.ROOT).replace("̇", "");
        String out = Normalizer.normalize(lower, Normalizer.Form.NFC);
        if (out.isEmpty() || out.length() > MAX_LENGTH || out.indexOf(',') >= 0
            || out.chars().anyMatch(Character::isISOControl)) {
            return null;
        }
        return out;
    }

    /**
     * The normal forms of a version's names, sorted so the order the operator typed them never changes the stored row or
     * the snapshot bytes; null when the list is empty, longer than 32, has an invalid name, or names a group twice after
     * normalisation.
     */
    public static List<String> normaliseAll(List<String> raw) {
        if (raw == null || raw.isEmpty() || raw.size() > MAX_GROUPS) {
            return null;
        }
        Set<String> seen = new HashSet<>();
        List<String> out = new ArrayList<>(raw.size());
        for (String g : raw) {
            String n = normalise(g);
            if (n == null || !seen.add(n)) {
                return null;
            }
            out.add(n);
        }
        out.sort(null);
        return List.copyOf(out);
    }

    /** True when every stored name is already in normal form and the list is valid (the compiler's check). */
    public static boolean storedFormOk(List<String> stored) {
        List<String> n = normaliseAll(stored);
        return n != null && n.equals(stored.stream().sorted().toList());
    }
}
