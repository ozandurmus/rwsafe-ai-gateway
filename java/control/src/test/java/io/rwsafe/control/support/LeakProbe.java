package io.rwsafe.control.support;

import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * The canary digest comparison of MASKING_AND_PRIVACY part C (AC-5, SR-PRIV-2; the neXus {@code e2e_canary_digests}
 * pattern). Every seeded real token is held only as an HMAC digest under a key generated for this run; every response is
 * cut into tokens, each token is digested the same way, and a match reports the location class (endpoint template and
 * JSON path with array indices erased) and the canary class, never the value.
 *
 * <p>Canaries and texts are compared in one form ({@link #fold}): NFC, Turkish letters folded to ASCII, lower case,
 * combining marks dropped, so {@code İ}, a decomposed {@code ü} and {@code u} agree (PR 24 review D-02). Tokens of a
 * text: every maximal run of letters, digits, combining marks and {@code . - _ @ \ : + /}; every contiguous span of the
 * letter-and-digit parts inside such a run (so {@code x-<host>-y} still yields {@code <host>}); every maximal digit run
 * inside a run (so {@code ref<digits>} still yields the digits); for digits written in groups across single spaces,
 * hyphens, dots or underscores, every contiguous span of the groups (a phone, card or IBAN written in groups, even after
 * a prefix group); and the same again for the text with each run of valid percent escapes decoded. A multi-word canary is also registered word by word (words of four or more letters and digits).
 */
public final class LeakProbe {

    /** One finding: where (classes only) and what class of canary; the value is never held here. */
    public record Hit(String location, String canaryClass) {

        @Override
        public String toString() {
            return location + " <- " + canaryClass;
        }
    }

    private static final String SEPARATORS = ".-_@\\:+/";
    private static final String DIGIT_JOINERS = " -._";

    private final SecretKeySpec key;
    private final Map<String, String> classByDigest = new HashMap<>();
    private final Set<String> classes = new TreeSet<>();

    public LeakProbe() {
        byte[] k = new byte[32];
        new SecureRandom().nextBytes(k);
        key = new SecretKeySpec(k, "HmacSHA256");
    }

    /** Registers a canary value of {@code canaryClass}; the value is digested at once and not kept. */
    public void canary(String canaryClass, String value) {
        String f = fold(value);
        classByDigest.put(digest(f), canaryClass);
        String[] words = f.split("\\s+");
        if (words.length > 1) {
            for (String word : words) {
                String core = trimSeparators(word);
                if (alphanumeric(core) >= 4) {
                    classByDigest.putIfAbsent(digest(core), canaryClass);
                }
            }
        }
        classes.add(canaryClass);
    }

    public Set<String> classes() {
        return classes;
    }

    public int size() {
        return classByDigest.size();
    }

    /** Scans every string leaf and field name of {@code body}; the location is {@code endpoint} plus the path class. */
    public List<Hit> scan(String endpoint, JsonNode body) {
        List<Hit> hits = new ArrayList<>();
        if (body != null) {
            walk(endpoint, "$", body, hits);
        }
        return hits;
    }

    /** Scans one text (a header value, a log, a raw body); {@code location} names its class. */
    public List<Hit> scanText(String location, String text) {
        List<Hit> hits = new ArrayList<>();
        if (text == null) {
            return hits;
        }
        Set<String> seen = new TreeSet<>();
        for (String token : tokens(text)) {
            String cls = classByDigest.get(digest(token));
            if (cls != null && seen.add(cls)) {
                hits.add(new Hit(location, cls));
            }
        }
        return hits;
    }

    private void walk(String endpoint, String path, JsonNode node, List<Hit> hits) {
        if (node.isObject()) {
            for (var it = node.properties().iterator(); it.hasNext(); ) {
                var e = it.next();
                hits.addAll(scanText(endpoint + " " + path + " (field name)", e.getKey()));
                walk(endpoint, path + "." + e.getKey(), e.getValue(), hits);
            }
        } else if (node.isArray()) {
            for (JsonNode element : node) {
                walk(endpoint, path + "[]", element, hits);
            }
        } else if (!node.isNull()) {
            hits.addAll(scanText(endpoint + " " + path, node.asText()));
        }
    }

    /** NFC, Turkish letters folded to ASCII, lower case ({@code Locale.ROOT}), combining marks dropped. */
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
        return b.toString().toLowerCase(Locale.ROOT);
    }

    /** The token set of one text (see the class comment). */
    static Set<String> tokens(String text) {
        Set<String> out = new LinkedHashSet<>();
        collect(fold(text), out);
        if (text.indexOf('%') >= 0) {
            // Each run of valid %XX escapes is decoded on its own, so a stray '%' elsewhere cannot stop it (N-03).
            String decoded = percentDecoded(text);
            collect(fold(decoded), out);
            collect(fold(decoded.replace('+', ' ')), out);
        }
        return out;
    }

    /** Decodes every maximal run of {@code %XX} escapes as UTF-8; anything else stays as it is. */
    static String percentDecoded(String text) {
        StringBuilder out = new StringBuilder(text.length());
        int i = 0;
        while (i < text.length()) {
            if (escapeAt(text, i)) {
                java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
                while (escapeAt(text, i)) {
                    bytes.write(Integer.parseInt(text.substring(i + 1, i + 3), 16));
                    i += 3;
                }
                out.append(bytes.toString(StandardCharsets.UTF_8));
            } else {
                out.append(text.charAt(i++));
            }
        }
        return out.toString();
    }

    private static boolean escapeAt(String text, int i) {
        return i + 2 < text.length() && text.charAt(i) == '%' && Character.digit(text.charAt(i + 1), 16) >= 0
            && Character.digit(text.charAt(i + 2), 16) >= 0;
    }

    private static void collect(String s, Set<String> out) {
        int i = 0;
        while (i < s.length()) {
            if (!compoundChar(s.charAt(i))) {
                i++;
                continue;
            }
            int end = i;
            while (end < s.length() && compoundChar(s.charAt(end))) {
                end++;
            }
            compound(s.substring(i, end), out);
            i = end;
        }
        // Digit groups joined across one space, hyphen, dot or underscore: a number written in groups yields every
        // contiguous span of its groups, so a prefix group ("v1-" before a card) cannot hide the number (N-03).
        List<String> groups = new ArrayList<>();
        StringBuilder digits = new StringBuilder();
        for (int k = 0; k <= s.length(); k++) {
            char c = k < s.length() ? s.charAt(k) : '\0';
            if (Character.isDigit(c)) {
                digits.append(c);
            } else if (c != '\0' && DIGIT_JOINERS.indexOf(c) >= 0 && digits.length() > 0 && k + 1 < s.length()
                && Character.isDigit(s.charAt(k + 1))) {
                groups.add(digits.toString());
                digits.setLength(0);
            } else {
                if (digits.length() > 0) {
                    groups.add(digits.toString());
                }
                spans(groups, out);
                groups.clear();
                digits.setLength(0);
            }
        }
    }

    private static void spans(List<String> groups, Set<String> out) {
        for (int a = 0; a < groups.size(); a++) {
            StringBuilder b = new StringBuilder();
            for (int z = a; z < groups.size(); z++) {
                b.append(groups.get(z));
                out.add(b.toString());
            }
        }
    }

    private static void compound(String run, Set<String> out) {
        out.add(run);
        List<int[]> parts = new ArrayList<>();
        int k = 0;
        while (k < run.length()) {
            if (SEPARATORS.indexOf(run.charAt(k)) >= 0) {
                k++;
                continue;
            }
            int end = k;
            while (end < run.length() && SEPARATORS.indexOf(run.charAt(end)) < 0) {
                end++;
            }
            parts.add(new int[] {k, end});
            k = end;
        }
        for (int a = 0; a < parts.size(); a++) {
            for (int b = a; b < parts.size(); b++) {
                out.add(run.substring(parts.get(a)[0], parts.get(b)[1]));
            }
        }
        int d = 0;
        while (d < run.length()) {
            if (!Character.isDigit(run.charAt(d))) {
                d++;
                continue;
            }
            int end = d;
            while (end < run.length() && Character.isDigit(run.charAt(end))) {
                end++;
            }
            out.add(run.substring(d, end));
            d = end;
        }
    }

    private static boolean compoundChar(char c) {
        return Character.isLetterOrDigit(c) || SEPARATORS.indexOf(c) >= 0
            || Character.getType(c) == Character.NON_SPACING_MARK;
    }

    private static String trimSeparators(String word) {
        int a = 0;
        int b = word.length();
        while (a < b && !Character.isLetterOrDigit(word.charAt(a))) {
            a++;
        }
        while (b > a && !Character.isLetterOrDigit(word.charAt(b - 1))) {
            b--;
        }
        return word.substring(a, b);
    }

    private static int alphanumeric(String s) {
        int n = 0;
        for (int i = 0; i < s.length(); i++) {
            if (Character.isLetterOrDigit(s.charAt(i))) {
                n++;
            }
        }
        return n;
    }

    private String digest(String token) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            return java.util.HexFormat.of().formatHex(mac.doFinal(token.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }
}
