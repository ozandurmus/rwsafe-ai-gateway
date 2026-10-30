package io.rwsafe.control.support;

import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
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
 * <p>Tokens of a text, all lower-cased: every maximal run of letters, digits and {@code . - _ @ \ : + /}; every
 * contiguous span of the letter-and-digit parts inside such a run (so {@code x-<host>-y} still yields {@code <host>});
 * and every run of digits joined across single spaces (so a spaced phone number or IBAN still yields its digits).
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
        classByDigest.put(digest(value.toLowerCase(Locale.ROOT)), canaryClass);
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

    /** The token set of one text (see the class comment). */
    static Set<String> tokens(String text) {
        Set<String> out = new LinkedHashSet<>();
        String s = text.toLowerCase(Locale.ROOT);
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
        // Digit groups joined across single spaces: a phone number written in groups also yields its digit string.
        StringBuilder digits = new StringBuilder();
        for (int k = 0; k <= s.length(); k++) {
            char c = k < s.length() ? s.charAt(k) : '\0';
            if (Character.isDigit(c)) {
                digits.append(c);
            } else if (c == ' ' && digits.length() > 0 && k + 1 < s.length() && Character.isDigit(s.charAt(k + 1))) {
                continue;
            } else {
                if (digits.length() > 0) {
                    out.add(digits.toString());
                }
                digits.setLength(0);
            }
        }
        return out;
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
        // Maximal digit runs inside a part ("ref12345678901" still yields the eleven digits).
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
        return Character.isLetterOrDigit(c) || SEPARATORS.indexOf(c) >= 0;
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
