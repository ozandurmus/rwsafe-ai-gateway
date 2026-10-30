package io.rwsafe.control.privacy;

import com.google.re2j.Matcher;
import com.google.re2j.Pattern;
import io.rwsafe.detect.DetectorSet;
import io.rwsafe.platform.verdict.DataClass;
import io.rwsafe.platform.verdict.Finding;
import java.util.List;
import java.util.Locale;
import java.util.function.Function;

/**
 * The free-text layers of MASKING_AND_PRIVACY B2 for one string, in the {@code rwmask-v1} order: secret shapes and the
 * Turkish and sector identifiers through the Tier-1 detectors (layers 6 and 4), e-mail addresses, IPv4 and IPv6
 * addresses (layer 2), Turkish mobile numbers (layer 4), then the estate dictionary (layer 3). Linear-time RE2/J only.
 * Times such as {@code 12:30:45} and opaque ids are not addresses and stay as they are.
 */
public final class TextMasker {

    /**
     * The rule-set version on every masked page. Slice 1 implements layers 1, 2, 3, the identifier part of 4 and 6 of
     * {@code rwmask-v1}; the Turkish name dictionary (layer 4) and the free-text heuristics (layer 5) arrive before any
     * free-text column (C3, C15) exists, and the version then becomes {@code rwmask-v1} (PR 12 review Q-2).
     */
    public static final String RULE_SET = "rwmask-v1-slice1";

    private static final Pattern EMAIL = Pattern.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)+");
    private static final Pattern IPV4 = Pattern.compile("\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b");
    private static final Pattern IPV6 = Pattern.compile("[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}");
    private static final Pattern TR_MOBILE = Pattern.compile("(?:\\+90 ?|\\b0|\\b)5\\d{2} ?\\d{3} ?\\d{2} ?\\d{2}\\b");
    private static final DetectorSet DETECTORS = DetectorSet.standard();

    private final Pseudonymiser pseudonymiser;
    private final List<String> estateTerms;

    TextMasker(Pseudonymiser pseudonymiser, List<String> estateTerms) {
        this.pseudonymiser = pseudonymiser;
        this.estateTerms = estateTerms;
    }

    public String mask(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        String s = detectors(text);
        s = replace(s, EMAIL, pseudonymiser::user);
        s = replace(s, IPV4, ip -> Pseudonymiser.ipv4(ip) == null ? ip : pseudonymiser.subnet(ip));
        s = replace(s, IPV6, v6 -> looksLikeIpv6(v6) ? Pseudonymiser.REDACTED_IP : v6);
        s = replace(s, TR_MOBILE, phone -> pseudonymiser.token("TEL", subscriber(phone)));
        return estate(s);
    }

    private String detectors(String text) {
        List<Finding> findings = DETECTORS.scan(text);
        if (findings.isEmpty()) {
            return text;
        }
        StringBuilder out = new StringBuilder(text.length());
        int cursor = 0;
        int i = 0;
        while (i < findings.size()) {
            Finding f = findings.get(i);
            int start = Math.max(f.start(), cursor);
            int end = f.end();
            int j = i + 1;
            while (j < findings.size() && findings.get(j).start() < end) {
                end = Math.max(end, findings.get(j).end());
                j++;
            }
            if (end > start) {
                out.append(text, cursor, start).append(replacement(f.dataClass(), text.substring(start, end)));
                cursor = end;
            }
            i = j;
        }
        return out.append(text, cursor, text.length()).toString();
    }

    private String replacement(DataClass dataClass, String value) {
        return switch (dataClass) {
            case SECRET -> dataClass.redactionToken();
            case TCKN -> pseudonymiser.token("TCKN", value);
            case TR_IBAN -> pseudonymiser.token("IBAN-TR", value.replace(" ", "").toUpperCase(Locale.ROOT));
            case PAYMENT_CARD -> pseudonymiser.token("CARD", value.replace(" ", "").replace("-", ""));
        };
    }

    /** The ten subscriber digits, whatever the prefix ({@code +90}, {@code 0} or none): one number, one token (D-10). */
    static String subscriber(String phone) {
        StringBuilder digits = new StringBuilder();
        for (int i = 0; i < phone.length(); i++) {
            if (Character.isDigit(phone.charAt(i))) {
                digits.append(phone.charAt(i));
            }
        }
        return digits.length() > 10 ? digits.substring(digits.length() - 10) : digits.toString();
    }

    /** At least two colons and either {@code ::} or a hex letter: a time of day is neither. */
    private static boolean looksLikeIpv6(String candidate) {
        if (candidate.contains("::")) {
            return true;
        }
        for (int i = 0; i < candidate.length(); i++) {
            char c = Character.toLowerCase(candidate.charAt(i));
            if (c >= 'a' && c <= 'f') {
                return true;
            }
        }
        return false;
    }

    /** Estate terms inside tokens of letters, digits and {@code ._:-} (layer 3: the token or any of its parts). */
    private String estate(String s) {
        if (estateTerms.isEmpty()) {
            return s;
        }
        StringBuilder out = new StringBuilder(s.length());
        int i = 0;
        while (i < s.length()) {
            if (!tokenChar(s.charAt(i))) {
                out.append(s.charAt(i++));
                continue;
            }
            int end = i;
            while (end < s.length() && tokenChar(s.charAt(end))) {
                end++;
            }
            out.append(estateToken(s.substring(i, end)));
            i = end;
        }
        return out.toString();
    }

    /**
     * Every occurrence of a term that starts and ends on the token's edges or on a {@code ._:-} separator. Matching is
     * case-insensitive per character on the original token, so a case mapping that changes length (a Turkish dotted
     * capital I lower-cases to two characters) cannot shift the offsets (PR 12 review D-01). Terms come longest first.
     */
    private String estateToken(String token) {
        for (String term : estateTerms) {
            int at = 0;
            while (!term.isEmpty() && at + term.length() <= token.length()) {
                int end = at + term.length();
                boolean edges = (at == 0 || isSeparator(token.charAt(at - 1)))
                    && (end == token.length() || isSeparator(token.charAt(end)));
                if (edges && token.regionMatches(true, at, term, 0, term.length())) {
                    String replacement = pseudonymiser.token("EST", term);
                    token = token.substring(0, at) + replacement + token.substring(end);
                    at += replacement.length();
                } else {
                    at++;
                }
            }
        }
        return token;
    }

    private static boolean tokenChar(char c) {
        return Character.isLetterOrDigit(c) || isSeparator(c);
    }

    private static boolean isSeparator(char c) {
        return c == '.' || c == '_' || c == ':' || c == '-';
    }

    private static String replace(String s, Pattern pattern, Function<String, String> replacement) {
        Matcher m = pattern.matcher(s);
        if (!m.find()) {
            return s;
        }
        StringBuilder out = new StringBuilder(s.length());
        int cursor = 0;
        do {
            out.append(s, cursor, m.start()).append(replacement.apply(m.group()));
            cursor = m.end();
        } while (m.find());
        return out.append(s, cursor, s.length()).toString();
    }
}
