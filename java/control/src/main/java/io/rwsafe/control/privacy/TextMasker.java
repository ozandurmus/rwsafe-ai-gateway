package io.rwsafe.control.privacy;

import com.google.re2j.Matcher;
import com.google.re2j.Pattern;
import io.rwsafe.detect.DetectorSet;
import io.rwsafe.detect.TcknDetector;
import io.rwsafe.platform.verdict.DataClass;
import io.rwsafe.platform.verdict.Finding;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.Function;

/**
 * The text layers of MASKING_AND_PRIVACY B2 for one string, rule set {@value #RULE_SET}. Linear-time RE2/J and plain
 * scans only; no {@code java.util.regex}.
 *
 * <p>{@link #mask} is for every string a masked page shows (ids, hosts, vocabulary, short values): secret shapes and the
 * Turkish and sector identifiers through the Tier-1 detectors (layers 6 and 4), e-mail, IPv4 and IPv6 addresses (layer
 * 2), Turkish mobile numbers and a TCKN or mobile number glued to letters (layer 4), the estate dictionary (layer 3) and
 * a Turkish name run, a given name next to a family name (layer 4). Times such as {@code 12:30:45}, opaque ids and public
 * host names stay as they are.
 *
 * <p>{@link #maskFreeText} is for sentences people write or read (reasons, details, messages): everything above plus the
 * heuristic pass of layer 5 (domain accounts, IBAN-shaped groups, addresses glued to letters, digit runs of six or more
 * glued to letters, host-shaped dotted labels) and a lone common given name.
 */
public final class TextMasker {

    /**
     * The rule-set version on every masked page. {@code rwmask-v2} adds to slice 1 the Turkish name dictionary (layer 4)
     * and the free-text heuristics (layer 5). Layer 5's keyword-following word, project code names and user-directory
     * paths, and the PO's customer-number formats (Q-23), are not in it yet.
     */
    public static final String RULE_SET = "rwmask-v2";

    /**
     * What the masked role reads in place of free text a person wrote (retirement and withdrawal reasons, a correlation
     * id that is not a UUID): the masking layers cannot recognise a name, so such text is withheld, not masked (PO
     * decision on PR 24 review Q-1: permanently).
     */
    public static final String WITHHELD = "[FREE_TEXT_WITHHELD]";

    private static final Pattern EMAIL = Pattern.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)+");
    private static final Pattern IPV4 = Pattern.compile("\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b");
    private static final Pattern IPV4_ANYWHERE = Pattern.compile("[0-9]{1,3}(?:\\.[0-9]{1,3}){3}");
    private static final Pattern IPV6 = Pattern.compile("[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}");
    private static final Pattern TR_MOBILE = Pattern.compile("(?:\\+90 ?|\\b0|\\b)5\\d{2} ?\\d{3} ?\\d{2} ?\\d{2}\\b");
    /** {@code DOMAIN\\user}: the same claim spelling the user column pseudonymises (PHASE0_PROXYSG_RECORD F-3). */
    private static final Pattern DOMAIN_ACCOUNT =
        Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,63}\\\\[A-Za-z0-9][A-Za-z0-9._$-]{0,63}");
    /** Country code, check digits, one alphanumeric group, then digit groups, compact or in groups of four. */
    private static final Pattern IBAN_SHAPE =
        Pattern.compile("[A-Za-z]{2}[0-9]{2}(?: ?[A-Za-z0-9]{4})(?: ?[0-9]{4}){1,7}(?: ?[0-9]{1,3})?");
    private static final int IBAN_MIN_DIGITS = 12;
    private static final int GLUED_DIGITS = 6;
    private static final Set<String> TOP_LEVEL = Set.of("com", "net", "org", "edu", "gov", "mil", "int", "info", "biz",
        "io", "ai", "dev", "app", "co", "tr", "uk", "de", "eu", "us", "local", "lan", "corp", "internal", "intra",
        "intranet", "localdomain", "home", "arpa", "example", "invalid", "test", "localhost", "cloud", "online", "site",
        "tech");
    /** Labels of the tokens this masker writes; a word right after {@code LABEL-} is a pseudonym, never re-masked. */
    private static final Set<String> TOKEN_LABELS =
        Set.of("USR", "TCKN", "TR", "CARD", "TEL", "EST", "NAME", "HST", "NUM", "IBAN", "GRP");
    private static final int MAX_RUN = 4;
    /** The detector set keeps at most {@link DetectorSet#MAX_FINDINGS}; longer texts are scanned in pieces. */
    private static final int DETECTOR_CHUNK = 8192;
    static final String OVER_LIMIT = "[REDACTED:OVER_LIMIT]";
    private static final DetectorSet DETECTORS = DetectorSet.standard();

    private final Pseudonymiser pseudonymiser;
    private final List<String> estateTerms;
    private final NameDictionary names;

    TextMasker(Pseudonymiser pseudonymiser, List<String> estateTerms, NameDictionary names) {
        this.pseudonymiser = pseudonymiser;
        this.estateTerms = estateTerms;
        this.names = names;
    }

    /**
     * A directory group name: always replaced by its keyed pseudonym, never passed through the free-text layers (a
     * group name is an estate identifier whatever it contains).
     */
    public String group(String name) {
        return pseudonymiser.group(name);
    }

    /** A string a masked page shows that is not a sentence: identifiers become class tokens, names in pairs. */
    public String mask(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        String s = detectors(text);
        s = replace(s, EMAIL, pseudonymiser::user);
        s = replace(s, IPV4, ip -> Pseudonymiser.ipv4(ip) == null ? ip : pseudonymiser.subnet(ip));
        s = replace(s, IPV6, v6 -> looksLikeIpv6(v6) ? Pseudonymiser.REDACTED_IP : v6);
        s = replace(s, TR_MOBILE, phone -> pseudonymiser.token("TEL", subscriber(phone)));
        s = gluedDigits(s, false);
        s = estate(s);
        return names(s, false);
    }

    /**
     * A sentence (a reason, a detail, a message): {@link #mask} plus the heuristic pass (layer 5) and lone common given
     * names. Masks more than it must rather than less.
     */
    public String maskFreeText(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        String s = detectors(text);
        s = replace(s, EMAIL, pseudonymiser::user);
        s = replace(s, DOMAIN_ACCOUNT, pseudonymiser::user);
        s = ibanShapes(s);
        s = replaceIpv4Anywhere(s);
        s = replace(s, IPV6, v6 -> looksLikeIpv6(v6) ? Pseudonymiser.REDACTED_IP : v6);
        s = replace(s, TR_MOBILE, phone -> pseudonymiser.token("TEL", subscriber(phone)));
        s = gluedDigits(s, true);
        s = hosts(s);
        s = estate(s);
        return names(s, true);
    }

    // ---- layers 6 and 4: the Tier-1 detectors -------------------------------------------------------------------

    private String detectors(String text) {
        if (text.length() <= DETECTOR_CHUNK) {
            return detectorsIn(text);
        }
        StringBuilder out = new StringBuilder(text.length());
        int from = 0;
        while (from < text.length()) {
            int to = chunkEnd(text, from);
            out.append(detectorsIn(text.substring(from, to)));
            from = to;
        }
        return out.toString();
    }

    /**
     * A piece ends on whitespace that does not sit between two digits (a spaced IBAN, card or phone number is never cut),
     * near {@link #DETECTOR_CHUNK}; a piece with no such place runs on to the next one.
     */
    private static int chunkEnd(String text, int from) {
        int n = text.length();
        if (n - from <= DETECTOR_CHUNK) {
            return n;
        }
        for (int i = from + DETECTOR_CHUNK; i < n; i++) {
            if (Character.isWhitespace(text.charAt(i))
                && !(Character.isDigit(text.charAt(i - 1)) && i + 1 < n && Character.isDigit(text.charAt(i + 1)))) {
                return i + 1;
            }
        }
        return n;
    }

    /** One piece; a piece in which the detectors reach their finding limit is withheld whole (fail closed). */
    private String detectorsIn(String text) {
        List<Finding> findings = DETECTORS.scan(text);
        if (findings.isEmpty()) {
            return text;
        }
        if (DetectorSet.overLimit(findings)) {
            return OVER_LIMIT;
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

    // ---- layer 5: heuristics over free text -----------------------------------------------------------------------

    /**
     * IBAN-shaped groups the TR detector did not take (another country, a bad check digit, glued to text): at least
     * twelve digits; a valid TR IBAN reads as the detector's token, anything else as {@code IBAN-}.
     */
    private String ibanShapes(String s) {
        Matcher m = IBAN_SHAPE.matcher(s);
        StringBuilder out = null;
        int cursor = 0;
        while (m.find()) {
            String value = m.group();
            int digits = 0;
            for (int i = 0; i < value.length(); i++) {
                digits += Character.isDigit(value.charAt(i)) ? 1 : 0;
            }
            if (digits < IBAN_MIN_DIGITS || (m.end() < s.length() && Character.isLetterOrDigit(s.charAt(m.end())))
                || (m.start() > 0 && Character.isDigit(s.charAt(m.start() - 1)))) {
                continue;
            }
            String compact = value.replace(" ", "").toUpperCase(Locale.ROOT);
            String token = compact.startsWith("TR") && mod97(compact) ? pseudonymiser.token("IBAN-TR", compact)
                : pseudonymiser.token("IBAN", compact);
            if (out == null) {
                out = new StringBuilder(s.length());
            }
            out.append(s, cursor, m.start()).append(token);
            cursor = m.end();
        }
        return out == null ? s : out.append(s, cursor, s.length()).toString();
    }

    /** ISO 13616: the first four characters moved to the end, letters as 10..35, remainder 1 under 97. */
    static boolean mod97(String compact) {
        String rearranged = compact.substring(4) + compact.substring(0, 4);
        int rem = 0;
        for (int i = 0; i < rearranged.length(); i++) {
            char c = rearranged.charAt(i);
            int v = Character.isDigit(c) ? c - '0' : c - 'A' + 10;
            rem = (v > 9 ? rem * 100 + v : rem * 10 + v) % 97;
        }
        return rem == 1;
    }

    /** Dotted quads with a letter on either side as well ({@code host10.0.0.1}); never inside a longer dotted number. */
    private String replaceIpv4Anywhere(String s) {
        Matcher m = IPV4_ANYWHERE.matcher(s);
        StringBuilder out = null;
        int cursor = 0;
        while (m.find()) {
            int start = m.start();
            int end = m.end();
            boolean before = start > 0 && (Character.isDigit(s.charAt(start - 1))
                || (s.charAt(start - 1) == '.' && start > 1 && Character.isDigit(s.charAt(start - 2))));
            boolean after = end < s.length() && (Character.isDigit(s.charAt(end))
                || (s.charAt(end) == '.' && end + 1 < s.length() && Character.isDigit(s.charAt(end + 1))));
            if (before || after || Pseudonymiser.ipv4(m.group()) == null) {
                continue;
            }
            if (out == null) {
                out = new StringBuilder(s.length());
            }
            out.append(s, cursor, start).append(pseudonymiser.subnet(m.group()));
            cursor = end;
        }
        return out == null ? s : out.append(s, cursor, s.length()).toString();
    }

    /**
     * A run of digits glued to a letter on either side, which the word-bounded detectors miss: a valid TCKN reads as
     * {@code TCKN-}, a Turkish mobile number as {@code TEL-} (both in every field); in free text any other run of six or
     * more digits reads as {@code NUM-}. Pseudonyms this masker wrote are left alone.
     */
    private String gluedDigits(String s, boolean freeText) {
        StringBuilder out = null;
        int cursor = 0;
        int n = s.length();
        int i = 0;
        while (i < n) {
            if (!isAsciiDigit(s.charAt(i))) {
                i++;
                continue;
            }
            int start = i;
            while (i < n && isAsciiDigit(s.charAt(i))) {
                i++;
            }
            int end = i;
            boolean glued = (start > 0 && Character.isLetter(s.charAt(start - 1)))
                || (end < n && Character.isLetter(s.charAt(end)));
            if (end - start < GLUED_DIGITS || !glued || insidePseudonym(s, start)) {
                continue;
            }
            String token = gluedToken(s.substring(start, end), freeText);
            if (token == null) {
                continue;
            }
            if (out == null) {
                out = new StringBuilder(n);
            }
            out.append(s, cursor, start).append(token);
            cursor = end;
        }
        return out == null ? s : out.append(s, cursor, n).toString();
    }

    private String gluedToken(String digits, boolean freeText) {
        List<Finding> tckn = new ArrayList<>(1);
        new TcknDetector().scan(digits, tckn);
        if (!tckn.isEmpty()) {
            return pseudonymiser.token("TCKN", digits);
        }
        int len = digits.length();
        if ((len == 10 && digits.startsWith("5")) || (len == 11 && digits.startsWith("05"))
            || (len == 12 && digits.startsWith("905"))) {
            return pseudonymiser.token("TEL", subscriber(digits));
        }
        return freeText ? pseudonymiser.token("NUM", digits) : null;
    }

    /** True when the letters-and-digits word around {@code index} directly follows a {@code LABEL-} this masker wrote. */
    private static boolean insidePseudonym(String s, int index) {
        int w = index;
        while (w > 0 && Character.isLetterOrDigit(s.charAt(w - 1))) {
            w--;
        }
        return afterTokenLabel(s, w);
    }

    private static boolean afterTokenLabel(String s, int wordStart) {
        if (wordStart < 2 || s.charAt(wordStart - 1) != '-') {
            return false;
        }
        int k = wordStart - 1;
        while (k > 0 && s.charAt(k - 1) >= 'A' && s.charAt(k - 1) <= 'Z') {
            k--;
        }
        return TOKEN_LABELS.contains(s.substring(k, wordStart - 1));
    }

    /**
     * Host-shaped dotted labels: three or more labels, or two whose last is a known top-level name, the last label
     * letters only ({@code chat.vendor.example}, {@code node7.example.com}); never a version or a decimal.
     */
    private String hosts(String s) {
        StringBuilder out = null;
        int cursor = 0;
        int n = s.length();
        int i = 0;
        while (i < n) {
            if (!hostChar(s.charAt(i))) {
                i++;
                continue;
            }
            int start = i;
            while (i < n && hostChar(s.charAt(i))) {
                i++;
            }
            int a = start;
            int b = i;
            while (a < b && (s.charAt(a) == '.' || s.charAt(a) == '-')) {
                a++;
            }
            while (b > a && (s.charAt(b - 1) == '.' || s.charAt(b - 1) == '-')) {
                b--;
            }
            if (b <= a || !hostShaped(s.substring(a, b))) {
                continue;
            }
            if (out == null) {
                out = new StringBuilder(n);
            }
            out.append(s, cursor, a).append(pseudonymiser.token("HST", s.substring(a, b).toLowerCase(Locale.ROOT)));
            cursor = b;
        }
        return out == null ? s : out.append(s, cursor, n).toString();
    }

    private static boolean hostShaped(String candidate) {
        int labels = 1;
        int labelStart = 0;
        for (int i = 0; i <= candidate.length(); i++) {
            if (i == candidate.length() || candidate.charAt(i) == '.') {
                int length = i - labelStart;
                if (length == 0 || length > 63) {
                    return false;
                }
                if (i < candidate.length()) {
                    labels++;
                    labelStart = i + 1;
                }
            }
        }
        String last = candidate.substring(labelStart);
        if (labels < 2 || last.length() < 2 || last.length() > 24) {
            return false;
        }
        for (int i = 0; i < last.length(); i++) {
            if (!Character.isLetter(last.charAt(i))) {
                return false;
            }
        }
        return labels >= 3 || TOP_LEVEL.contains(last.toLowerCase(Locale.ROOT));
    }

    private static boolean hostChar(char c) {
        return Character.isLetterOrDigit(c) || c == '.' || c == '-';
    }

    private static boolean isAsciiDigit(char c) {
        return c >= '0' && c <= '9';
    }

    // ---- layer 3: the estate dictionary ---------------------------------------------------------------------------

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

    // ---- layer 4: Turkish names -----------------------------------------------------------------------------------

    /** One whole word found in the name dictionary; {@code end} includes a case ending. */
    private record NameWord(int start, int end, String key, int flags, boolean capitalised, boolean suffixed) {

        boolean given() {
            return (flags & NameDictionary.GIVEN) != 0;
        }

        boolean surname() {
            return (flags & NameDictionary.SURNAME) != 0;
        }

        boolean common() {
            return (flags & NameDictionary.COMMON) != 0;
        }
    }

    /**
     * Name runs: up to four dictionary words joined by spaces or one {@code ._-}, a case ending on the last word only
     * ({@code Ayşe'nin}, {@code Mehmete}). A run with a given name and a family name becomes one {@code NAME-} token
     * when one of its words is not an everyday word or every word is capitalised; in free text a lone given name that is
     * not an everyday word becomes a {@code NAME-} token too. The ending is dropped with the name.
     */
    private String names(String s, boolean freeText) {
        List<int[]> spans = new ArrayList<>();
        List<String> tokens = new ArrayList<>();
        List<NameWord> run = new ArrayList<>(MAX_RUN);
        int n = s.length();
        int i = 0;
        while (i < n) {
            if (!wordChar(s.charAt(i))) {
                i++;
                continue;
            }
            int start = i;
            while (i < n && wordChar(s.charAt(i))) {
                i++;
            }
            int stemEnd = i;
            boolean apostrophe = false;
            if (i + 1 < n && isApostrophe(s.charAt(i)) && Character.isLetter(s.charAt(i + 1))) {
                apostrophe = true;
                i++;
                while (i < n && wordChar(s.charAt(i))) {
                    i++;
                }
            }
            NameWord word = nameWord(s, start, stemEnd, i, apostrophe);
            if (word == null) {
                flush(run, freeText, spans, tokens);
                continue;
            }
            if (!run.isEmpty() && !joins(s, run.get(run.size() - 1), word)) {
                flush(run, freeText, spans, tokens);
            }
            run.add(word);
            if (word.suffixed() || run.size() == MAX_RUN) {
                flush(run, freeText, spans, tokens);
            }
        }
        flush(run, freeText, spans, tokens);
        if (spans.isEmpty()) {
            return s;
        }
        StringBuilder out = new StringBuilder(n);
        int cursor = 0;
        for (int k = 0; k < spans.size(); k++) {
            out.append(s, cursor, spans.get(k)[0]).append(tokens.get(k));
            cursor = spans.get(k)[1];
        }
        return out.append(s, cursor, n).toString();
    }

    private NameWord nameWord(String s, int start, int stemEnd, int end, boolean apostrophe) {
        boolean wholeWord = (start == 0 || !Character.isLetterOrDigit(s.charAt(start - 1)))
            && (end == s.length() || !Character.isLetterOrDigit(s.charAt(end)));
        if (!wholeWord || afterTokenLabel(s, start)) {
            return null;
        }
        String folded = NameDictionary.fold(s.substring(start, stemEnd));
        int flags = names.flags(folded);
        boolean suffixed = apostrophe;
        if (flags == 0 && !apostrophe) {
            String stem = names.stem(folded);
            if (stem == null) {
                return null;
            }
            folded = stem;
            flags = names.flags(stem);
            suffixed = true;
        }
        if (flags == 0) {
            return null;
        }
        char first = s.charAt(start);
        return new NameWord(start, end, folded, flags, Character.isUpperCase(first) || Character.isTitleCase(first),
            suffixed);
    }

    /** Two words join a run across a space run (no line break) or exactly one of {@code ._-}. */
    private static boolean joins(String s, NameWord previous, NameWord next) {
        int gap = next.start() - previous.end();
        if (gap == 1 && (s.charAt(previous.end()) == '.' || s.charAt(previous.end()) == '_'
            || s.charAt(previous.end()) == '-')) {
            return true;
        }
        if (gap < 1 || gap > 3) {
            return false;
        }
        for (int k = previous.end(); k < next.start(); k++) {
            char c = s.charAt(k);
            if (c != ' ' && c != '\t' && c != ' ') {
                return false;
            }
        }
        return true;
    }

    private void flush(List<NameWord> run, boolean freeText, List<int[]> spans, List<String> tokens) {
        if (run.isEmpty()) {
            return;
        }
        if (isPerson(run)) {
            StringBuilder key = new StringBuilder();
            for (NameWord w : run) {
                key.append(key.isEmpty() ? "" : " ").append(w.key());
            }
            spans.add(new int[] {run.get(0).start(), run.get(run.size() - 1).end()});
            tokens.add(pseudonymiser.token("NAME", key.toString()));
        } else if (freeText) {
            for (NameWord w : run) {
                if (w.given() && !w.common()) {
                    spans.add(new int[] {w.start(), w.end()});
                    tokens.add(pseudonymiser.token("NAME", w.key()));
                }
            }
        }
        run.clear();
    }

    private static boolean isPerson(List<NameWord> run) {
        if (run.size() < 2) {
            return false;
        }
        boolean pair = false;
        for (int a = 0; a < run.size() && !pair; a++) {
            for (int b = 0; b < run.size() && !pair; b++) {
                pair = a != b && run.get(a).given() && run.get(b).surname();
            }
        }
        if (!pair) {
            return false;
        }
        boolean allCapitalised = true;
        for (NameWord w : run) {
            if (!w.common()) {
                return true;
            }
            allCapitalised &= w.capitalised();
        }
        return allCapitalised;
    }

    private static boolean wordChar(char c) {
        int type = Character.getType(c);
        return Character.isLetter(c) || type == Character.NON_SPACING_MARK || type == Character.COMBINING_SPACING_MARK;
    }

    private static boolean isApostrophe(char c) {
        return c == '\'' || c == '’' || c == '‘' || c == 'ʼ';
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
