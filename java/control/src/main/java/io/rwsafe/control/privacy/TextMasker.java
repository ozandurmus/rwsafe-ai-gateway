package io.rwsafe.control.privacy;

import com.google.re2j.Matcher;
import com.google.re2j.Pattern;
import io.rwsafe.detect.CardDetector;
import io.rwsafe.detect.DetectorSet;
import io.rwsafe.detect.TcknDetector;
import io.rwsafe.platform.verdict.DataClass;
import io.rwsafe.platform.verdict.Finding;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.Predicate;

/**
 * The text layers of MASKING_AND_PRIVACY B2 for one string, rule set {@value #RULE_SET}. One pipeline for every path:
 * each layer claims spans of the original text, a later layer never touches a claimed span, and the result is written
 * once, so a pseudonym is never masked again and the same value reads the same on every screen, in the capture store
 * and in the SIEM export (PR 26 review D-06). Linear scans and RE2/J only; no {@code java.util.regex}.
 *
 * <p>Order: tokens this masker writes and canonical UUIDs are kept as they are; the Tier-1 detectors (layer 6 and the
 * identifiers of layer 4) on the text and its lower- and upper-case forms; e-mail addresses, user-directory paths,
 * {@code DOMAIN\\user} accounts and URL hosts (layers 1 and 2); IPv6 then IPv4 (layer 2); IBAN shapes, Turkish mobile
 * numbers in every written form and every run of six or more digits, glued or grouped across one space, hyphen, dot or
 * underscore as {@link IdentifierCheck} joins them (layer 4 and 5); the estate dictionary, folded (layer 3); Turkish
 * names (layer 4); host-shaped dotted names (layer 5). {@link #maskFreeText} adds what only a sentence has: a lone name,
 * the word after a keyword ({@code host}, {@code user}, {@code müşteri}, {@code hesap}, {@code TCKN}, {@code IBAN},
 * {@code from}, {@code to}) and serial-like tokens (layer 5).
 */
public final class TextMasker {

    /**
     * The rule-set version on every masked page. {@code rwmask-v1} (MASKING_AND_PRIVACY B2, FROZEN) still needs the B3
     * pseudonym registry, MAC OUI-preserving masking, customer numbers (formats from the PO, Q-23) and project code names
     * (an estate list of them); until then this is slice 2.
     */
    public static final String RULE_SET = "rwmask-v1-slice2";

    /**
     * What the masked role reads in place of free text a person wrote (retirement and withdrawal reasons, a correlation
     * id that is not a UUID): withheld, not masked (PO decision on PR 24 review Q-1: permanently).
     */
    public static final String WITHHELD = "[FREE_TEXT_WITHHELD]";
    static final String OVER_LIMIT = "[REDACTED:OVER_LIMIT]";

    private static final Pattern KEEP = Pattern.compile("(?:USR|GRP)-[0-9a-f]{10}"
        + "|(?:IBAN-TR|TCKN|CARD|TEL|EST|HST|NUM|IBAN|CUST|SER)-[0-9a-f]{4}|NAME-[A-Z]{8}"
        + "|2(?:4[0-9]|5[0-5])\\.[0-9]{1,3}\\.[0-9]{1,3}\\.0/24|\\[REDACTED_IP\\]|\\[INVALID_ADDRESS\\]"
        + "|\\[REDACTED:[A-Z_]+\\]"
        + "|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
    private static final Pattern EMAIL = Pattern.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)+");
    /** {@code DOMAIN\\user}: the same claim spelling the user column pseudonymises (PHASE0_PROXYSG_RECORD F-3). */
    private static final Pattern DOMAIN_ACCOUNT =
        Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,63}\\\\[A-Za-z0-9][A-Za-z0-9._$-]{0,63}");
    private static final Pattern IPV4 = Pattern.compile("[0-9]{1,3}(?:\\.[0-9]{1,3}){3}");
    private static final Pattern IPV6 = Pattern.compile("[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}");
    private static final Pattern IPV4_TAIL = Pattern.compile("^\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}");
    /** Country code, check digits, then groups of four letters or digits, compact or spaced, and a short last group. */
    private static final Pattern IBAN_SHAPE =
        Pattern.compile("[A-Za-z]{2}[0-9]{2}(?: ?[A-Za-z0-9]{4}){2,8}(?: ?[A-Za-z0-9]{1,3})?");
    private static final int IBAN_MIN_DIGITS = 12;
    /**
     * A Turkish mobile number with the operator code in parentheses: {@code 0(5XX) XXX XX XX}, {@code +90 (5XX) ...},
     * {@code 90(5XX)...}; the separator after a prefix belongs to the prefix (PR 26 confirmation review N-02).
     */
    private static final Pattern PAREN_PHONE = Pattern.compile(
        "(?:(?:\\+90|0090|90|0)[ ._-]?)?\\(5[0-9]{2}\\)[ ._-]?[0-9]{3}[ ._-]?[0-9]{2}[ ._-]?[0-9]{2}");
    /** The run length {@link IdentifierCheck} refuses on write; the masker masks it on read. */
    private static final int DIGIT_RUN = IdentifierCheck.MAX_DIGIT_RUN_EXCLUSIVE;
    private static final String DIGIT_JOINS = " -._";
    private static final Set<String> TOP_LEVEL = Set.of("com", "net", "org", "edu", "gov", "mil", "int", "info", "biz",
        "io", "ai", "dev", "app", "co", "cloud", "online", "site", "tech", "local", "lan", "corp", "internal", "intra",
        "intranet", "localdomain", "home", "arpa", "localhost", "example", "invalid", "test");
    /** Two-letter endings that are file types, not country domains. */
    private static final Set<String> FILE_ENDINGS = Set.of("js", "ts", "py", "sh", "md", "rb", "go", "rs", "cs", "pl",
        "db", "gz", "xz", "so", "mk", "hs", "ml", "tf", "kt", "cc", "hh");
    private static final Set<String> TITLES_BEFORE = Set.of("sayin", "sn", "dr", "prof", "doc", "av", "uzm", "bay",
        "bayan", "mr", "mrs", "ms", "mx");
    /** Titles after a name; inflected forms count too ({@code Beye}, {@code Hanıma}, {@code Beyin}). */
    private static final Set<String> TITLES_AFTER = Set.of("bey", "hanim", "hoca", "hocam");
    private static final Set<String> USER_WORDS = Set.of("user", "username", "kullanici", "login", "account", "uid");
    private static final Set<String> HOST_WORDS = Set.of("host", "hostname", "server", "sunucu", "makine", "node");
    private static final Set<String> CUSTOMER_WORDS = Set.of("musteri", "customer", "hesap");
    private static final Set<String> TCKN_WORDS = Set.of("tckn", "kimlik");
    private static final Set<String> IBAN_WORDS = Set.of("iban");
    /** Keywords whose next word is masked only when it looks like an identifier. */
    private static final Set<String> WEAK_WORDS = Set.of("from", "to", "kimden", "kime");
    /**
     * Words that follow a keyword in ordinary product and operational sentences ("the host name is", "user content",
     * "server error", "hesap kapandı", "kimlik doğrulama"): never taken as its value (PR 26 confirmation review N-04).
     * Folded forms.
     */
    private static final Set<String> STOP_WORDS = Set.copyOf(List.of("name", "names", "adi", "is", "are", "was",
        "were", "has", "have", "had", "not", "no", "and", "or", "the", "a", "an", "of", "for", "to", "from", "in", "on",
        "at", "with", "by", "this", "that", "these", "list", "lists", "group", "groups", "role", "roles", "id", "ids",
        "key", "keys", "header", "headers", "label", "settings", "count", "ve", "veya", "ile", "icin", "bu", "su", "o",
        "bir", "de", "da", "mi", "listesi", "grubu", "adresi", "bilgisi", "numarasi", "yok", "var", "olarak",
        "tarafindan", "sayisi", "rolu", "adina", "claim", "claims", "address", "addresses", "part", "field", "value",
        "content", "data", "session", "sessions", "error", "errors", "agent", "agents", "access", "request",
        "requests", "response", "responses", "timeout", "failed", "failure", "blocked", "retired", "disabled",
        "enabled", "policy", "policies", "rule", "rules", "platform", "endpoint", "endpoints", "traffic", "token",
        "tokens", "page", "pages", "service", "services", "system", "mode", "scope", "flow", "record", "records",
        "attempt", "attempts", "lock", "locked", "suffix", "suffixes", "certificate", "port", "ports", "check",
        "checks", "status", "experience", "interface", "account", "accounts", "management", "login", "logins",
        "logout", "input", "prompt", "prompts", "notice", "consent", "identity", "number", "numbers", "details",
        "dogrulama", "dogrulamasi", "kontrolu", "girisi", "cikisi", "oturumu", "oturum", "hatasi", "hata", "yaniti",
        "verisi", "verileri", "temsilcisi", "ozeti", "bakimi", "talebi", "kaydi", "kayitlari", "aradi", "girdi",
        "cikti", "kapandi", "kapatildi", "acildi", "hizmeti", "bilgileri", "numarasi", "sifresi", "adi", "hesabi",
        "karti", "yonetimi", "erisimi", "ayarlari", "durumu", "tarafi", "icerigi"));
    private static final int SERIAL_MIN = 8;
    private static final int SERIAL_MAX = 32;
    private static final int MAX_RUN = 6;
    /** The detector set keeps at most {@link DetectorSet#MAX_FINDINGS}; longer texts are scanned in pieces. */
    private static final int DETECTOR_CHUNK = 8192;
    private static final DetectorSet DETECTORS = DetectorSet.standard();

    private final Pseudonymiser pseudonymiser;
    private final List<String> estateTerms;
    private final NameDictionary names;

    TextMasker(Pseudonymiser pseudonymiser, List<String> estateTerms, NameDictionary names) {
        this.pseudonymiser = pseudonymiser;
        Set<String> folded = new LinkedHashSet<>();
        for (String term : estateTerms) {
            String f = foldTerm(term);
            if (!f.isEmpty()) {
                folded.add(f);
            }
        }
        List<String> sorted = new ArrayList<>(folded);
        sorted.sort(Comparator.comparingInt(String::length).reversed());
        this.estateTerms = List.copyOf(sorted);
        this.names = names;
    }

    /**
     * A directory group name: always replaced by its keyed pseudonym, never passed through the free-text layers (a
     * group name is an estate identifier whatever it contains).
     */
    public String group(String name) {
        return pseudonymiser.group(name);
    }

    /** A value a masked page shows that is not a sentence (an id, a label, a vocabulary token): names only in pairs. */
    public String mask(String text) {
        return run(text, false, host -> false);
    }

    /**
     * A vendor endpoint of a policy registry platform row (public, not estate data): every layer applies except that a
     * bare host name stays as written.
     */
    public String maskVendorHost(String host) {
        return run(host, false, h -> true);
    }

    /** A sentence (a reason, a detail, a message, captured text): every layer, including the free-text ones. */
    public String maskFreeText(String text) {
        return run(text, true, host -> false);
    }

    /**
     * {@link #maskFreeText(String)} that leaves the host names {@code publicHost} accepts (given in lower case) as
     * written: the vendor endpoints of the policy registry's platform rows, which are public and not estate data.
     */
    public String maskFreeText(String text, Predicate<String> publicHost) {
        return run(text, true, publicHost);
    }

    private String run(String text, boolean freeText, Predicate<String> publicHost) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        Claims c = new Claims(text);
        keep(c);
        if (!detectors(c)) {
            return OVER_LIMIT;
        }
        // URL authorities first, so a URL's user and password are masked as userinfo, never half as an e-mail (N-03).
        urlHosts(c, publicHost);
        emails(c);
        userPaths(c);
        domainAccounts(c);
        ipv6(c);
        ipv4(c);
        ibans(c);
        parenPhones(c);
        digitRuns(c);
        estate(c);
        names(c, freeText);
        hosts(c, publicHost);
        if (freeText) {
            keywords(c);
            serials(c);
        }
        return c.render();
    }

    // ---- claims -------------------------------------------------------------------------------------------------------

    /** Spans of the original text taken by a layer, with their replacements; written once at the end. */
    private static final class Claims {

        final String s;
        final int n;
        final boolean[] taken;
        final List<int[]> spans = new ArrayList<>();
        final List<String> replacements = new ArrayList<>();

        Claims(String s) {
            this.s = s;
            this.n = s.length();
            this.taken = new boolean[n];
        }

        boolean free(int from, int to) {
            for (int i = from; i < to; i++) {
                if (taken[i]) {
                    return false;
                }
            }
            return true;
        }

        boolean claim(int from, int to, String replacement) {
            if (from < 0 || to > n || from >= to || !free(from, to)) {
                return false;
            }
            Arrays.fill(taken, from, to, true);
            spans.add(new int[] {from, to, replacements.size()});
            replacements.add(replacement);
            return true;
        }

        String render() {
            if (spans.isEmpty()) {
                return s;
            }
            spans.sort(Comparator.comparingInt(a -> a[0]));
            StringBuilder out = new StringBuilder(n);
            int cursor = 0;
            for (int[] span : spans) {
                out.append(s, cursor, span[0]).append(replacements.get(span[2]));
                cursor = span[1];
            }
            return out.append(s, cursor, n).toString();
        }
    }

    private static boolean alnumAt(String s, int i) {
        return i >= 0 && i < s.length() && Character.isLetterOrDigit(s.charAt(i));
    }

    private static boolean digitAt(String s, int i) {
        return i >= 0 && i < s.length() && s.charAt(i) >= '0' && s.charAt(i) <= '9';
    }

    /**
     * {@code masked} with every token this masker writes (and every canonical UUID) blanked, so a check for identifier
     * shapes on masked text does not count the digits inside a subnet label or a pseudonym (N-02).
     */
    public static String withoutTokens(String masked) {
        if (masked == null || masked.isEmpty()) {
            return masked;
        }
        Claims c = new Claims(masked);
        keep(c);
        for (int k = 0; k < c.replacements.size(); k++) {
            c.replacements.set(k, " ");
        }
        return c.render();
    }

    /** Tokens this masker wrote, the subnet labels and markers it writes, and canonical UUIDs (kept for navigation). */
    private static void keep(Claims c) {
        Matcher m = KEEP.matcher(c.s);
        while (m.find()) {
            if (!alnumAt(c.s, m.start() - 1) && !alnumAt(c.s, m.end())) {
                c.claim(m.start(), m.end(), m.group());
            }
        }
    }

    // ---- layers 6 and 4: the Tier-1 detectors -------------------------------------------------------------------------

    /**
     * Detector findings on the text and on its per-character lower- and upper-case forms (the forms
     * {@link IdentifierCheck} scans; the offsets are the same). False when a piece reaches the finding limit: the whole
     * string is then withheld (PR 26 review D-08).
     */
    private boolean detectors(Claims c) {
        List<Finding> findings = new ArrayList<>();
        for (String form : List.of(c.s, perChar(c.s, true), perChar(c.s, false))) {
            List<Finding> f = scan(form);
            if (f == null) {
                return false;
            }
            findings.addAll(f);
        }
        findings.sort(Comparator.comparingInt(Finding::start));
        int i = 0;
        while (i < findings.size()) {
            Finding f = findings.get(i);
            int end = f.end();
            int j = i + 1;
            while (j < findings.size() && findings.get(j).start() < end) {
                end = Math.max(end, findings.get(j).end());
                j++;
            }
            c.claim(f.start(), end, replacement(f.dataClass(), c.s.substring(f.start(), end)));
            i = j;
        }
        return true;
    }

    /** The folded form (Turkish letters and every i form as ASCII) in lower or upper case; one character per character. */
    private static String perChar(String s, boolean lower) {
        char[] out = s.toCharArray();
        for (int i = 0; i < out.length; i++) {
            char folded = foldChar(out[i]);
            out[i] = lower ? folded : Character.toUpperCase(folded);
        }
        return new String(out);
    }

    /** All findings of one form, scanned in pieces when it holds more than the limit; null when a piece is over it. */
    private static List<Finding> scan(String text) {
        List<Finding> whole = DETECTORS.scan(text);
        if (!DetectorSet.overLimit(whole)) {
            return whole;
        }
        List<Finding> out = new ArrayList<>();
        int from = 0;
        while (from < text.length()) {
            int to = chunkEnd(text, from);
            List<Finding> piece = DETECTORS.scan(text.substring(from, to));
            if (DetectorSet.overLimit(piece)) {
                return null;
            }
            for (Finding f : piece) {
                out.add(new Finding(f.dataClass(), f.start() + from, f.end() + from));
            }
            from = to;
        }
        return out;
    }

    /**
     * A piece ends after a line break, or after sentence punctuation and a space, near {@link #DETECTOR_CHUNK}; never
     * inside a spaced IBAN, card or phone number. A text without such a place is one piece.
     */
    private static int chunkEnd(String text, int from) {
        int n = text.length();
        if (n - from <= DETECTOR_CHUNK) {
            return n;
        }
        for (int i = from + DETECTOR_CHUNK; i < n; i++) {
            char ch = text.charAt(i);
            if (ch == '\n' || (Character.isWhitespace(ch) && ".;!?".indexOf(text.charAt(i - 1)) >= 0
                && !digitAt(text, i + 1))) {
                return i + 1;
            }
        }
        return n;
    }

    private String replacement(DataClass dataClass, String value) {
        return switch (dataClass) {
            case SECRET -> dataClass.redactionToken();
            case TCKN -> pseudonymiser.token("TCKN", value);
            case TR_IBAN -> pseudonymiser.token("IBAN-TR", value.replace(" ", "").toUpperCase(Locale.ROOT));
            case PAYMENT_CARD -> pseudonymiser.token("CARD", value.replace(" ", "").replace("-", ""));
        };
    }

    // ---- layers 1 and 2: accounts, paths, hosts in URLs, addresses -------------------------------------------------

    private void emails(Claims c) {
        Matcher m = EMAIL.matcher(c.s);
        while (m.find()) {
            c.claim(m.start(), m.end(), pseudonymiser.user(m.group()));
        }
    }

    /** {@code /Users/<name>}, {@code /home/<name>}, {@code C:\Users\<name>} (also with doubled backslashes). */
    private void userPaths(Claims c) {
        String s = c.s;
        for (int i = 0; i < s.length(); i++) {
            int segment = -1;
            if (s.regionMatches(true, i, "/users/", 0, 7)) {
                segment = i + 7;
            } else if (s.regionMatches(true, i, "/home/", 0, 6)) {
                segment = i + 6;
            } else if (s.regionMatches(true, i, "\\\\users\\\\", 0, 9)) {
                segment = i + 9;
            } else if (s.regionMatches(true, i, "\\users\\", 0, 7)) {
                segment = i + 7;
            }
            if (segment < 0) {
                continue;
            }
            int end = segment;
            while (end < s.length() && (Character.isLetterOrDigit(s.charAt(end)) || "._$-".indexOf(s.charAt(end)) >= 0)) {
                end++;
            }
            if (end > segment) {
                c.claim(segment, end, pseudonymiser.user(s.substring(segment, end)));
                i = end - 1;
            }
        }
    }

    private void domainAccounts(Claims c) {
        Matcher m = DOMAIN_ACCOUNT.matcher(c.s);
        while (m.find()) {
            if (!alnumAt(c.s, m.start() - 1) && (m.start() == 0 || c.s.charAt(m.start() - 1) != '\\')) {
                c.claim(m.start(), m.end(), pseudonymiser.user(m.group()));
            }
        }
    }

    /** The host of every {@code scheme://} authority, whatever its label count (PR 26 review D-06). */
    private void urlHosts(Claims c, Predicate<String> publicHost) {
        String s = c.s;
        int at = s.indexOf("://");
        while (at >= 0) {
            int start = at + 3;
            int end = start;
            while (end < s.length() && "/?#\"'<> \t\r\n".indexOf(s.charAt(end)) < 0) {
                end++;
            }
            int host = start;
            for (int k = start; k < end; k++) {
                if (s.charAt(k) == '@') {
                    host = k + 1;
                }
            }
            if (host > start + 1) {
                // Userinfo (PR 26 confirmation review N-03): the user as its USR- pseudonym, a password redacted.
                int colon = s.indexOf(':', start);
                int userEnd = colon >= 0 && colon < host - 1 ? colon : host - 1;
                String user = s.substring(start, userEnd);
                String userinfo = (user.isBlank() ? "" : pseudonymiser.user(user))
                    + (userEnd < host - 1 ? ":" + DataClass.SECRET.redactionToken() : "");
                c.claim(start, host - 1, userinfo);
            }
            int hostEnd = host;
            while (hostEnd < end && s.charAt(hostEnd) != ':') {
                hostEnd++;
            }
            String name = s.substring(host, hostEnd).toLowerCase(Locale.ROOT);
            if (!name.isEmpty() && name.charAt(0) != '[' && Pseudonymiser.ipv4(name) == null && !publicHost.test(name)) {
                c.claim(host, hostEnd, pseudonymiser.token("HST", name));
            }
            at = s.indexOf("://", Math.max(end, at + 3));
        }
    }

    /** IPv6 before IPv4, so an IPv4-mapped address ({@code ::ffff:} and a dotted quad) is one redaction. */
    private static void ipv6(Claims c) {
        String s = c.s;
        Matcher m = IPV6.matcher(s);
        while (m.find()) {
            int start = m.start();
            int end = m.end();
            String candidate = m.group();
            if (!looksLikeIpv6(candidate) || alnumAt(s, start - 1)) {
                continue;
            }
            Matcher tail = IPV4_TAIL.matcher(s.substring(end, Math.min(s.length(), end + 12)));
            if (end < s.length() && s.charAt(end) == '.' && digitAt(s, end - 1) && tail.find()) {
                end += tail.end();
            }
            if (!alnumAt(s, end)) {
                c.claim(start, end, Pseudonymiser.REDACTED_IP);
            }
        }
    }

    /** At least two colons and either {@code ::} with a hex digit, or a hex letter: a time of day is neither. */
    private static boolean looksLikeIpv6(String candidate) {
        boolean hexDigit = false;
        boolean hexLetter = false;
        for (int i = 0; i < candidate.length(); i++) {
            char ch = Character.toLowerCase(candidate.charAt(i));
            hexLetter |= ch >= 'a' && ch <= 'f';
            hexDigit |= (ch >= 'a' && ch <= 'f') || (ch >= '0' && ch <= '9');
        }
        return hexLetter || (candidate.contains("::") && hexDigit);
    }

    /** Dotted quads, glued to letters too ({@code host10.0.0.1}); never inside a longer dotted number. */
    private void ipv4(Claims c) {
        String s = c.s;
        Matcher m = IPV4.matcher(s);
        while (m.find()) {
            int start = m.start();
            int end = m.end();
            boolean before = digitAt(s, start - 1) || (start > 0 && s.charAt(start - 1) == '.' && digitAt(s, start - 2));
            boolean after = digitAt(s, end) || (end < s.length() && s.charAt(end) == '.' && digitAt(s, end + 1));
            if (!before && !after && Pseudonymiser.ipv4(m.group()) != null) {
                c.claim(start, end, pseudonymiser.subnet(m.group()));
            }
        }
    }

    // ---- layers 4 and 5: IBANs, phone numbers, digit runs --------------------------------------------------------------

    /**
     * IBAN shapes the TR detector did not take (another country, letters in the account part, a bad check digit, glued to
     * text): the longest prefix that passes ISO 13616 mod-97 ({@code IBAN-TR-} for TR, else {@code IBAN-}), otherwise a
     * country, check digits, one group and digit groups with at least twelve digits ({@code IBAN-}).
     */
    private void ibans(Claims c) {
        String s = c.s;
        Matcher m = IBAN_SHAPE.matcher(s);
        while (m.find()) {
            if (digitAt(s, m.start() - 1)) {
                continue;
            }
            // Glued to a word before it, only an upper-case country code with a valid check is an IBAN (odemeTR...);
            // otherwise the letters belong to the word (kart4...) and the digits to the digit-run layer.
            boolean glued = m.start() > 0 && Character.isLetter(s.charAt(m.start() - 1));
            if (glued && !(Character.isUpperCase(s.charAt(m.start())) && Character.isUpperCase(s.charAt(m.start() + 1)))) {
                continue;
            }
            StringBuilder compact = new StringBuilder();
            List<Integer> ends = new ArrayList<>();
            for (int k = m.start(); k < m.end(); k++) {
                char ch = s.charAt(k);
                if (ch != ' ') {
                    compact.append(Character.toUpperCase(ch));
                    ends.add(k + 1);
                }
            }
            boolean claimed = false;
            for (int length = Math.min(compact.length(), 34); length >= 15 && !claimed; length--) {
                String value = compact.substring(0, length);
                int end = ends.get(length - 1);
                if (!digitAt(s, end) && mod97(value)) {
                    claimed = c.claim(m.start(), end, pseudonymiser.token(value.startsWith("TR") ? "IBAN-TR" : "IBAN",
                        value));
                }
            }
            if (claimed || glued) {
                continue;
            }
            // No valid check: country, check digits, one group, then digits only (spaces allowed), twelve digits or more.
            int digits = 0;
            int end = -1;
            for (int k = 0; k < compact.length(); k++) {
                char ch = compact.charAt(k);
                if (k >= 8 && !Character.isDigit(ch)) {
                    break;
                }
                digits += Character.isDigit(ch) ? 1 : 0;
                if (digits >= IBAN_MIN_DIGITS && !digitAt(s, ends.get(k))) {
                    end = k;
                }
            }
            if (end > 0) {
                String value = compact.substring(0, end + 1);
                c.claim(m.start(), ends.get(end), pseudonymiser.token("IBAN", value));
            }
        }
    }

    /** ISO 13616: the first four characters moved to the end, letters as 10..35, remainder 1 under 97. */
    static boolean mod97(String compact) {
        if (compact.length() < 5) {
            return false;
        }
        String rearranged = compact.substring(4) + compact.substring(0, 4);
        int rem = 0;
        for (int i = 0; i < rearranged.length(); i++) {
            char ch = rearranged.charAt(i);
            int v;
            if (ch >= '0' && ch <= '9') {
                v = ch - '0';
            } else if (ch >= 'A' && ch <= 'Z') {
                v = ch - 'A' + 10;
            } else {
                return false;
            }
            rem = (v > 9 ? rem * 100 + v : rem * 10 + v) % 97;
        }
        return rem == 1;
    }

    private void parenPhones(Claims c) {
        Matcher m = PAREN_PHONE.matcher(c.s);
        while (m.find()) {
            if (!digitAt(c.s, m.start() - 1) && !digitAt(c.s, m.end())) {
                c.claim(m.start(), m.end(), pseudonymiser.token("TEL", subscriber(m.group())));
            }
        }
    }

    /**
     * Every run of digits, joined across one space, hyphen, dot or underscore with a digit on both sides (the joins of
     * {@link IdentifierCheck#longestDigitRun}), glued to letters or not: a valid TCKN reads as {@code TCKN-}, a Turkish
     * mobile number in any prefix form as {@code TEL-}, a Luhn-valid card as {@code CARD-}, any other run of six or more
     * digits as {@code NUM-} (PR 26 review D-04, Q-2). A calendar date ({@code 2026-10-31}, {@code 31.10.2026}) is not a
     * number.
     */
    private void digitRuns(Claims c) {
        String s = c.s;
        int n = s.length();
        int i = 0;
        while (i < n) {
            if (!digitAt(s, i) || c.taken[i]) {
                i++;
                continue;
            }
            int date = dateLength(s, i);
            if (date > 0) {
                i += date;
                continue;
            }
            int start = i;
            StringBuilder digits = new StringBuilder();
            int j = i;
            while (true) {
                while (j < n && digitAt(s, j) && !c.taken[j]) {
                    digits.append(s.charAt(j));
                    j++;
                }
                if (j + 1 < n && DIGIT_JOINS.indexOf(s.charAt(j)) >= 0 && digitAt(s, j + 1) && !c.taken[j]
                    && !c.taken[j + 1]) {
                    j++;
                    continue;
                }
                break;
            }
            if (digits.length() >= DIGIT_RUN) {
                // An international prefix's plus sign belongs to the number: +90 532 ... and 0532 ... read the same.
                int from = start > 0 && s.charAt(start - 1) == '+' && !c.taken[start - 1] ? start - 1 : start;
                c.claim(from, j, digitToken(digits.toString()));
            }
            i = Math.max(j, i + 1);
        }
    }

    private String digitToken(String digits) {
        int len = digits.length();
        List<Finding> found = new ArrayList<>(1);
        if (len == 11) {
            new TcknDetector().scan(digits, found);
            if (!found.isEmpty()) {
                return pseudonymiser.token("TCKN", digits);
            }
        }
        if ((len == 10 && digits.startsWith("5")) || (len == 11 && digits.startsWith("05"))
            || (len == 12 && digits.startsWith("905")) || (len == 14 && digits.startsWith("00905"))) {
            return pseudonymiser.token("TEL", subscriber(digits));
        }
        if (len >= 13 && len <= 19) {
            new CardDetector().scan(digits, found);
            if (!found.isEmpty() && found.get(0).start() == 0 && found.get(0).end() == len) {
                return pseudonymiser.token("CARD", digits);
            }
        }
        return pseudonymiser.token("NUM", digits);
    }

    /**
     * The length of an exact date written {@code yyyy-mm-dd}, {@code yyyy.mm.dd}, {@code dd.mm.yyyy} or
     * {@code dd-mm-yyyy}: neither side touches a digit or a digit join with a digit beyond it, so a longer grouped number
     * that starts like a date is a number (PR 26 confirmation review N-02).
     */
    static int dateLength(String s, int i) {
        if (i + 10 > s.length() || digitAt(s, i + 10) || digitAt(s, i - 1)
            || (i + 10 < s.length() && DIGIT_JOINS.indexOf(s.charAt(i + 10)) >= 0 && digitAt(s, i + 11))
            || (i >= 2 && DIGIT_JOINS.indexOf(s.charAt(i - 1)) >= 0 && digitAt(s, i - 2))) {
            return 0;
        }
        char a = s.charAt(i + 4);
        char b = s.charAt(i + 7);
        if ((a == '-' || a == '.') && a == b && allDigits(s, i, 4) && allDigits(s, i + 5, 2) && allDigits(s, i + 8, 2)
            && validDate(number(s, i, 4), number(s, i + 5, 2), number(s, i + 8, 2))) {
            return 10;
        }
        a = s.charAt(i + 2);
        b = s.charAt(i + 5);
        if ((a == '-' || a == '.') && a == b && allDigits(s, i, 2) && allDigits(s, i + 3, 2) && allDigits(s, i + 6, 4)
            && validDate(number(s, i + 6, 4), number(s, i + 3, 2), number(s, i, 2))) {
            return 10;
        }
        return 0;
    }

    private static boolean allDigits(String s, int from, int count) {
        for (int k = from; k < from + count; k++) {
            if (!digitAt(s, k)) {
                return false;
            }
        }
        return true;
    }

    private static int number(String s, int from, int count) {
        return Integer.parseInt(s.substring(from, from + count));
    }

    private static boolean validDate(int year, int month, int day) {
        return year >= 1900 && year <= 2199 && month >= 1 && month <= 12 && day >= 1 && day <= 31;
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

    // ---- layer 3: the estate dictionary --------------------------------------------------------------------------------

    /**
     * Estate terms in the text, compared folded on both sides (NFC, case, the Turkish letters and every i form; PR 26
     * review D-06) with every run of separators ({@code - _ . :} and spaces) as one {@code -} (PR 26 confirmation review
     * N-03), so {@code şube-merkez}, {@code SUBE_MERKEZ}, {@code sube.merkez} and {@code Şube Merkez} are one term and
     * one {@code EST-} token. A term matches whole, between separators or other punctuation, never inside a word; a
     * claimed span is never matched again.
     */
    private void estate(Claims c) {
        if (estateTerms.isEmpty()) {
            return;
        }
        String s = c.s;
        StringBuilder folded = new StringBuilder(s.length());
        int[] origin = new int[s.length()];
        for (int k = 0; k < s.length(); k++) {
            char ch = s.charAt(k);
            if (isMark(ch)) {
                continue;
            }
            char f;
            if (isSeparator(ch) || Character.isWhitespace(ch)) {
                if (folded.length() > 0 && folded.charAt(folded.length() - 1) == '-') {
                    continue;
                }
                f = '-';
            } else if (Character.isLetterOrDigit(ch)) {
                f = foldChar(ch);
            } else {
                f = '\0';
            }
            origin[folded.length()] = k;
            folded.append(f);
        }
        String text = folded.toString();
        for (String term : estateTerms) {
            int at = text.indexOf(term);
            while (at >= 0) {
                int end = at + term.length();
                boolean edges = (at == 0 || !Character.isLetterOrDigit(text.charAt(at - 1)))
                    && (end == text.length() || !Character.isLetterOrDigit(text.charAt(end)));
                if (edges) {
                    int start = origin[at];
                    int stop = origin[end - 1] + 1;
                    while (stop < s.length() && isMark(s.charAt(stop))) {
                        stop++;
                    }
                    c.claim(start, stop, pseudonymiser.token("EST", term));
                }
                at = text.indexOf(term, at + 1);
            }
        }
    }

    /** An estate term folded as the text is: {@link #fold}, every run of separators and spaces as one {@code -}. */
    static String foldTerm(String term) {
        String f = fold(term.strip());
        StringBuilder out = new StringBuilder(f.length());
        for (int k = 0; k < f.length(); k++) {
            char ch = f.charAt(k);
            if (isSeparator(ch) || Character.isWhitespace(ch)) {
                if (out.length() > 0 && out.charAt(out.length() - 1) != '-') {
                    out.append('-');
                }
            } else {
                out.append(Character.isLetterOrDigit(ch) ? ch : '\0');
            }
        }
        int end = out.length();
        while (end > 0 && out.charAt(end - 1) == '-') {
            end--;
        }
        return out.substring(0, end);
    }

    private static boolean isSeparator(char ch) {
        return ch == '.' || ch == '_' || ch == ':' || ch == '-';
    }

    private static boolean isMark(char ch) {
        int type = Character.getType(ch);
        return type == Character.NON_SPACING_MARK || type == Character.COMBINING_SPACING_MARK;
    }

    /** One character folded: lower case, every i form as {@code i}, the Turkish letters as ASCII. */
    static char foldChar(char ch) {
        return switch (ch) {
            case 'I', '\u0130', '\u0131' -> 'i';
            default -> {
                char lower = Character.toLowerCase(ch);
                yield switch (lower) {
                    case '\u00e7' -> 'c';
                    case '\u011f' -> 'g';
                    case '\u00f6' -> 'o';
                    case '\u015f' -> 's';
                    case '\u00fc' -> 'u';
                    case '\u00e2' -> 'a';
                    case '\u00ee' -> 'i';
                    case '\u00fb' -> 'u';
                    default -> lower;
                };
            }
        };
    }

    /** NFC, then {@link #foldChar} per character, combining marks dropped. */
    static String fold(String s) {
        String nfc = Normalizer.normalize(s, Normalizer.Form.NFC);
        StringBuilder out = new StringBuilder(nfc.length());
        for (int i = 0; i < nfc.length(); i++) {
            char ch = nfc.charAt(i);
            if (!isMark(ch)) {
                out.append(foldChar(ch));
            }
        }
        return out.toString();
    }

    // ---- layer 4: Turkish names --------------------------------------------------------------------------------------

    private enum Kind { NAME, INITIAL, TITLE_BEFORE, TITLE_AFTER, CAPITALISED, OTHER }

    /** How a word is written: all lower case, capitalised ({@code Ayşe}) or all capitals ({@code AYŞE}). */
    private enum Case { LOWER, TITLE, UPPER }

    /** One word of the text with what the name layer needs to know about it. */
    private record Word(Kind kind, int start, int end, String key, int flags, boolean suffixed, boolean shortStem,
                        Case writing) {

        boolean given() {
            return (flags & NameDictionary.GIVEN) != 0;
        }

        boolean surname() {
            return (flags & NameDictionary.SURNAME) != 0;
        }

        boolean common() {
            return (flags & NameDictionary.COMMON) != 0;
        }

        boolean capitalised() {
            return writing != Case.LOWER;
        }
    }

    /**
     * Name runs: dictionary words, initials ({@code A.}, {@code a.}) and a capitalised word hyphenated to a family name,
     * joined by one {@code ._-} or by spaces. Joined by {@code ._-} words always join ({@code deniz.kaya}). Across spaces
     * two names that are not everyday words join; an everyday word joins when written like its neighbour (both
     * capitalised; both lower case when the run holds a name that is not an everyday word or a title stands before or
     * after it: {@code ayşe pınar yılmaz}, {@code deniz kaya Bey}), or, written differently, when the two make a given
     * name and a family name with one of them not an everyday word ({@code ayşe Yılmaz}, {@code Mehmet yazıcı}: privacy
     * before readability, PR 26 confirmation review N-01). A run with a given name and a family name, or with an initial
     * and a name, is one {@code NAME-<WORD>} in every field; in free text any other run of two or more is one too, and a
     * lone word is a name when it is capitalised (title case or capitals, with or without an ending), stands by a title
     * ({@code Sayın}, {@code Dr.}, {@code Bey}, {@code Hanıma}), or is not an everyday word (a lower-case short stem
     * with an ending excepted). The key is the run's names in sorted order, so {@code Ayşe Yılmaz} and
     * {@code YILMAZ Ayşe} are one token.
     */
    private void names(Claims c, boolean freeText) {
        List<Word> words = words(c);
        // Whether a title follows the chain of name words that starts at each index (deniz kaya Bey).
        boolean[] titledAhead = new boolean[words.size()];
        for (int k = words.size() - 2; k >= 0; k--) {
            Word after = words.get(k + 1);
            if (joinable(c, words.get(k), after)) {
                titledAhead[k] = after.kind() == Kind.TITLE_AFTER
                    || ((after.kind() == Kind.NAME || after.kind() == Kind.INITIAL) && titledAhead[k + 1]);
            }
        }
        List<Word> run = new ArrayList<>(MAX_RUN);
        boolean titled = false;
        for (int k = 0; k < words.size(); k++) {
            Word w = words.get(k);
            Word previous = k > 0 ? words.get(k - 1) : null;
            Word next = k + 1 < words.size() ? words.get(k + 1) : null;
            boolean joinable = previous != null && joinable(c, previous, w);
            Word last = run.isEmpty() ? null : run.get(run.size() - 1);
            boolean plainName = run.stream().anyMatch(r -> r.kind() == Kind.NAME && !r.common());
            switch (w.kind()) {
                case NAME, INITIAL -> {
                    if (last != null && joinable && joins(c, last, w, titled || titledAhead[k], plainName)
                        && run.size() < MAX_RUN) {
                        run.add(w);
                    } else {
                        flush(c, run, titled, freeText);
                        titled = previous != null && joinable && previous.kind() == Kind.TITLE_BEFORE;
                        run.add(w);
                    }
                }
                case CAPITALISED -> {
                    // A capitalised word outside the dictionary joins a run only hyphenated to a name (a double
                    // family name: Yılmaz-Kocaoğlu, Kocaoğlu-Yılmaz).
                    boolean after = last != null && last.kind() == Kind.NAME && joinable && hyphen(c, last, w);
                    boolean before = next != null && next.kind() == Kind.NAME && joinable(c, w, next)
                        && hyphen(c, w, next);
                    if (after && run.size() < MAX_RUN) {
                        run.add(w);
                    } else if (before) {
                        if (!(last != null && joinable && joins(c, last, w, titled, plainName)
                            && run.size() < MAX_RUN)) {
                            flush(c, run, titled, freeText);
                            titled = previous != null && joinable && previous.kind() == Kind.TITLE_BEFORE;
                        }
                        run.add(w);
                    } else {
                        flush(c, run, titled, freeText);
                        titled = false;
                    }
                }
                case TITLE_AFTER -> {
                    if (!run.isEmpty() && joinable) {
                        titled = true;
                    }
                    flush(c, run, titled, freeText);
                    titled = false;
                }
                default -> {
                    flush(c, run, titled, freeText);
                    titled = false;
                }
            }
        }
        flush(c, run, titled, freeText);
    }

    /** The words of the text, whole words only; a word over a claimed span is {@link Kind#OTHER}. */
    private List<Word> words(Claims c) {
        String s = c.s;
        int n = s.length();
        List<Word> out = new ArrayList<>();
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
            out.add(word(c, start, stemEnd, i, apostrophe));
            i = Math.max(i, out.get(out.size() - 1).end());
        }
        return out;
    }

    private Word word(Claims c, int start, int stemEnd, int end, boolean apostrophe) {
        String s = c.s;
        String surface = s.substring(start, stemEnd);
        Case writing = writing(surface);
        boolean whole = !alnumAt(s, start - 1) && !digitAt(s, end) && !(end < s.length() && Character.isLetter(
            s.charAt(end)));
        if (!whole || !c.free(start, end)) {
            return new Word(Kind.OTHER, start, end, null, 0, false, false, writing);
        }
        String folded = fold(surface);
        boolean dot = stemEnd < s.length() && s.charAt(stemEnd) == '.' && !apostrophe;
        if (TITLES_BEFORE.contains(folded)) {
            return new Word(Kind.TITLE_BEFORE, start, dot ? stemEnd + 1 : end, null, 0, false, false, writing);
        }
        if (NameDictionary.inflectionOf(folded, TITLES_AFTER)) {
            return new Word(Kind.TITLE_AFTER, start, end, null, 0, false, false, writing);
        }
        if (surface.length() == 1 && writing != Case.LOWER && dot && c.free(stemEnd, stemEnd + 1)) {
            return new Word(Kind.INITIAL, start, stemEnd + 1, folded, 0, false, true, writing);
        }
        // A single letter glued by . _ - to the next word, any case: a.yilmaz, m_kaya (N-01).
        if (surface.length() == 1 && !apostrophe && stemEnd + 1 < s.length() && "._-".indexOf(s.charAt(stemEnd)) >= 0
            && Character.isLetter(s.charAt(stemEnd + 1)) && c.free(stemEnd, stemEnd + 1)) {
            return new Word(Kind.INITIAL, start, stemEnd + 1, folded, 0, false, true, writing);
        }
        NameDictionary.Match match = names.match(folded, apostrophe);
        if (match != null) {
            return new Word(Kind.NAME, start, end, match.key(), match.flags(), match.suffixed(), match.shortStem(),
                writing);
        }
        if (writing == Case.TITLE || writing == Case.UPPER) {
            return new Word(Kind.CAPITALISED, start, end, folded, 0, false, false, writing);
        }
        return new Word(Kind.OTHER, start, end, null, 0, false, false, writing);
    }

    private static Case writing(String surface) {
        boolean firstUpper = Character.isUpperCase(surface.charAt(0)) || Character.isTitleCase(surface.charAt(0));
        if (!firstUpper) {
            return Case.LOWER;
        }
        for (int k = 1; k < surface.length(); k++) {
            if (Character.isLowerCase(surface.charAt(k))) {
                return Case.TITLE;
            }
        }
        return surface.length() == 1 ? Case.TITLE : Case.UPPER;
    }

    /** Two words are neighbours across one {@code ._-}, or across one to three spaces on one line, nothing claimed. */
    private static boolean joinable(Claims c, Word a, Word b) {
        int gap = b.start() - a.end();
        if (gap < 0 || gap > 3 || !c.free(a.end(), b.start())) {
            return false;
        }
        if (gap == 0) {
            return a.kind() == Kind.INITIAL || a.kind() == Kind.TITLE_BEFORE;
        }
        if (gap == 1 && "._-".indexOf(c.s.charAt(a.end())) >= 0) {
            return true;
        }
        for (int k = a.end(); k < b.start(); k++) {
            char ch = c.s.charAt(k);
            if (ch != ' ' && ch != '\t' && ch != '\u00a0') {
                return false;
            }
        }
        return true;
    }

    private static boolean punctuationJoin(Claims c, Word a, Word b) {
        return b.start() - a.end() == 1 && "._-".indexOf(c.s.charAt(a.end())) >= 0;
    }

    private static boolean hyphen(Claims c, Word a, Word b) {
        return b.start() - a.end() == 1 && c.s.charAt(a.end()) == '-';
    }

    /**
     * Whether {@code next} continues a run ending with {@code last} (both already neighbours); {@code titled} when a
     * title stands before or after the run, {@code plainName} when the run holds a name that is not an everyday word.
     */
    private static boolean joins(Claims c, Word last, Word next, boolean titled, boolean plainName) {
        if (last.kind() == Kind.INITIAL) {
            // After an initial: a name word glued to it, capitalised, or not an everyday word (A. metin stays a word).
            return next.start() == last.end() || next.kind() == Kind.INITIAL || next.capitalised() || !next.common()
                || punctuationJoin(c, last, next);
        }
        if (next.kind() == Kind.INITIAL || punctuationJoin(c, last, next)) {
            return true;
        }
        if (!last.common() && !next.common()) {
            return true;
        }
        if (last.capitalised() == next.capitalised()) {
            return last.capitalised() || titled || plainName || !last.common() || !next.common();
        }
        boolean pair = (last.given() && next.surname()) || (last.surname() && next.given());
        return titled || (pair && (!last.common() || !next.common()));
    }

    private void flush(Claims c, List<Word> run, boolean titled, boolean freeText) {
        if (run.isEmpty()) {
            return;
        }
        List<Word> members = new ArrayList<>(run);
        run.clear();
        boolean person = person(members);
        if (members.size() >= 2 && (person || freeText)) {
            if (claimRun(c, members)) {
                return;
            }
        }
        if (!freeText) {
            return;
        }
        for (Word w : members) {
            if (w.kind() == Kind.NAME && lone(w, titled)) {
                c.claim(w.start(), w.end(), nameToken(w.key()));
            }
        }
    }

    /** A given name and a family name in different words, or an initial and a name. */
    private static boolean person(List<Word> members) {
        boolean initial = false;
        boolean name = false;
        for (Word a : members) {
            initial |= a.kind() == Kind.INITIAL;
            name |= a.kind() == Kind.NAME;
            for (Word b : members) {
                if (a != b && a.kind() == Kind.NAME && b.kind() == Kind.NAME && a.given() && b.surname()) {
                    return true;
                }
            }
        }
        return initial && name;
    }

    private boolean claimRun(Claims c, List<Word> members) {
        if (members.stream().noneMatch(w -> w.kind() == Kind.NAME)) {
            return false;
        }
        List<String> keys = new ArrayList<>();
        for (Word w : members) {
            keys.add(w.key());
        }
        keys.sort(null);
        return c.claim(members.get(0).start(), members.get(members.size() - 1).end(), nameToken(String.join(" ", keys)));
    }

    /**
     * A word on its own (free text): capitalised (title case or capitals, with or without an ending) or by a title it is
     * a name; in lower case an everyday word stays a word, and so does a short stem with an ending (N-01).
     */
    private static boolean lone(Word w, boolean titled) {
        if (titled || w.capitalised()) {
            return true;
        }
        return !w.common() && !(w.shortStem() && w.suffixed());
    }

    /** {@code NAME-<WORD>}; a word that itself reads as a dictionary name is drawn again. */
    private String nameToken(String key) {
        return pseudonymiser.word("NAME", key, word -> names.match(NameDictionary.fold(word), false) != null);
    }

    /** Letters and combining marks; the modifier-letter apostrophe (U+02BC) is a letter to Java but an apostrophe here. */
    private static boolean wordChar(char ch) {
        return (Character.isLetter(ch) && !isApostrophe(ch)) || isMark(ch);
    }

    private static boolean isApostrophe(char ch) {
        return ch == '\'' || ch == '\u2019' || ch == '\u2018' || ch == '\u02bc' || ch == '`' || ch == '\u00b4';
    }

    // ---- layer 5: hosts, keywords, serials -----------------------------------------------------------------------------

    /**
     * Host-shaped dotted names not claimed already: the last label letters only and a known top-level or two-letter
     * country name, or three labels one of which has a digit, hyphen or underscore, or four labels or more. Product
     * vocabulary ({@code policy.rule.draft}), versions and file names stay. In a field, a bare host the caller marks
     * public stays too.
     */
    private void hosts(Claims c, Predicate<String> publicHost) {
        String s = c.s;
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
            while (a < b && ".-_".indexOf(s.charAt(a)) >= 0) {
                a++;
            }
            while (b > a && ".-_".indexOf(s.charAt(b - 1)) >= 0) {
                b--;
            }
            if (b <= a || !c.free(a, b)) {
                continue;
            }
            String host = s.substring(a, b).toLowerCase(Locale.ROOT);
            if (hostShaped(host) && !publicHost.test(host)) {
                c.claim(a, b, pseudonymiser.token("HST", host));
            }
        }
    }

    static boolean hostShaped(String host) {
        List<String> labels = new ArrayList<>();
        int from = 0;
        for (int k = 0; k <= host.length(); k++) {
            if (k == host.length() || host.charAt(k) == '.') {
                String label = host.substring(from, k);
                if (label.isEmpty() || label.length() > 63) {
                    return false;
                }
                labels.add(label);
                from = k + 1;
            }
        }
        if (labels.size() < 2) {
            return false;
        }
        String last = labels.get(labels.size() - 1);
        if (last.length() < 2 || last.length() > 24 || !last.chars().allMatch(Character::isLetter)) {
            return false;
        }
        boolean topLevel = TOP_LEVEL.contains(last) || (last.length() == 2 && !FILE_ENDINGS.contains(last));
        boolean hostish = labels.stream().anyMatch(l -> l.chars().anyMatch(ch -> Character.isDigit(ch) || ch == '-'
            || ch == '_'));
        return topLevel || (labels.size() >= 3 && hostish) || labels.size() >= 4;
    }

    private static boolean hostChar(char ch) {
        return Character.isLetterOrDigit(ch) || ch == '.' || ch == '-' || ch == '_';
    }

    /**
     * The word after a keyword (MASKING_AND_PRIVACY B2 layer 5): after {@code host}, {@code user}, {@code müşteri},
     * {@code hesap}, {@code TCKN}, {@code IBAN} and their kin unless it is an ordinary word of such sentences; after
     * {@code from}, {@code to} only when it looks like an identifier (a digit, a dot, an at sign, a slash or backslash,
     * a hyphen or underscore, or capitals inside it).
     */
    private void keywords(Claims c) {
        String s = c.s;
        int n = s.length();
        int i = 0;
        while (i < n) {
            if (Character.isWhitespace(s.charAt(i))) {
                i++;
                continue;
            }
            int start = i;
            while (i < n && !Character.isWhitespace(s.charAt(i)) && s.charAt(i) != ':' && s.charAt(i) != '=') {
                i++;
            }
            if (i == start) {
                i++;
                continue;
            }
            String keyword = fold(strip(s.substring(start, i)));
            int value = i;
            while (value < n && (s.charAt(value) == ':' || s.charAt(value) == '=' || s.charAt(value) == ' '
                || s.charAt(value) == '\t')) {
                value++;
            }
            if (!isKeyword(keyword) || value >= n || value - i > 4) {
                continue;
            }
            int end = value;
            while (end < n && !Character.isWhitespace(s.charAt(end))) {
                end++;
            }
            int vs = value;
            int ve = end;
            while (vs < ve && "(\"'[<".indexOf(s.charAt(vs)) >= 0) {
                vs++;
            }
            while (ve > vs && ",.;:!?)\"']>".indexOf(s.charAt(ve - 1)) >= 0) {
                ve--;
            }
            if (ve - vs < 3 || !c.free(vs, ve)) {
                continue;
            }
            String word = s.substring(vs, ve);
            String folded = fold(word);
            // A host-shaped value was decided by the host layer (masked, or a public vendor endpoint kept on purpose).
            if (STOP_WORDS.contains(folded) || isKeyword(folded) || hostShaped(word.toLowerCase(Locale.ROOT))) {
                continue;
            }
            if (WEAK_WORDS.contains(keyword) && !identifierLooking(word)) {
                continue;
            }
            // A TCKN or an IBAN has digits: "kimlik doğrulama" is a sentence (N-04).
            if ((TCKN_WORDS.contains(keyword) || IBAN_WORDS.contains(keyword))
                && word.chars().noneMatch(Character::isDigit)) {
                continue;
            }
            c.claim(vs, ve, keywordToken(keyword, word, folded));
        }
    }

    private static boolean isKeyword(String folded) {
        return USER_WORDS.contains(folded) || HOST_WORDS.contains(folded) || CUSTOMER_WORDS.contains(folded)
            || TCKN_WORDS.contains(folded) || IBAN_WORDS.contains(folded) || WEAK_WORDS.contains(folded);
    }

    private String keywordToken(String keyword, String word, String folded) {
        if (USER_WORDS.contains(keyword)) {
            return pseudonymiser.user(word);
        }
        if (CUSTOMER_WORDS.contains(keyword)) {
            return pseudonymiser.token("CUST", folded);
        }
        if (TCKN_WORDS.contains(keyword)) {
            return pseudonymiser.token("TCKN", word);
        }
        if (IBAN_WORDS.contains(keyword)) {
            return pseudonymiser.token("IBAN", word.replace(" ", "").toUpperCase(Locale.ROOT));
        }
        return pseudonymiser.token("HST", folded);
    }

    private static String strip(String word) {
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

    private static boolean identifierLooking(String word) {
        for (int k = 0; k < word.length(); k++) {
            char ch = word.charAt(k);
            if (Character.isDigit(ch) || "._-@\\/".indexOf(ch) >= 0 || (k > 0 && Character.isUpperCase(ch))) {
                return true;
            }
        }
        return false;
    }

    /** Serial-like tokens: 8 to 32 ASCII letters and digits with at least three digits and two letters. */
    private void serials(Claims c) {
        String s = c.s;
        int n = s.length();
        int i = 0;
        while (i < n) {
            if (!asciiAlnum(s.charAt(i))) {
                i++;
                continue;
            }
            int start = i;
            int digits = 0;
            int letters = 0;
            while (i < n && asciiAlnum(s.charAt(i))) {
                if (Character.isDigit(s.charAt(i))) {
                    digits++;
                } else {
                    letters++;
                }
                i++;
            }
            int length = i - start;
            if (length >= SERIAL_MIN && length <= SERIAL_MAX && digits >= 3 && letters >= 2 && !alnumAt(s, start - 1)
                && !alnumAt(s, i)) {
                c.claim(start, i, pseudonymiser.token("SER", s.substring(start, i).toUpperCase(Locale.ROOT)));
            }
        }
    }

    private static boolean asciiAlnum(char ch) {
        return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9');
    }
}
