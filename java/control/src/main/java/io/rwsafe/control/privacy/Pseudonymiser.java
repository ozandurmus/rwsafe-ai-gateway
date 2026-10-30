package io.rwsafe.control.privacy;

import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.function.Predicate;
import org.springframework.stereotype.Component;

/**
 * Layer 1 and layer 2 of MASKING_AND_PRIVACY B2, applied before persistence: the proxy's identity claim becomes
 * {@code USR-<10 hex>} and the client address becomes a subnet label in the synthetic 240/4 space. Neither input is kept.
 */
@Component
public class Pseudonymiser {

    public static final String REDACTED_IP = "[REDACTED_IP]";
    public static final String INVALID_ADDRESS = "[INVALID_ADDRESS]";

    /** The alphabet of {@code <WORD>} pseudonyms: four consonant-vowel syllables, 39^4 (about 2.3 million) words. */
    private static final String WORD_CONSONANTS = "BDFGLMNPRSTVZ";
    private static final String WORD_VOWELS = "AEO";
    private static final int WORD_SYLLABLES = 4;
    private static final int WORD_ATTEMPTS = 8;
    /** Fragments a generated word never carries (an unfortunate reading in Turkish or English). */
    private static final List<String> WORD_BLOCKED = List.of("GOT", "MEME", "POPO", "PEZE", "DOLO");

    private final PrivacyKeys keys;

    public Pseudonymiser(PrivacyKeys keys) {
        this.keys = keys;
    }

    /**
     * the {@code DOMAIN}-backslash-{@code user} form (PHASE0_PROXYSG_RECORD F-3) or {@code user@realm}: the realm is a label and the user part is
     * the person; both are lower-cased, so the same person reads the same in every claim spelling of one realm.
     */
    public String user(String claim) {
        if (claim == null || claim.isBlank()) {
            return null;
        }
        String c = claim.strip().toLowerCase(Locale.ROOT);
        String realm = "";
        String user = c;
        int backslash = c.lastIndexOf('\\');
        int at = c.lastIndexOf('@');
        if (backslash >= 0) {
            realm = c.substring(0, backslash);
            user = c.substring(backslash + 1);
        } else if (at >= 0) {
            realm = c.substring(at + 1);
            user = c.substring(0, at);
        }
        return "USR-" + HexFormat.of().formatHex(keys.hmac("user", realm + "\\" + user), 0, 5);
    }

    /**
     * IPv4: the /24 maps to a stable, keyed /24 inside 240.0.0.0/4 and the host octet is dropped, so "same subnet" stays
     * visible while the address does not (neXus {@code SubnetPreservingIpMasker}, minimised). 20 bits of label for 24 bits
     * of prefix: two subnets can share a label, which only merges them on screen. IPv6 is redacted (fail closed).
     */
    public String subnet(String address) {
        if (address == null || address.isBlank()) {
            return null;
        }
        String a = address.strip();
        if (a.indexOf(':') >= 0) {
            return REDACTED_IP;
        }
        int[] octets = ipv4(a);
        if (octets == null) {
            return INVALID_ADDRESS;
        }
        byte[] h = keys.hmac("subnet", octets[0] + "." + octets[1] + "." + octets[2]);
        int first = 240 + (h[0] & 0x0F);
        return first + "." + (h[1] & 0xFF) + "." + (h[2] & 0xFF) + ".0/24";
    }

    /**
     * A directory group name as the masked role sees it (PO decision Q-39): {@code GRP-<10 hex>}, keyed, stable per
     * estate, the same for every spelling the shared normal form ({@link io.rwsafe.policy.GroupNames#normalise}: NFC, the
     * Turkish and Latin i forms, case, surrounding space) treats as one group (PR 21 review D-03). A name that is not a
     * valid group name is still pseudonymised, never returned.
     */
    public String group(String name) {
        if (name == null || name.isBlank()) {
            return name;
        }
        String normal = io.rwsafe.policy.GroupNames.normalise(name);
        String key = normal != null ? normal : "invalid:" + name.strip().toLowerCase(Locale.ROOT);
        return "GRP-" + HexFormat.of().formatHex(keys.hmac("group", key), 0, 5);
    }

    /** A class-visible token such as {@code TCKN-1a2b}: the same value reads the same across screens (layer 4). */
    public String token(String label, String value) {
        return label + "-" + HexFormat.of().formatHex(keys.hmac("token:" + label, value), 0, 2);
    }

    /**
     * A {@code LABEL-<WORD>} pseudonym (MASKING_AND_PRIVACY B2, layer 4: {@code NAME-<WORD>}): a pronounceable upper-case
     * word of four consonant-vowel syllables chosen by rwsafe's HMAC over the value, so it is stable per estate and
     * changes with the key. A word with a blocked fragment, or one {@code refused} rejects (a word that reads as a real
     * name), is drawn again from the next keyed attempt; the draws are deterministic, so the same value always reads the
     * same. Two values can share a word (about one in 2.3 million per pair): the B3 pseudonym registry that would claim
     * each word once per kind does not exist yet.
     */
    public String word(String label, String value, Predicate<String> refused) {
        String word = null;
        for (int attempt = 0; attempt < WORD_ATTEMPTS; attempt++) {
            byte[] h = keys.hmac("word:" + label, attempt == 0 ? value : value + "\0" + attempt);
            StringBuilder w = new StringBuilder(2 * WORD_SYLLABLES);
            for (int k = 0; k < WORD_SYLLABLES; k++) {
                int syllable = (((h[2 * k] & 0xFF) << 8) | (h[2 * k + 1] & 0xFF))
                    % (WORD_CONSONANTS.length() * WORD_VOWELS.length());
                w.append(WORD_CONSONANTS.charAt(syllable / WORD_VOWELS.length()))
                    .append(WORD_VOWELS.charAt(syllable % WORD_VOWELS.length()));
            }
            word = w.toString();
            if (WORD_BLOCKED.stream().noneMatch(word::contains) && !refused.test(word)) {
                break;
            }
        }
        return label + "-" + word;
    }

    /** Strict dotted-quad parse without name resolution; null for anything else. */
    public static int[] ipv4(String s) {
        String[] parts = s.split("\\.", -1);
        if (parts.length != 4) {
            return null;
        }
        int[] out = new int[4];
        for (int i = 0; i < 4; i++) {
            String p = parts[i];
            if (p.isEmpty() || p.length() > 3 || (p.length() > 1 && p.charAt(0) == '0')) {
                return null;
            }
            int v = 0;
            for (int j = 0; j < p.length(); j++) {
                char c = p.charAt(j);
                if (c < '0' || c > '9') {
                    return null;
                }
                v = v * 10 + (c - '0');
            }
            if (v > 255) {
                return null;
            }
            out[i] = v;
        }
        return out;
    }
}
