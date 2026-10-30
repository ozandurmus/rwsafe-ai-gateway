package io.rwsafe.dataplane.server;

import io.rwsafe.dataplane.icap.HeaderBlock;
import io.rwsafe.policy.ScopedRule;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

/**
 * Reads the proxy's group claim, {@code X-Authenticated-Groups} (ICAP spec identity row), into normalised group names for
 * {@link io.rwsafe.policy.PolicyEvaluator#resolve}. The result is identity data: it is never logged, never put in a
 * metrics label and never copied onto a verdict event (only rule ids travel, POLICY_SNAPSHOT_CONTRACT.md format 2).
 *
 * <p>UNVERIFIED (2026-10-30): whether the estate's proxy sends this header and in which format is open (PO decision Q-39,
 * open item; verified with the PO against the proxy guide). This reader accepts a comma-separated list, each entry
 * trimmed and compared case-insensitively, taken verbatim otherwise (a {@code WinNT://} or {@code LDAP://} prefix is
 * part of the name the registry must hold). It also accepts the whole value base64-encoded, the convention ProxySG
 * documents for its ICAP identity headers; the shape test below is a heuristic. Anything it cannot read with confidence
 * is no claim (null), which selects the strictest policy, never a looser one.
 */
final class GroupClaim {

    static final String HEADER = "X-Authenticated-Groups";
    /** A claim longer than this, or with more groups, is no claim: cutting it could drop the group that matters. */
    static final int MAX_VALUE = 8 * 1024;
    static final int MAX_GROUPS = 256;
    /** The longest group name a snapshot may carry; a longer claimed entry can match no rule and is skipped. */
    private static final int MAX_GROUP_NAME = 256;

    private GroupClaim() {
    }

    /** The claimed groups, normalised by {@link ScopedRule#normaliseGroup}, or null when missing or unreadable. */
    static Set<String> parse(HeaderBlock icapHead) {
        if (icapHead.count(HEADER) != 1) {
            return null;
        }
        return parse(icapHead.first(HEADER));
    }

    static Set<String> parse(String headerValue) {
        if (headerValue == null || headerValue.length() > MAX_VALUE) {
            return null;
        }
        String value = utf8(headerValue.strip());
        if (value == null || value.isEmpty()) {
            return null;
        }
        String decoded = base64(value);
        if (decoded != null) {
            value = decoded;
        }
        Set<String> groups = new HashSet<>();
        int start = 0;
        while (true) {
            int comma = value.indexOf(',', start);
            int end = comma < 0 ? value.length() : comma;
            String entry = value.substring(start, end).strip();
            if (!entry.isEmpty() && entry.length() <= MAX_GROUP_NAME) {
                groups.add(ScopedRule.normaliseGroup(entry));
                if (groups.size() > MAX_GROUPS) {
                    return null;
                }
            }
            if (comma < 0) {
                break;
            }
            start = comma + 1;
        }
        return groups.isEmpty() ? null : Set.copyOf(groups);
    }

    /**
     * Header values arrive as ISO-8859-1 characters (one per octet, {@link HeaderBlock}); non-ASCII octets are read as
     * UTF-8 (UNVERIFIED, as above). Octets that are not valid UTF-8 make the claim unreadable.
     */
    private static String utf8(String latin1) {
        boolean ascii = true;
        for (int i = 0; i < latin1.length() && ascii; i++) {
            ascii = latin1.charAt(i) < 0x80;
        }
        return ascii ? latin1 : strictUtf8(latin1.getBytes(StandardCharsets.ISO_8859_1));
    }

    /**
     * UNVERIFIED heuristic for the ProxySG base64 convention: the value is one token of the base64 alphabet whose length
     * is a multiple of four, decodes to valid UTF-8 without control characters, and the decoded text contains a character
     * outside the base64 alphabet (a separator, a scheme colon, a space, a backslash). A plain group name such as
     * {@code dev1} fails the last two tests and is read as it is.
     */
    private static String base64(String value) {
        if (value.length() % 4 != 0) {
            return null;
        }
        for (int i = 0; i < value.length(); i++) {
            if (!isBase64(value.charAt(i))) {
                return null;
            }
        }
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            return null;
        }
        String text = strictUtf8(raw);
        if (text == null || text.isBlank()) {
            return null;
        }
        boolean outside = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c < 0x20 || c == 0x7f) {
                return null;
            }
            outside |= !isBase64(c);
        }
        return outside ? text : null;
    }

    private static boolean isBase64(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/'
            || c == '=';
    }

    private static String strictUtf8(byte[] bytes) {
        try {
            CharBuffer chars = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes));
            return chars.toString();
        } catch (CharacterCodingException e) {
            return null;
        }
    }
}
