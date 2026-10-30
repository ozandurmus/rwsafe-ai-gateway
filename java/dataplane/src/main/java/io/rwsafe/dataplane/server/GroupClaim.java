package io.rwsafe.dataplane.server;

import io.rwsafe.dataplane.icap.HeaderBlock;
import io.rwsafe.dataplane.server.EngineConfig.GroupClaimEncoding;
import io.rwsafe.policy.GroupNames;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

/**
 * Reads the proxy's group claim, {@code X-Authenticated-Groups} (ICAP spec identity row), into group names in the
 * comparison form of {@link GroupNames} for {@link io.rwsafe.policy.PolicyEvaluator#resolve}. The result is identity data:
 * it is never logged, never put in a metrics label and never copied onto a verdict event (only rule ids travel,
 * POLICY_SNAPSHOT_CONTRACT.md format 2).
 *
 * <p>The encoding is a configured fact, never guessed per value (PR 20 review D-01, Q-1; {@link GroupClaimEncoding}). Which
 * one the estate's proxy uses is UNVERIFIED (2026-10-30; PO decision Q-39, open item). The decoded value is a list of
 * short group names separated by commas (review Q-2: names hold no comma). Anything this reader cannot read exactly is
 * no claim (null), which selects the strictest policy, never a looser one: a control character, a token over
 * {@value GroupNames#MAX_LENGTH} characters, more than {@value #MAX_TOKENS} tokens (empty and repeated ones counted),
 * octets that are not UTF-8, invalid base64, or no group at all.
 */
final class GroupClaim {

    static final String HEADER = "X-Authenticated-Groups";
    /** A claim longer than this, or with more tokens, is no claim: cutting it could drop the group that matters. */
    static final int MAX_VALUE = 8 * 1024;
    static final int MAX_TOKENS = 256;

    private GroupClaim() {
    }

    /** The claimed groups in comparison form, or null when disabled, missing, repeated or unreadable. */
    static Set<String> parse(HeaderBlock icapHead, GroupClaimEncoding encoding) {
        if (encoding == GroupClaimEncoding.DISABLED || icapHead.count(HEADER) != 1) {
            return null;
        }
        return parse(icapHead.first(HEADER), encoding);
    }

    /** @param headerValue the field value as {@link HeaderBlock} holds it (one ISO-8859-1 character per octet) */
    static Set<String> parse(String headerValue, GroupClaimEncoding encoding) {
        if (encoding == null || encoding == GroupClaimEncoding.DISABLED || headerValue == null
            || headerValue.length() > MAX_VALUE) {
            return null;
        }
        // No strip(): HeaderBlock already trimmed OWS, and strip() would drop a control character (review N-01).
        byte[] octets = headerValue.getBytes(StandardCharsets.ISO_8859_1);
        if (encoding == GroupClaimEncoding.BASE64) {
            octets = base64(octets);
            if (octets == null) {
                return null;
            }
        }
        String list = strictUtf8(octets);
        return list == null ? null : groups(list);
    }

    private static Set<String> groups(String list) {
        for (int i = 0; i < list.length(); i++) {
            char c = list.charAt(i);
            if (c < 0x20 || c == 0x7f) {
                return null;
            }
        }
        Set<String> groups = new HashSet<>();
        int tokens = 0;
        int start = 0;
        while (true) {
            if (++tokens > MAX_TOKENS) {
                return null;
            }
            int comma = list.indexOf(',', start);
            int end = comma < 0 ? list.length() : comma;
            String token = list.substring(start, end);
            if (!token.isBlank()) {
                String name = GroupNames.normalise(token);
                if (name == null) {
                    return null;
                }
                groups.add(name);
            }
            if (comma < 0) {
                break;
            }
            start = comma + 1;
        }
        return groups.isEmpty() ? null : Set.copyOf(groups);
    }

    /** Standard base64 with padding, the whole value; null when it is not exactly that. */
    private static byte[] base64(byte[] value) {
        if (value.length == 0 || value.length % 4 != 0) {
            return null;
        }
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static String strictUtf8(byte[] bytes) {
        try {
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException e) {
            return null;
        }
    }
}
