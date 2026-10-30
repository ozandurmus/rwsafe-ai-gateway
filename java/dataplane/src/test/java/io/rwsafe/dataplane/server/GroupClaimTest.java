package io.rwsafe.dataplane.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import io.rwsafe.dataplane.icap.HeaderBlock;
import io.rwsafe.dataplane.server.EngineConfig.GroupClaimEncoding;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * {@code X-Authenticated-Groups} reading under the configured encoding (PR 20 review D-01, D-03, Q-1, Q-2); the header's
 * format on the estate proxy is UNVERIFIED (PO decision Q-39).
 */
class GroupClaimTest {

    private static final GroupClaimEncoding PLAIN = GroupClaimEncoding.PLAIN;
    private static final GroupClaimEncoding BASE64 = GroupClaimEncoding.BASE64;

    private static HeaderBlock head(String extra) {
        byte[] b = ("REQMOD icap://icap.example.invalid/reqmod-ai ICAP/1.0\r\nHost: icap.example.invalid\r\n" + extra
            + "\r\n").getBytes(StandardCharsets.ISO_8859_1);
        return HeaderBlock.parse(b, 0, b.length, 8192, 64, 400);
    }

    private static String b64(String s) {
        return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    /** The header as HeaderBlock holds it: one ISO-8859-1 character per octet. */
    private static String octets(String utf8) {
        return new String(utf8.getBytes(StandardCharsets.UTF_8), StandardCharsets.ISO_8859_1);
    }

    @Test
    void theSettingIsExactAndDefaultsToDisabled() {
        assertEquals(PLAIN, GroupClaimEncoding.fromSetting("plain"));
        assertEquals(BASE64, GroupClaimEncoding.fromSetting("base64"));
        for (String other : new String[] {null, "", "PLAIN", " base64", "auto", "b64"}) {
            assertEquals(GroupClaimEncoding.DISABLED, GroupClaimEncoding.fromSetting(other), String.valueOf(other));
        }
        assertEquals(GroupClaimEncoding.DISABLED, EngineConfig.defaults().groupClaimEncoding());
        assertNull(GroupClaim.parse("finance", GroupClaimEncoding.DISABLED), "disabled: no claim, strictest for all");
        assertNull(GroupClaim.parse(head("X-Authenticated-Groups: finance\r\n"), GroupClaimEncoding.DISABLED));
    }

    @Test
    void plainReadsACommaSeparatedListInComparisonForm() {
        assertEquals(Set.of("finance", "platform-devs"), GroupClaim.parse(" Finance ,PLATFORM-DEVS,, finance ", PLAIN));
        assertEquals(Set.of("winnt://synthetic/finance"), GroupClaim.parse("WinNT://synthetic/Finance", PLAIN));
        assertEquals(Set.of("iç-denetim"), GroupClaim.parse(octets("İç-Denetim"), PLAIN),
            "UTF-8 octets, Turkish dotted capital I folded (D-02)");
        assertEquals(Set.of("zmluyw5jzq=="), GroupClaim.parse(b64("finance"), PLAIN),
            "plain mode never decodes: a base64-looking value is a literal name");
    }

    /** D-01: a single group whose letters are all in the base64 alphabet is decoded, never taken literally. */
    @Test
    void base64DecodesTheWholeValueAlways() {
        assertEquals(Set.of("finance"), GroupClaim.parse(b64("finance"), BASE64));
        assertEquals(Set.of("finance", "platform-devs"), GroupClaim.parse(b64("finance,platform-devs"), BASE64));
        assertEquals(Set.of("iç-denetim"), GroupClaim.parse(b64("IÇ-DENETİM"), BASE64));
        assertNull(GroupClaim.parse("finance", BASE64), "not base64 (length): no claim");
        assertNull(GroupClaim.parse("fin!", BASE64), "not base64 (alphabet): no claim");
        assertNull(GroupClaim.parse(b64("finance").replace("==", ""), BASE64), "padding is required");
        assertNull(GroupClaim.parse(Base64.getEncoder().encodeToString(new byte[] {(byte) 0xC3, 0x28}), BASE64),
            "decoded octets that are not UTF-8");
        assertNull(GroupClaim.parse(b64("finance\u0000,platform-devs"), BASE64), "a control character after decoding");
    }

    /** D-03: control characters, oversized tokens and too many tokens are no claim, never a partial one. */
    @Test
    void anythingUnreadableIsNoClaim() {
        assertNull(GroupClaim.parse((String) null, PLAIN));
        assertNull(GroupClaim.parse("   ", PLAIN));
        assertNull(GroupClaim.parse(" , ,", PLAIN));
        assertNull(GroupClaim.parse("Ã(", PLAIN), "octets that are not UTF-8");
        assertNull(GroupClaim.parse("finance\u0001,platform-devs", PLAIN), "control character");
        assertNull(GroupClaim.parse("finance\u007f,platform-devs", PLAIN), "DEL");
        assertNull(GroupClaim.parse("platform-devs," + "x".repeat(257), PLAIN), "a token over 256 characters");
        assertEquals(Set.of("x".repeat(256)), GroupClaim.parse(" " + "x".repeat(256) + " ", PLAIN));
        assertNull(GroupClaim.parse("g".repeat(GroupClaim.MAX_VALUE + 1), PLAIN));
        assertNull(GroupClaim.parse("a,".repeat(GroupClaim.MAX_TOKENS) + "a", PLAIN), "repeated tokens count");
        assertNull(GroupClaim.parse(",".repeat(GroupClaim.MAX_TOKENS) + "a", PLAIN), "empty tokens count");
        assertEquals(Set.of("a"), GroupClaim.parse(",".repeat(GroupClaim.MAX_TOKENS - 1) + "a", PLAIN),
            "exactly the bound is read");
    }

    @Test
    void readsTheIcapHeaderOnce() {
        assertEquals(Set.of("finance"), GroupClaim.parse(head("X-Authenticated-Groups: finance\r\n"), PLAIN));
        assertEquals(Set.of("finance"), GroupClaim.parse(head("x-authenticated-groups: finance\r\n"), PLAIN));
        assertNull(GroupClaim.parse(head(""), PLAIN), "missing");
        assertNull(GroupClaim.parse(head("X-Authenticated-Groups: finance\r\nX-Authenticated-Groups: audit\r\n"), PLAIN),
            "two headers are ambiguous: no claim");
    }
}
