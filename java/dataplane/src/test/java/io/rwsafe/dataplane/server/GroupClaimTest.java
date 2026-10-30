package io.rwsafe.dataplane.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import io.rwsafe.dataplane.icap.HeaderBlock;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** {@code X-Authenticated-Groups} reading; the header's format on the estate proxy is UNVERIFIED (PO decision Q-39). */
class GroupClaimTest {

    private static HeaderBlock head(String extra) {
        byte[] b = ("REQMOD icap://icap.example.invalid/reqmod-ai ICAP/1.0\r\nHost: icap.example.invalid\r\n" + extra
            + "\r\n").getBytes(StandardCharsets.ISO_8859_1);
        return HeaderBlock.parse(b, 0, b.length, 8192, 64, 400);
    }

    private static String b64(String s) {
        return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void readsACommaSeparatedListTrimmedAndCaseInsensitive() {
        assertEquals(Set.of("finance", "platform-devs"), GroupClaim.parse(" Finance ,PLATFORM-DEVS,, finance "));
        assertEquals(Set.of("winnt://synthetic/finance"), GroupClaim.parse("WinNT://synthetic/Finance"),
            "a scheme prefix is part of the name");
        assertEquals(Set.of("dev1"), GroupClaim.parse("dev1"), "a short base64-shaped name is read as it is");
        assertEquals(Set.of("abcd"), GroupClaim.parse("abcd"));
    }

    @Test
    void decodesTheBase64Convention() {
        assertEquals(Set.of("finance", "platform-devs"), GroupClaim.parse(b64("finance,platform-devs")));
        assertEquals(Set.of("winnt://synthetic/finance"), GroupClaim.parse(b64("WinNT://synthetic/finance")));
        assertEquals(Set.of("muhasebe-ğrubu"), GroupClaim.parse(b64("Muhasebe-Ğrubu")), "UTF-8 inside base64");
    }

    @Test
    void readsUtf8Octets() {
        String latin1 = new String("Muhasebe-Ğrubu".getBytes(StandardCharsets.UTF_8), StandardCharsets.ISO_8859_1);
        assertEquals(Set.of("muhasebe-ğrubu"), GroupClaim.parse(latin1));
    }

    @Test
    void anythingUnreadableIsNoClaim() {
        assertNull(GroupClaim.parse((String) null));
        assertNull(GroupClaim.parse("   "));
        assertNull(GroupClaim.parse(" , ,"));
        assertNull(GroupClaim.parse(new String(new byte[] {(byte) 0xC3, (byte) 0x28}, StandardCharsets.ISO_8859_1)),
            "octets that are not UTF-8");
        assertNull(GroupClaim.parse("g".repeat(GroupClaim.MAX_VALUE + 1)));
        StringBuilder many = new StringBuilder();
        for (int i = 0; i <= GroupClaim.MAX_GROUPS; i++) {
            many.append("g").append(i).append(',');
        }
        assertNull(GroupClaim.parse(many.toString()), "more groups than the bound: never a truncated claim");
        assertEquals(Set.of("short"), GroupClaim.parse("short," + "x".repeat(300)),
            "an entry longer than any rule group can match nothing and is skipped");
    }

    @Test
    void readsTheIcapHeaderOnce() {
        assertEquals(Set.of("finance"), GroupClaim.parse(head("X-Authenticated-Groups: finance\r\n")));
        assertEquals(Set.of("finance"), GroupClaim.parse(head("x-authenticated-groups: finance\r\n")));
        assertNull(GroupClaim.parse(head("")), "missing");
        assertNull(GroupClaim.parse(head("X-Authenticated-Groups: finance\r\nX-Authenticated-Groups: audit\r\n")),
            "two headers are ambiguous: no claim");
    }
}
