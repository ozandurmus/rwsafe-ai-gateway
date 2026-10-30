package io.rwsafe.control.privacy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class PseudonymiserTest {

    static PrivacyKeys keys(int seed) {
        byte[] key = new byte[32];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) (seed * 31 + i);
        }
        return new PrivacyKeys(key, List.of("synthetic-estate"));
    }

    private final Pseudonymiser p = new Pseudonymiser(keys(1));

    @Test
    void userPseudonymsAreStableAndCaseInsensitivePerRealm() {
        String a = p.user("SYNTHETIC\\synthetic.user.001");
        assertTrue(a.matches("USR-[0-9a-f]{10}"));
        assertEquals(a, p.user("synthetic\\Synthetic.User.001"));
        assertEquals(a, p.user("synthetic.user.001@synthetic"));
        assertNotEquals(a, p.user("SYNTHETIC\\synthetic.user.002"));
        assertNotEquals(a, p.user("OTHER-SYNTHETIC\\synthetic.user.001"));
        assertNull(p.user(null));
        assertNull(p.user("  "));
    }

    // PR 21 review D-03: one group, one pseudonym, under the shared normal form (NFC, the Turkish and Latin i forms).
    @Test
    void groupPseudonymsFollowTheSharedNormalForm() {
        String g = p.group("grp-istanbul");
        assertTrue(g.matches("GRP-[0-9a-f]{10}"));
        for (String spelling : new String[] {"GRP-İSTANBUL", " grp-ıstanbul ", "GRP-ISTANBUL",
            "grp-i̇stanbul", "GRP-İSTANBUL"}) {
            assertEquals(g, p.group(spelling), spelling);
        }
        assertNotEquals(g, p.group("grp-izmir"));
        assertTrue(p.group("grp-a,grp-b").matches("GRP-[0-9a-f]{10}"), "an invalid name is still never shown");
    }

    @Test
    void anotherKeyGivesOtherPseudonyms() {
        assertNotEquals(p.user("synthetic.user.001"), new Pseudonymiser(keys(2)).user("synthetic.user.001"));
    }

    @Test
    void subnetsArePreservedHostsAreDroppedAndLabelsLieIn240Slash4() {
        String a = p.subnet("192.0.2.10");
        assertEquals(a, p.subnet("192.0.2.200"));
        assertNotEquals(a, p.subnet("198.51.100.10"));
        assertTrue(a.endsWith(".0/24"));
        int first = Integer.parseInt(a.substring(0, a.indexOf('.')));
        assertTrue(first >= 240 && first <= 255);
        assertTrue(!a.contains("192.0.2"));
    }

    @Test
    void ipv6AndMalformedAddressesAreNeverStoredAsGiven() {
        assertEquals(Pseudonymiser.REDACTED_IP, p.subnet("2001:db8::1"));
        assertEquals(Pseudonymiser.INVALID_ADDRESS, p.subnet("192.0.2"));
        assertEquals(Pseudonymiser.INVALID_ADDRESS, p.subnet("192.0.2.010"));
        assertEquals(Pseudonymiser.INVALID_ADDRESS, p.subnet("synthetic.example.test"));
        assertEquals(Pseudonymiser.INVALID_ADDRESS, p.subnet("192.0.2.256"));
        assertNull(p.subnet(null));
    }

    @Test
    void withoutAKeyNothingIsComputed() {
        Pseudonymiser none = new Pseudonymiser(new PrivacyKeys(new byte[16], List.of()));
        assertThrows(MaskingUnavailableException.class, () -> none.user("synthetic.user.001"));
        assertThrows(MaskingUnavailableException.class, () -> none.subnet("192.0.2.1"));
    }
}
