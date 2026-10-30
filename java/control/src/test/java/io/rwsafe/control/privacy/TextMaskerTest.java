package io.rwsafe.control.privacy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.control.support.Synthetic;
import java.util.List;
import org.junit.jupiter.api.Test;

/** The free-text layers on synthetic values built at runtime (the MASKING_AND_PRIVACY lesson: test adjacent shapes). */
class TextMaskerTest {

    private final Masking masking = new Masking(PseudonymiserTest.keys(1),
        new Pseudonymiser(PseudonymiserTest.keys(1)));
    private final TextMasker m = masking.masker();

    @Test
    void turkishIdentifiersBecomeClassTokens() {
        String tckn = Synthetic.tckn(7);
        String iban = Synthetic.iban(7);
        String card = Synthetic.card(7);
        String out = m.mask("musteri " + tckn + " hesap " + iban + " kart " + card);
        assertFalse(out.contains(tckn));
        assertFalse(out.contains(iban));
        assertFalse(out.contains(card));
        assertTrue(out.matches("musteri TCKN-[0-9a-f]{4} hesap IBAN-TR-[0-9a-f]{4} kart CARD-[0-9a-f]{4}"), out);
        assertEquals(out, m.mask("musteri " + tckn + " hesap " + iban + " kart " + card), "stable across screens");
    }

    @Test
    void secretShapesAreRedacted() {
        String out = m.mask("key " + Synthetic.githubToken() + " end");
        assertEquals("key [REDACTED:SECRET] end", out);
    }

    @Test
    void addressesAndMailAreMaskedButTimesAndIdsAreNot() {
        String text = "from 192.0.2.10:8443 and 198.51.100.7/24 at 12:30:45, v6 2001:db8::5, mail synthetic.user@example.invalid"
            + " id 7e333ed3-40c7-1185-e8f9-081f9ff9ce6e";
        String out = m.mask(text);
        assertFalse(out.contains("192.0.2.10"));
        assertFalse(out.contains("198.51.100.7"));
        assertFalse(out.contains("2001:db8::5"));
        assertFalse(out.contains("synthetic.user@example.invalid"));
        assertTrue(out.contains("12:30:45"));
        assertTrue(out.contains("7e333ed3-40c7-1185-e8f9-081f9ff9ce6e"));
        assertTrue(out.contains(Pseudonymiser.REDACTED_IP));
        assertTrue(out.contains(":8443"));
    }

    @Test
    void turkishMobileNumbersAndEstateTermsAreMasked() {
        String phone = "05" + "32" + " 123 45 67";
        String out = m.mask("ara " + phone + " on SYNTHETIC-ESTATE.core:1 or synthetic-estate");
        assertFalse(out.contains("123 45 67"), out);
        assertFalse(out.toLowerCase().contains("synthetic-estate"), out);
        assertTrue(out.contains("TEL-"));
        assertTrue(out.contains("EST-"));
        assertTrue(out.contains(".core:1"));
    }

    @Test
    void withoutTheDictionaryTheMaskedRoleIsRefused() {
        byte[] key = new byte[32];
        PrivacyKeys noDictionary = new PrivacyKeys(key, null);
        Masking off = new Masking(noDictionary, new Pseudonymiser(noDictionary));
        assertFalse(off.available());
        assertThrows(MaskingUnavailableException.class, off::masker);
        assertTrue(noDictionary.keyAvailable());
        assertEquals(List.of(), new PrivacyKeys(key, List.of()).estateTerms());
    }
}
