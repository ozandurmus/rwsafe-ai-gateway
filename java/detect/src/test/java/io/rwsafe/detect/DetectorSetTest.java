package io.rwsafe.detect;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.platform.verdict.DataClass;
import io.rwsafe.platform.verdict.Finding;
import java.util.List;
import org.junit.jupiter.api.Test;

class DetectorSetTest {

    private final DetectorSet set = DetectorSet.standard();

    private List<DataClass> classes(String text) {
        return set.scan(Normaliser.normalise(text)).stream().map(Finding::dataClass).toList();
    }

    @Test
    void validTcknIsFoundAndAnInvalidOneIsNot() {
        String valid = Synthetic.tckn(7);
        String broken = valid.substring(0, 10) + ((valid.charAt(10) - '0' + 1) % 10);
        assertEquals(List.of(DataClass.TCKN), classes("synthetic customer " + valid + " please"));
        assertEquals(List.of(), classes("synthetic customer " + broken + " please"));
        assertEquals(List.of(), classes("order " + valid + "9 is longer"));
    }

    @Test
    void ibanCompactAndGrouped() {
        String iban = Synthetic.iban(11);
        StringBuilder grouped = new StringBuilder();
        for (int k = 0; k < iban.length(); k += 4) {
            grouped.append(iban, k, Math.min(k + 4, iban.length())).append(k + 4 < iban.length() ? " " : "");
        }
        assertEquals(List.of(DataClass.TR_IBAN), classes("synthetic transfer to " + iban));
        assertTrue(classes("synthetic transfer to " + grouped).contains(DataClass.TR_IBAN));
    }

    @Test
    void cardNeedsLuhn() {
        String card = Synthetic.card(3);
        assertEquals(List.of(DataClass.PAYMENT_CARD), classes("synthetic card " + card));
        String broken = card.substring(0, 15) + ((card.charAt(15) - '0' + 1) % 10);
        assertEquals(List.of(), classes("synthetic card " + broken));
    }

    @Test
    void secretShapes() {
        assertEquals(List.of(DataClass.SECRET), classes("synthetic key " + Synthetic.awsKey() + " end"));
        assertEquals(List.of(DataClass.SECRET), classes("token " + Synthetic.githubToken()));
        assertEquals(List.of(DataClass.SECRET), classes("-----BEGIN RSA " + "PRIVATE KEY-----\nsynthetic"));
    }

    @Test
    void zeroWidthSplitIsNormalisedAway() {
        String valid = Synthetic.tckn(19);
        String split = valid.substring(0, 5) + "​" + valid.substring(5);
        assertEquals(List.of(DataClass.TCKN), classes("synthetic " + split));
    }

    @Test
    void fullWidthDigitsAreFolded() {
        String valid = Synthetic.tckn(23);
        StringBuilder wide = new StringBuilder();
        valid.chars().forEach(c -> wide.append((char) (c - '0' + 0xFF10)));
        assertEquals(List.of(DataClass.TCKN), classes("synthetic " + wide));
    }

    @Test
    void redactorReplacesWithClassTokens() {
        String text = Normaliser.normalise("synthetic a " + Synthetic.tckn(5) + " b " + Synthetic.awsKey());
        String redacted = Redactor.redact(text, set.scan(text));
        assertEquals("synthetic a [REDACTED:TCKN] b [REDACTED:SECRET]", redacted);
    }

    @Test
    void linearOnAdversarialInput() {
        String hostile = "sk-" + "a".repeat(2_000_000) + "!" + "1".repeat(500_000);
        long t0 = System.nanoTime();
        set.scan(hostile);
        long ms = (System.nanoTime() - t0) / 1_000_000;
        assertTrue(ms < 5_000, "scan took " + ms + " ms");
    }

    /** PR 11 review D-05. */
    @Test
    void cardFollowedByExpiryAndLowercaseIban() {
        String card = Synthetic.card(8);
        assertTrue(classes("synthetic " + card + " 12 27 cvv").contains(DataClass.PAYMENT_CARD));
        assertTrue(classes("synthetic " + card.substring(0, 4) + "-" + card.substring(4, 8) + "-" + card.substring(8, 12)
            + "-" + card.substring(12) + "-12-27").contains(DataClass.PAYMENT_CARD));
        assertEquals(List.of(DataClass.TR_IBAN), classes("synthetic " + Synthetic.iban(4).toLowerCase()));
    }

    /** PR 11 review D-01: every detector stops at the limit, and the limit is visible to the caller. */
    @Test
    void findingLimitIsReported() {
        StringBuilder s = new StringBuilder("synthetic ");
        for (int i = 0; i < 1200; i++) {
            s.append(Synthetic.tckn(i)).append(' ');
        }
        List<Finding> found = set.scan(s.toString());
        assertTrue(DetectorSet.overLimit(found));
        assertEquals(DetectorSet.MAX_FINDINGS, found.size());
    }
}
