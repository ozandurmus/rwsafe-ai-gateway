package io.rwsafe.control.privacy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.control.support.Synthetic;
import java.text.Normalizer;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.Test;

/**
 * Masking layers 4 (Turkish names) and 5 (free-text heuristics) of {@code rwmask-v2} on a synthetic corpus built at
 * runtime: generic dictionary names, identifiers with valid checksums generated here (AGENTS.md 4.5), documentation
 * addresses and example host names only.
 */
class TextMaskerFreeTextTest {

    private static final String NAME = "NAME-[0-9a-f]{4}";

    private final TextMasker m = new Masking(PseudonymiserTest.keys(1), new Pseudonymiser(PseudonymiserTest.keys(1)))
        .masker();

    @Test
    void theRuleSetVersionIsV2() {
        assertEquals("rwmask-v2", TextMasker.RULE_SET);
    }

    // ---- layer 4: names ----------------------------------------------------------------------------------------------

    @Test
    void aGivenNameWithAFamilyNameIsOnePersonTokenInEveryField() {
        String pair = m.mask("Ayşe Yılmaz");
        assertTrue(pair.matches(NAME), pair);
        assertEquals(pair, m.mask("AYŞE YILMAZ"), "case");
        assertEquals(pair, m.mask("Ayse Yilmaz"), "ASCII spelling");
        assertEquals(pair, m.mask("ayse.yilmaz"), "account-style spelling");
        assertEquals(pair, m.maskFreeText("Ayşe Yılmaz"), "the same token in free text");
        assertTrue(m.mask("Ayşe Nur Yılmaz").matches(NAME), "two given names and a family name");
        assertTrue(m.mask("YILMAZ Ayşe").matches(NAME), "family name first");
        assertNotEquals(pair, m.mask("Mehmet Yılmaz"), "another person, another token");
        assertTrue(m.mask("onaylayan: Mehmet Kaya, tarih").matches("onaylayan: " + NAME + ", tarih"));
    }

    @Test
    void aLoneGivenNameIsMaskedOnlyInFreeText() {
        assertEquals("Mehmet", m.mask("Mehmet"), "an identifier field keeps a lone given name");
        String out = m.maskFreeText("Mehmet bugün aradı");
        assertTrue(out.matches(NAME + " bugün aradı"), out);
        assertTrue(m.maskFreeText("Ali ve Zeynep geldi").matches(NAME + " ve " + NAME + " geldi"));
        assertEquals("Yılmaz", m.mask("Yılmaz"), "a lone family name is not a person");
    }

    @Test
    void caseEndingsWithAndWithoutAnApostropheGoWithTheName() {
        String ayse = m.maskFreeText("Ayşe");
        for (String text : List.of("Ayşe'nin", "Ayşe’nin", "Ayşenin", "AYŞE'NİN", "ayse'ye", "Ayşeden")) {
            assertEquals(ayse + " raporu", m.maskFreeText(text + " raporu"), text);
        }
        String mehmet = m.maskFreeText("Mehmet");
        for (String text : List.of("Mehmet'e", "Mehmete", "Mehmet'ten", "Mehmetle", "Mehmetin")) {
            assertEquals("bunu " + mehmet, m.maskFreeText("bunu " + text), text);
        }
        String pair = m.mask("Ayşe Yılmaz");
        assertEquals(pair + " onayı", m.mask("Ayşe Yılmaz'ın onayı"));
        assertEquals(pair + " onayı", m.mask("Ayşe Yılmazın onayı"));
    }

    @Test
    void turkishLettersFoldAcrossEveryISpellingAndUnicodeForm() {
        String ibrahim = m.maskFreeText("İbrahim");
        assertTrue(ibrahim.matches(NAME), ibrahim);
        for (String spelling : List.of("IBRAHIM", "İBRAHİM", "ibrahim", "Ibrahim", "ıbrahım")) {
            assertEquals(ibrahim, m.maskFreeText(spelling), spelling);
        }
        String composed = "Gülşen Öztürk";
        String decomposed = Normalizer.normalize(composed, Normalizer.Form.NFD);
        assertNotEquals(composed, decomposed);
        assertEquals(m.mask(composed), m.mask(decomposed));
        assertTrue(m.mask(decomposed).matches(NAME), "no combining mark is left behind");
    }

    @Test
    void wordsThatAreAlsoNamesAreNotMaskedAlone() {
        // The allow list: deniz (sea), umut (hope), metin (text), kaya (rock), özel (private), yazıcı (printer), can.
        for (String text : List.of(
            "Deniz kenarında umut var; metin kaya gibi sağlam",
            "Özel yazıcı ayarı bozuk, Metin alanı boş",
            "Can the mine tan in May?",
            "Osmanlı arşivi ayda bir taranır",
            "Barış ve Umut")) {
            assertEquals(text, m.maskFreeText(text), text);
        }
        assertTrue(m.maskFreeText("Deniz Kaya geldi").matches(NAME + " geldi"), "capitalised, they are a person");
        assertEquals("deniz kaya", m.maskFreeText("deniz kaya"), "lower case, they are words");
        assertTrue(m.maskFreeText("Ali can sıkıntısı").startsWith("NAME-"), "next to a plain name, a word counts");
    }

    @Test
    void namesAreWholeWordsAndPseudonymsAreNeverReMasked() {
        for (String text : List.of("Alibaba", "Mehmetçikler", "ali123", "x_Selin9")) {
            assertEquals(text, m.maskFreeText(text), text);
        }
        // Hex bodies of tokens this masker writes can spell a name (ece, eda, ada): they stay as written.
        for (String token : List.of("USR-ece0123456", "TEL-eda1", "NUM-ada1", "EST-ece", "HST-eda")) {
            assertEquals("by " + token, m.maskFreeText("by " + token), token);
        }
    }

    // ---- layer 5: free-text heuristics -------------------------------------------------------------------------------

    @Test
    void identifiersGluedToLettersAreMasked() {
        String tckn = Synthetic.tckn(11);
        String glued = m.mask("musteri" + tckn + "x");
        assertFalse(glued.contains(tckn), glued);
        assertEquals(m.mask("musteri " + tckn + " x").replace(" ", ""), glued.replace(" ", ""),
            "the same TCKN token glued or not");
        String phone = "05" + "32" + "1234567";
        assertEquals(m.mask(phone), m.mask("tel" + phone).substring(3), "one number, one TEL token");
        String run = "7" + "34" + "1029";
        String ref = m.maskFreeText("ref" + run + "a");
        assertTrue(ref.matches("refNUM-[0-9a-f]{4}a"), ref);
        assertEquals("ref" + run + "a", m.mask("ref" + run + "a"), "identifier fields keep a plain number");
        assertEquals("build12345x", m.maskFreeText("build12345x"), "five digits are not a run");
        assertEquals("count 123456 rows", m.maskFreeText("count 123456 rows"), "a free-standing number stays");
    }

    @Test
    void accountsHostsAddressesAndIbanShapesAreMaskedByClass() {
        Pseudonymiser p = new Pseudonymiser(PseudonymiserTest.keys(1));
        String account = "SYNTHETIC\\synthetic.user.001";
        assertEquals("from " + p.user(account) + " today", m.maskFreeText("from " + account + " today"),
            "the user column's pseudonym");
        String hosts = m.maskFreeText("see https://chat.vendor.example/path and node7.example.com.");
        assertTrue(hosts.matches("see https://HST-[0-9a-f]{4}/path and HST-[0-9a-f]{4}\\."), hosts);
        String keep = "report.pdf, v1.2.3, 3.5 GB, e.g. i.e. 12:30:45, rwmask-v2";
        assertEquals(keep, m.maskFreeText(keep));
        String address = m.maskFreeText("host192.0.2.10 down");
        assertFalse(address.contains("192.0.2.10"), address);
        assertEquals(m.mask("192.0.2.10"), address.substring(4, address.indexOf(' ')));
        assertEquals("1.192.0.2.10", m.maskFreeText("1.192.0.2.10"), "inside a longer dotted number");

        String foreign = iban("DE", 18, 3);
        String spaced = spaced(foreign);
        String a = m.maskFreeText("iban " + spaced + " ok");
        assertTrue(a.matches("iban IBAN-[0-9a-f]{4} ok"), a);
        assertEquals(a, m.maskFreeText("iban " + foreign + " ok"), "compact or spaced, one token");
        String tr = Synthetic.iban(5);
        assertEquals(m.mask(tr), m.maskFreeText(spaced(tr)), "a valid TR IBAN reads as the detector's token");
        String badCheck = "TR00" + tr.substring(4);
        assertTrue(m.maskFreeText(spaced(badCheck)).matches("IBAN-[0-9a-f]{4}"), "a TR shape with a bad check");
    }

    @Test
    void estateTermsAreMaskedInFreeTextToo() {
        String out = m.maskFreeText("Ayşe synthetic-estate sunucusunu yeniden başlattı");
        assertTrue(out.matches(NAME + " EST-[0-9a-f]{4} sunucusunu yeniden başlattı"), out);
    }

    // ---- stability, corpus, performance ------------------------------------------------------------------------------

    @Test
    void pseudonymsAreStablePerEstateAndDifferAcrossKeys() {
        String text = corpus(new Random(7), 40);
        assertEquals(m.maskFreeText(text), m.maskFreeText(text));
        TextMasker other = new Masking(PseudonymiserTest.keys(2), new Pseudonymiser(PseudonymiserTest.keys(2)))
            .masker();
        assertNotEquals(m.maskFreeText("Ayşe Yılmaz"), other.maskFreeText("Ayşe Yılmaz"));
    }

    @Test
    void aSyntheticCorpusLeavesNoNameOrIdentifierBehind() {
        Random r = new Random(17);
        String text = corpus(r, 300);
        String out = m.maskFreeText(text);
        for (String leak : List.of("Ayşe", "Mehmet", "Yılmaz", "Zeynep", "Kaya'nın", "05" + "32", "192.0.2.")) {
            assertFalse(out.contains(leak), leak);
        }
        assertFalse(out.matches("(?s).*\\d{6}.*"), "no run of six digits is left");
    }

    @Test
    void sixtyFourKilobytesAreMaskedQuicklyAndCompletely() {
        Random r = new Random(64);
        StringBuilder text = new StringBuilder(65_536);
        while (text.length() < 65_536) {
            text.append(corpus(r, 1)).append(' ').append(Synthetic.tckn(r.nextInt(1_000_000))).append(' ');
        }
        String input = text.substring(0, 65_536);
        m.maskFreeText(input);
        long start = System.nanoTime();
        String out = m.maskFreeText(input);
        long millis = (System.nanoTime() - start) / 1_000_000;
        assertTrue(millis < 2_000, "64 KB took " + millis + " ms");
        assertFalse(out.matches("(?s).*\\d{11}.*"), "every TCKN is masked, past the detectors' finding limit too");
        assertFalse(out.contains("Ayşe"));
    }

    @Test
    void aPieceWithMoreFindingsThanTheLimitIsWithheldNotHalfMasked() {
        StringBuilder text = new StringBuilder();
        for (int i = 0; i < 1_100; i++) {
            text.append(Synthetic.tckn(i)).append(',');
        }
        assertEquals(TextMasker.OVER_LIMIT, m.mask(text.toString()));
    }

    /** Sentences of an incident note: names with endings, glued and spaced identifiers, hosts, addresses. */
    private static String corpus(Random r, int sentences) {
        List<String> given = List.of("Ayşe", "Mehmet", "Zeynep", "Ali", "Elif", "Mustafa", "Gülşen", "İbrahim");
        List<String> family = List.of("Yılmaz", "Kaya", "Demir", "Öztürk", "Şahin", "Çelik");
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < sentences; i++) {
            String g = given.get(r.nextInt(given.size()));
            String f = family.get(r.nextInt(family.size()));
            s.append(switch (r.nextInt(6)) {
                case 0 -> g + " " + f + "'nın talebi üzerine kural güncellendi. ";
                case 1 -> g + "'e iletildi, tel" + "05" + "32" + String.format("%07d", r.nextInt(10_000_000)) + ". ";
                case 2 -> "müşteri" + Synthetic.tckn(r.nextLong()) + " için " + g + " " + f + " aradı. ";
                case 3 -> "node" + r.nextInt(99) + ".example.com üzerinde 192.0.2." + r.nextInt(255) + " görüldü. ";
                case 4 -> f.toUpperCase(java.util.Locale.forLanguageTag("tr")) + " "
                    + g.toUpperCase(java.util.Locale.forLanguageTag("tr")) + " onayladı. ";
                default -> "Ayşe ile " + g + " Kaya'nın notu okundu. ";
            });
        }
        return s.toString();
    }

    /** A valid IBAN of another country with {@code digits} BBAN digits, built at runtime. */
    private static String iban(String country, int digits, long seed) {
        Random r = new Random(seed);
        StringBuilder bban = new StringBuilder();
        for (int i = 0; i < digits; i++) {
            bban.append(r.nextInt(10));
        }
        for (int check = 2; check < 99; check++) {
            String candidate = country + (check < 10 ? "0" : "") + check + bban;
            if (TextMasker.mod97(candidate)) {
                return candidate;
            }
        }
        throw new IllegalStateException("no check digits");
    }

    private static String spaced(String compact) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < compact.length(); i += 4) {
            out.append(i == 0 ? "" : " ").append(compact, i, Math.min(i + 4, compact.length()));
        }
        return out.toString();
    }
}
