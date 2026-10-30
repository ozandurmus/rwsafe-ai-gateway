package io.rwsafe.control.privacy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.control.support.Synthetic;
import java.text.Normalizer;
import java.util.List;
import java.util.Locale;
import java.util.Random;
import org.junit.jupiter.api.Test;

/**
 * Masking layers 4 (Turkish names) and 5 (free-text heuristics) of {@code rwmask-v1-slice2}, with every escaping form and
 * false positive of the PR 26 second review (D-01 to D-08) as a case. Synthetic values only, built at runtime: generic
 * dictionary names, identifiers with valid checksums generated here (AGENTS.md 4.5), documentation addresses and example
 * host names.
 */
class TextMaskerFreeTextTest {

    /** MASKING_AND_PRIVACY B2 layer 4: {@code NAME-<WORD>}, four consonant-vowel syllables. */
    private static final String NAME = "NAME-[A-Z]{8}";
    private static final Locale TR = Locale.forLanguageTag("tr");

    private final Pseudonymiser p = new Pseudonymiser(PseudonymiserTest.keys(1));
    private final TextMasker m = new Masking(PseudonymiserTest.keys(1), p).masker();

    @Test
    void theRuleSetIsSliceTwoUntilEveryFrozenLayerExists() {
        assertEquals("rwmask-v1-slice2", TextMasker.RULE_SET);
    }

    // ---- D-01: names that are also everyday words ----------------------------------------------------------------

    @Test
    void anEverydayWordInLowerCaseAloneStaysAWord() {
        for (String text : List.of(
            "deniz kenarında umut var; metin kaya gibi sağlam",
            "özel yazıcı ayarı bozuk, metin alanı boş",
            "you can mine tan ore",
            "osmanlı arşivi ayda bir taranır",
            "yalçın kaya", "aydın ufuk", "sona eren süre",
            "arası, arasın, arasa", "ferdi kullanım tekin değil", "mert ve utku sözcükleri", "ışıl ışıl", "ayla arda")) {
            assertEquals(text, m.maskFreeText(text), text);
        }
    }

    @Test
    void anEverydayWordInANamePositionIsAName() {
        assertTrue(m.maskFreeText("Deniz bugün geldi").matches(NAME + " bugün geldi"), "capitalised");
        assertTrue(m.maskFreeText("Sayın deniz kaya geldi").matches("Sayın " + NAME + " geldi"), "after a title");
        assertTrue(m.maskFreeText("Dr. kaya aradı").matches("Dr\\. " + NAME + " aradı"), "after a title");
        assertTrue(m.maskFreeText("deniz Bey aradı").matches(NAME + " Bey aradı"), "before a title");
        assertTrue(m.maskFreeText("Deniz Kaya geldi").matches(NAME + " geldi"), "next to another name word");
        for (String joined : List.of("deniz.kaya", "metin_kaya", "yilmaz-kemal", "metin.kaya")) {
            assertTrue(m.mask(joined).matches(NAME), "joined like an account, in a field: " + joined);
            assertTrue(m.maskFreeText(joined).matches(NAME), "and in free text: " + joined);
        }
    }

    @Test
    void givenNamesThatAreNotEverydayWordsAndLoneFamilyNamesAreMaskedInFreeText() {
        for (String name : List.of("Kemal", "Fatih", "Recep", "Ramazan", "Muharrem", "Kadir", "Kamil", "Kerem", "Ozan",
            "Hülya", "Seda", "Tuba", "Bora", "Levent", "Mete", "Tamer", "kemal", "ozan")) {
            assertTrue(m.maskFreeText(name + " aradı").matches(NAME + " aradı"), name);
        }
        for (String family : List.of("Öztürk", "Özdemir", "Eroğlu", "Şahinoğlu", "Kılıçarslan", "Karabulut",
            "Taşdemir", "öztürk")) {
            assertTrue(m.maskFreeText("aranan " + family).matches("aranan " + NAME), family);
            assertEquals("aranan " + family, m.mask("aranan " + family), "a field keeps a lone family name");
        }
    }

    // ---- D-05: false positives --------------------------------------------------------------------------------------

    /**
     * An everyday word next to a name in another case: when the two make a given name and a family name, they are taken
     * as one person (privacy before readability, PR 26 confirmation review N-01: "Mehmet yazıcı" may be a person); a
     * word that is only an everyday given name stays a word next to another given name.
     */
    @Test
    void anEverydayFamilyNameNextToAGivenNameIsTakenWithItOtherWordsStay() {
        for (String[] c : new String[][] {
            {"Ayşe metin gönderdi", " gönderdi"},
            {"Mehmet yazıcı ekledi", " ekledi"},
            {"Zeynep özel kural yazdı", " kural yazdı"},
            {"Ayşe durmuş", ""},
            {"Ali uçar", ""},
            {"Mehmet gezer", ""},
            {"Ali can sıkıntısı", " sıkıntısı"}}) {
            String out = m.maskFreeText(c[0]);
            assertTrue(out.matches(NAME + java.util.regex.Pattern.quote(c[1])), out);
        }
        for (String[] c : new String[][] {
            {"Mehmet umut ediyor", " umut ediyor"},
            {"Zeynep barış istedi", " barış istedi"}}) {
            String out = m.maskFreeText(c[0]);
            assertTrue(out.matches(NAME + java.util.regex.Pattern.quote(c[1])), out);
            assertEquals(m.maskFreeText(c[0].substring(0, c[0].indexOf(' '))), out.substring(0, 13),
                "the person's token is unchanged by the next word");
        }
    }

    // ---- PR 26 confirmation review N-01: the four escaping forms and initials ----------------------------------------

    @Test
    void capitalisedNamesWithEndingsAndInCapitalsAreNamesAlone() {
        for (String word : List.of("Denize", "Onurun", "Yasemine", "Yılmaza", "Alpe", "DENİZ", "ONUR", "YILMAZ",
            "DENİZ'İN", "YILMAZ'IN", "Deniz", "Kaya")) {
            assertTrue(m.maskFreeText("dün " + word + " aradı").matches("dün " + NAME + " aradı"), word);
        }
        for (String word : List.of("denize", "onurun", "deniz", "kaya", "umut")) {
            assertEquals("dün " + word + " aradı", m.maskFreeText("dün " + word + " aradı"), "lower case alone: " + word);
        }
        assertTrue(m.mask("Ayşe Yılmaza").matches(NAME), "a field: a capitalised suffixed family name joins");
        assertTrue(m.mask("DENİZ KAYA'NIN").matches(NAME), "a field: capitals with an apostrophised ending");
    }

    @Test
    void lowerCaseThreeWordNamesAndNamesBeforeATitleAreOnePerson() {
        for (String text : List.of("ayşe pınar yılmaz", "mehmet can kaya")) {
            assertTrue(m.mask(text).matches(NAME), "a field: " + text + " -> " + m.mask(text));
            assertTrue(m.maskFreeText("not " + text + " yazdı").matches("not " + NAME + " yazdı"), text);
        }
        assertTrue(m.mask("deniz kaya Bey").matches(NAME + " Bey"), m.mask("deniz kaya Bey"));
        assertTrue(m.maskFreeText("not deniz kaya Bey yazdı").matches("not " + NAME + " Bey yazdı"));
    }

    @Test
    void mixedCasePairsAreOnePerson() {
        for (String text : List.of("ayşe Yılmaz", "Ayşe yılmaz", "ayşe KAYA")) {
            assertTrue(m.mask(text).matches(NAME), "a field: " + text + " -> " + m.mask(text));
            assertTrue(m.maskFreeText(text).matches(NAME), text);
        }
        assertEquals(m.mask("Ayşe Yılmaz"), m.mask("ayşe Yılmaz"), "one person, one token");
    }

    @Test
    void inflectedTitlesAfterANameMakeItAName() {
        for (String text : List.of("deniz Beye", "deniz Hanıma", "deniz Beyin", "kaya Hocaya")) {
            String title = text.substring(text.indexOf(' '));
            assertTrue(m.maskFreeText(text + " yazdım").matches(NAME + title + " yazdım"), text);
        }
    }

    @Test
    void initialsJoinOnlyNamesAndGlueToFamilyNamesInAnyCase() {
        assertTrue(m.maskFreeText("A. metin alanı boş").matches("A\\. metin alanı boş"),
            "an initial before a lower-case everyday word");
        assertEquals("T.C. özel kural", m.maskFreeText("T.C. özel kural"));
        for (String text : List.of("a.yilmaz", "m_kaya", "A.Yılmaz", "e-ozturk")) {
            assertTrue(m.mask(text).matches(NAME), "a field: " + text + " -> " + m.mask(text));
        }
    }

    // ---- PR 26 confirmation review N-02 to N-04 ----------------------------------------------------------------------

    @Test
    void onlyAnExactDateIsExemptAndEveryParenthesisedMobileFormIsOneToken() {
        for (String text : List.of("2026-10-31-123", "31.10.2026.123", "1-2026-10-31", "2026-10-31 4567", "2026.10.31_12")) {
            assertTrue(m.mask("no " + text).matches("no NUM-[0-9a-f]{4}"), text + " -> " + m.mask("no " + text));
        }
        assertEquals("on 2026-10-31. and 31.10.2026 tarihinde", m.maskFreeText("on 2026-10-31. and 31.10.2026 tarihinde"));
        String mobile = "05" + "32" + "1234567";
        String token = m.mask(mobile);
        String rest = " " + mobile.substring(4, 7) + " " + mobile.substring(7, 9) + " " + mobile.substring(9);
        String op = "(" + mobile.substring(1, 4) + ")";
        assertEquals("ara " + token, m.mask("ara 9" + "0" + op + rest), "90(5XX)");
        assertEquals("ara " + token, m.mask("ara " + op + rest), "no prefix: the space before stays");
    }

    @Test
    void theMaskersOwnTokensAreNotIdentifierShapes() {
        String masked = m.maskFreeText("moved off 192.0.2.10 by synthetic.user@example.invalid");
        assertFalse(IdentifierCheck.identifierShape(TextMasker.withoutTokens(masked)), masked);
        assertEquals("a   b", TextMasker.withoutTokens("a " + m.mask("192.0.2.10") + " b"));
    }

    @Test
    void estateTermsMatchWhateverTheSeparator() {
        TextMasker estate = new TextMasker(p, List.of("şube-merkez"), NameDictionary.standard());
        String a = estate.mask("x SUBE_MERKEZ y");
        assertTrue(a.matches("x EST-[0-9a-f]{4} y"), a);
        for (String form : List.of("x sube.merkez y", "x sube:merkez y", "x Şube Merkez y", "x şube - merkez y")) {
            assertEquals(a, estate.mask(form), form);
            assertEquals(a, estate.maskFreeText(form), form);
        }
        assertEquals("x subemerkez y", estate.mask("x subemerkez y"));
    }

    @Test
    void urlUserinfoIsMaskedAndDetectorsSeeDotlessI() {
        String withUser = m.maskFreeText("open https://" + "synthetic-person" + "@intranet:8443/x");
        assertTrue(withUser.matches("open https://USR-[0-9a-f]{10}@HST-[0-9a-f]{4}:8443/x"), withUser);
        String withPassword = m.maskFreeText("https://" + "synthetic-person" + ":" + "synthetic-value" + "@"
            + "host.example/x");
        assertTrue(withPassword.matches("https://USR-[0-9a-f]{10}:\\[REDACTED:SECRET\\]@HST-[0-9a-f]{4}/x"),
            withPassword);
        String dotless = Synthetic.githubToken().replace('i', 'ı');
        assertFalse(m.maskFreeText("key " + dotless).contains(dotless), "a secret written with a dotless i");
    }

    @Test
    void ordinaryWordsAfterKeywordsStayAndIdentifiersAfterThemDoNot() {
        for (String text : List.of("This is captured user content", "user session expired", "server error",
            "customer data", "login failed", "kullanıcı girişi", "sunucu hatası", "müşteri aradı", "hesap kapandı",
            "kimlik doğrulama", "iban kontrolu")) {
            assertEquals(text, m.maskFreeText(text), text);
        }
        assertEquals("user " + p.user("jdoe") + " logged in", m.maskFreeText("user jdoe logged in"));
        assertTrue(m.maskFreeText("host srvdb unreachable").matches("host HST-[0-9a-f]{4} unreachable"));
        assertTrue(m.maskFreeText("müşteri acmeltd aradı").matches("müşteri CUST-[0-9a-f]{4} aradı"));
        assertTrue(m.maskFreeText("kimlik ab12cd").matches("kimlik TCKN-[0-9a-f]{4}"));
    }

    // ---- D-02: endings without an apostrophe, short stems, compound endings, softened consonants ----------------------

    @Test
    void shortNamesWithEndingsCountNextToAnotherNameOrCapitalised() {
        for (String text : List.of("Ayşe Koça", "Mehmet Şene", "Ali Taşa", "Ayşe Özün", "Mehmet Erin", "Zeynep Ayın")) {
            assertTrue(m.mask(text).matches(NAME), "a field: " + text);
            assertTrue(m.maskFreeText(text + " yazdı").matches(NAME + " yazdı"), text);
        }
        assertTrue(m.maskFreeText("Ceme sordum").matches(NAME + " sordum"), "capitalised alone");
        assertEquals(m.maskFreeText("Cem'e sordum"), m.maskFreeText("Ceme sordum"), "the same person as Cem'e");
        assertEquals("ceme sordum", m.maskFreeText("ceme sordum"), "a lower-case short stem alone stays");
    }

    @Test
    void theLongestNameStemWinsAndMatchesTheApostrophisedForm() {
        for (String[] c : new String[][] {
            {"Gülaya", "Gülay'a"}, {"Gülayla", "Gülay'la"}, {"Nurayı", "Nuray'ı"}, {"Gökaya", "Gökay'a"},
            {"Aysunun", "Aysun'un"}, {"Aysundan", "Aysun'dan"}, {"Berkaya", "Berkay'a"}, {"Aysele", "Aysel'e"},
            {"Ahmetine", "Ahmet'ine"}, {"Ahmetinden", "Ahmet'inden"}, {"Ahmetiyle", "Ahmet'iyle"},
            {"Ayşeninki", "Ayşe'ninki"}, {"Mehmede", "Mehmet'e"}, {"Murada", "Murat'a"}, {"Recebe", "Recep'e"},
            {"Burağa", "Burak'a"}}) {
            String a = m.maskFreeText(c[0] + " yazdım");
            assertTrue(a.matches(NAME + " yazdım"), c[0]);
            assertEquals(m.maskFreeText(c[1] + " yazdım"), a, c[0]);
        }
    }

    // ---- D-03: initials, a suffixed first word, family name first, double names, more apostrophes -------------------------

    @Test
    void initialsSuffixedFirstWordsFamilyFirstAndDoubleNamesAreOnePerson() {
        for (String text : List.of("A. Yılmaz", "M. Kaya", "Ayşe N. Yılmaz", "M.Kaya", "Ayşe Yılmaz-Kocaoğlu",
            "Ayşe Kocaoğlu-Yılmaz", "Yılmaz'ın Ayşe", "YILMAZ Ayşe")) {
            assertTrue(m.mask(text).matches(NAME), "a field: " + text + " -> " + m.mask(text));
            assertTrue(m.maskFreeText("not: " + text + " aradı").matches("not: " + NAME + " aradı"), text);
        }
        String pair = m.mask("Ayşe Yılmaz");
        assertEquals(pair, m.mask("YILMAZ Ayşe"), "one person, one token, in either order");
        assertEquals(pair, m.mask("Yılmaz Ayşe"));
        assertEquals(pair, m.mask("ayse.yilmaz"));
        String ayse = m.maskFreeText("Ayşe'nin");
        for (String apostrophe : List.of("`", "\u00b4", "\u2019", "\u02bc")) {
            assertEquals(ayse, m.maskFreeText("Ayşe" + apostrophe + "nin"), apostrophe);
        }
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
    void namesAreWholeWordsAndTokensAreNeverMaskedAgain() {
        for (String text : List.of("Alibaba", "Mehmetçikler", "ali123")) {
            assertEquals(text, m.maskFreeText(text), text);
        }
        for (String token : List.of("USR-ece0123456", "TEL-eda1", "NUM-ada1", "EST-ece1", "HST-eda2", "NAME-ECEBELOS",
            "TCKN-1234", "IBAN-TR-ab12")) {
            assertEquals("by " + token + " now", m.maskFreeText("by " + token + " now"), token);
        }
    }

    // ---- D-04: phone numbers in every form, grouped and glued numbers, cards, IBANs ------------------------------------

    @Test
    void aMobileNumberIsOneTokenInEveryWrittenForm() {
        String mobile = "05" + "32" + "1234567";
        String token = m.mask(mobile);
        assertTrue(token.matches("TEL-[0-9a-f]{4}"), token);
        String a = mobile.substring(0, 4);
        String b = mobile.substring(4, 7);
        String c = mobile.substring(7, 9);
        String d = mobile.substring(9);
        String op = mobile.substring(1, 4);
        for (String form : List.of(a + "-" + b + "-" + c + "-" + d, a + "." + b + "." + c + "." + d,
            a + "_" + b + "_" + c + "_" + d, a + " " + b + " " + c + " " + d, "0(" + op + ") " + b + " " + c + " " + d,
            "+90 (" + op + ") " + b + " " + c + " " + d, "+90 " + op + " " + b + " " + c + " " + d,
            "9" + mobile, "009" + mobile, mobile.substring(1))) {
            assertEquals("ara " + token + " lütfen", m.mask("ara " + form + " lütfen"), form);
            assertEquals("ara " + token + " lütfen", m.maskFreeText("ara " + form + " lütfen"), form);
        }
        assertEquals("tel_" + token, m.mask("tel_" + mobile), "underscore-glued");
        assertEquals("tel" + token, m.mask("tel" + mobile), "letter-glued");
    }

    @Test
    void groupedAndGluedNumbersCardsAndIbansAreMaskedByClassOnEveryPath() {
        String tckn = Synthetic.tckn(11);
        String tcknToken = m.mask(tckn);
        assertTrue(tcknToken.matches("TCKN-[0-9a-f]{4}"));
        for (String form : List.of(tckn.substring(0, 5) + "-" + tckn.substring(5, 10) + "-" + tckn.substring(10),
            tckn.substring(0, 3) + " " + tckn.substring(3, 6) + " " + tckn.substring(6),
            tckn.substring(0, 3) + "." + tckn.substring(3)) ) {
            assertEquals(tcknToken, m.mask(form), form);
        }
        assertEquals("musteri" + tcknToken + "x", m.mask("musteri" + tckn + "x"), "glued to letters");
        String card = Synthetic.card(7);
        String cardToken = m.mask(card);
        assertTrue(cardToken.matches("CARD-[0-9a-f]{4}"), cardToken);
        assertEquals("kart" + cardToken, m.mask("kart" + card), "letter-glued card");
        assertEquals("kart" + cardToken, m.maskFreeText("kart" + card), "letter-glued card in free text");
        assertEquals(cardToken, m.mask(String.join("-", card.substring(0, 4), card.substring(4, 8),
            card.substring(8, 12), card.substring(12))), "dashed card");
        for (String number : List.of("ref-" + "123456", "ref_" + "123456", "ref" + "1234567")) {
            assertTrue(m.mask(number).matches("ref[-_]?NUM-[0-9a-f]{4}"), number);
        }
        assertTrue(m.maskFreeText("hesap 12345678 kapandı").matches("hesap NUM-[0-9a-f]{4} kapandı"), "Q-2");
        assertEquals("build 12345 and 2026-10-31 and 31.10.2026", m.maskFreeText(
            "build 12345 and 2026-10-31 and 31.10.2026"), "five digits and calendar dates are not numbers");
        assertEquals("build12345x", m.mask("build12345x"), "nor five digits glued, in a field");

        String foreign = iban("GB", "SYNT", 14, 3);
        String foreignToken = m.mask(foreign);
        assertTrue(foreignToken.matches("IBAN-[0-9a-f]{4}"), foreignToken);
        assertEquals(foreignToken, m.mask(spaced(foreign)), "letters in the account part, spaced");
        assertEquals("iban " + foreignToken, m.maskFreeText("iban " + spaced(foreign)));
        String tr = Synthetic.iban(5);
        assertEquals("odeme" + m.mask(tr) + "tl", m.mask("odeme" + tr + "tl"), "glued on both sides");
        String badCheck = "TR00" + tr.substring(4);
        assertTrue(m.mask(spaced(badCheck)).matches("IBAN-[0-9a-f]{4}"), "a TR shape with a bad check");
    }

    /** Every shape the shared write-side check refuses is masked on read, on both paths (PR 26 review D-04). */
    @Test
    void nothingIdentifierCheckRefusesSurvivesTheMasker() {
        String tckn = Synthetic.tckn(21);
        String mobile = "05" + tckn.substring(2);
        List<String> shapes = List.of(
            "ref" + tckn,
            tckn.substring(0, 5) + "-" + tckn.substring(5, 10) + "-" + tckn.substring(10),
            tckn.substring(0, 3) + " " + tckn.substring(3, 6) + " " + tckn.substring(6),
            mobile.substring(0, 4) + "-" + mobile.substring(4, 7) + "-" + mobile.substring(7, 9) + "-" + mobile.substring(9),
            "TEL_" + mobile.substring(0, 4) + "_" + mobile.substring(4, 7) + "_" + mobile.substring(7, 9) + "_"
                + mobile.substring(9),
            mobile.substring(0, 4) + "." + mobile.substring(4),
            "odeme" + Synthetic.iban(22),
            Synthetic.card(23),
            Synthetic.githubToken().toUpperCase(Locale.ROOT),
            Synthetic.githubToken(),
            "ref-" + "1234567", "acct 1 2 3 4 5 6 7");
        for (String shape : shapes) {
            assertTrue(IdentifierCheck.identifierShape(shape), "the check refuses form " + shapes.indexOf(shape));
            assertFalse(IdentifierCheck.identifierShape(m.mask(shape)), "mask() left form " + shapes.indexOf(shape));
            assertFalse(IdentifierCheck.identifierShape(m.maskFreeText(shape)), "maskFreeText() left form "
                + shapes.indexOf(shape));
        }
    }

    // ---- D-06: one pipeline, folded estate, hosts, mapped addresses ---------------------------------------------------

    @Test
    void theSameValueReadsTheSameOnEveryPath() {
        String mobile = "05" + "32" + "7654321";
        for (String value : List.of(Synthetic.tckn(3), mobile.substring(0, 4) + "-" + mobile.substring(4),
            Synthetic.card(4), iban("GB", "SYNT", 14, 5), "Ayşe Yılmaz", "node7.example.com",
            "synthetic.user@example.invalid", "SYNTHETIC\\synthetic.user.001", "ayse.nur.yilmaz",
            "synthetic-estate.example.com")) {
            assertEquals(m.mask(value), m.maskFreeText(value), value);
        }
        assertTrue(m.maskFreeText("ayse.nur.yilmaz").matches(NAME), "a dotted three-word name is a name, not a host");
    }

    @Test
    void estateTermsMatchFoldedOnPartEdges() {
        TextMasker estate = new TextMasker(p, List.of("şube-merkez", "\u0130STANBUL-DC".toLowerCase(Locale.ROOT)),
            NameDictionary.standard());
        String a = estate.mask("SUBE-MERKEZ.core");
        assertTrue(a.matches("EST-[0-9a-f]{4}\\.core"), a);
        assertEquals(a, estate.mask("Şube-Merkez.core"), "Turkish letters and case fold");
        assertTrue(estate.mask("istanbul-dc").matches("EST-[0-9a-f]{4}"), "a dotted capital I in the dictionary");
        assertEquals(estate.mask("istanbul-dc"), estate.mask("İSTANBUL-DC"));
        assertEquals("subemerkez", estate.mask("subemerkez"), "only on part edges");
    }

    @Test
    void hostsUrlsAndAddressesAreMaskedButProductTermsStay() {
        assertTrue(m.maskFreeText("see https://chat.vendor.example/path and node7.example.com.")
            .matches("see https://HST-[0-9a-f]{4}/path and HST-[0-9a-f]{4}\\."));
        assertTrue(m.maskFreeText("open https://intranet:8443/x").matches("open https://HST-[0-9a-f]{4}:8443/x"),
            "a single-label URL host");
        assertTrue(m.maskFreeText("on srv_01.lan").matches("on HST-[0-9a-f]{4}"), "an underscore in a label");
        String keep = "policy.rule.draft, report.pdf, notes.md, v1.2.3, 3.5 GB, e.g. i.e. 12:30:45, rwmask-v1-slice2";
        assertEquals(keep, m.maskFreeText(keep));
        String mapped = String.join(":", "", "", "ffff", "192.0.2.1");
        assertEquals("from [REDACTED_IP] now", m.maskFreeText("from " + mapped + " now"), "IPv4-mapped IPv6");
        String vendor = "moved to api.vendor.example and chat.vendor.example, not node7.example.com";
        String allowed = m.maskFreeText(vendor, h -> h.equals("vendor.example") || h.endsWith(".vendor.example"));
        assertTrue(allowed.matches("moved to api.vendor.example and chat.vendor.example, not HST-[0-9a-f]{4}"),
            allowed);
        assertEquals("api.vendor.example", m.maskVendorHost("api.vendor.example"), "a registry vendor endpoint");
        String address = m.maskFreeText("host192.0.2.10 down");
        assertFalse(address.contains("192.0.2.10"), address);
        assertTrue(m.maskFreeText("1.192.0.2.10").matches("NUM-[0-9a-f]{4}"),
            "a longer dotted number is not an address but a grouped number (Q-2)");
    }

    // ---- D-08 and Q-1: layer 5 keywords, user paths, serials; whole-string withholding --------------------------------

    @Test
    void theWordAfterAKeywordIsMaskedUnlessItIsAnOrdinaryWord() {
        assertEquals("user " + p.user("jdoe") + " logged in", m.maskFreeText("user jdoe logged in"));
        assertEquals("kullanıcı: " + p.user("aliveli") + " girdi", m.maskFreeText("kullanıcı: aliveli girdi"));
        assertTrue(m.maskFreeText("host srvdb unreachable").matches("host HST-[0-9a-f]{4} unreachable"));
        assertTrue(m.maskFreeText("müşteri acmeltd aradı").matches("müşteri CUST-[0-9a-f]{4} aradı"));
        assertTrue(m.maskFreeText("from srv-01 to db-02").matches("from HST-[0-9a-f]{4} to HST-[0-9a-f]{4}"));
        for (String text : List.of("the exporter host name is not a plain lower-case name", "from the proxy to the "
            + "control plane", "hesap no yok", "user or password is wrong")) {
            assertEquals(text, m.maskFreeText(text), text);
        }
    }

    @Test
    void userDirectoriesAndSerialsAreMasked() {
        String user = p.user("synthetic-person");
        assertEquals("/Users/" + user + "/x.txt", m.maskFreeText("/Users/synthetic-person/x.txt"));
        assertEquals("/home/" + user, m.maskFreeText("/home/synthetic-person"));
        assertEquals("C:\\Users\\" + user + "\\Desktop", m.maskFreeText("C:\\Users\\synthetic-person\\Desktop"));
        assertTrue(m.maskFreeText("seri SN4F7K29QX arızalı").matches("seri SER-[0-9a-f]{4} arızalı"));
    }

    @Test
    void aPieceOverTheFindingLimitWithholdsTheWholeString() {
        StringBuilder text = new StringBuilder("A quiet sentence. ".repeat(600));
        for (int i = 0; i < 1_100; i++) {
            text.append(Synthetic.tckn(i)).append(',');
        }
        assertEquals(TextMasker.OVER_LIMIT, m.mask(text.toString()));
        assertEquals(TextMasker.OVER_LIMIT, m.maskFreeText(text.toString()));
    }

    @Test
    void nameWordsArePronounceableStableAndNeverANameThemselves() {
        java.util.Set<String> words = new java.util.HashSet<>();
        for (int i = 0; i < 2_000; i++) {
            String token = p.word("NAME", "synthetic person " + i, w -> false);
            assertTrue(token.matches("NAME-(?:[BDFGLMNPRSTVZ][AEO]){4}"), token);
            assertFalse(token.contains("GOT") || token.contains("MEME"), token);
            words.add(token);
        }
        assertTrue(words.size() >= 1_998, "words are spread: " + words.size());
        assertEquals(p.word("NAME", "ayse yilmaz", w -> false), p.word("NAME", "ayse yilmaz", w -> false));
        assertNotEquals(p.word("NAME", "ayse yilmaz", w -> false),
            new Pseudonymiser(PseudonymiserTest.keys(2)).word("NAME", "ayse yilmaz", w -> false));
        String fallback = p.word("NAME", "ayse yilmaz", w -> true);
        assertTrue(fallback.matches("NAME-[BCDFGHJKLMNPRSTVZ]{8}"), "every draw refused: consonants only, " + fallback);
        assertEquals(fallback, p.word("NAME", "ayse yilmaz", w -> true));
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
        String out = m.maskFreeText(corpus(new Random(17), 300));
        for (String leak : List.of("Ayşe", "Mehmet", "Yılmaz", "YILMAZ", "Zeynep", "Kaya", "05" + "32", "192.0.2.")) {
            assertFalse(out.contains(leak), leak);
        }
        assertFalse(out.matches("(?s).*\\d{6}.*"), "no run of six digits is left");
    }

    @Test
    void sixtyFourKilobytesAreMaskedQuicklyAndCompletely() {
        Random r = new Random(64);
        StringBuilder text = new StringBuilder(65_536);
        while (text.length() < 65_536) {
            text.append(corpus(r, 1)).append(' ').append(Synthetic.tckn(r.nextInt(1_000_000))).append(". ");
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
    void productSentencesStayReadable() {
        for (String text : List.of("PostgreSQL answers", "masked role can be served", "key missing: ingestion is refused",
            "Only a security administrator retires a platform row.",
            "A draft needs mode (monitor, enforce) and an upper-case reasonCode.",
            "version 12 issued 5 minutes ago, key id dev-signing", "data-plane metrics are not implemented yet",
            "The reason holds an identifier (an address, a number or a name the masking rules recognise)")) {
            assertEquals(text, m.maskFreeText(text), text);
        }
    }

    /** Sentences of an incident note: names with endings, glued and spaced identifiers, hosts, addresses. */
    private static String corpus(Random r, int sentences) {
        List<String> given = List.of("Ayşe", "Mehmet", "Zeynep", "Ali", "Elif", "Mustafa", "Gülşen", "İbrahim");
        List<String> family = List.of("Yılmaz", "Kaya", "Demir", "Öztürk", "Şahin", "Çelik");
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < sentences; i++) {
            String g = given.get(r.nextInt(given.size()));
            String f = family.get(r.nextInt(family.size()));
            s.append(switch (r.nextInt(7)) {
                case 0 -> g + " " + f + "'nın talebi üzerine kural güncellendi. ";
                case 1 -> g + "'e iletildi, tel" + "05" + "32" + String.format("%07d", r.nextInt(10_000_000)) + ". ";
                case 2 -> "müşteri" + Synthetic.tckn(r.nextLong()) + " için " + g + " " + f + " aradı. ";
                case 3 -> "node" + r.nextInt(99) + ".example.com üzerinde 192.0.2." + r.nextInt(255) + " görüldü. ";
                case 4 -> f.toUpperCase(TR) + " " + g.toUpperCase(TR) + " onayladı. ";
                case 5 -> g.charAt(0) + ". " + f + " ve " + g + " " + f + "-Kocaoğlu toplantıda. ";
                default -> "Ayşe ile " + g + " Kaya'nın notu okundu. ";
            });
        }
        return s.toString();
    }

    /** A valid IBAN of {@code country} with a letter bank code and {@code digits} account digits, built at runtime. */
    private static String iban(String country, String bank, int digits, long seed) {
        Random r = new Random(seed);
        StringBuilder bban = new StringBuilder(bank);
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
