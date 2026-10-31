package io.rwsafe.platform.enduser;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** PRIV-2: the catalogue is complete, has no empty text and uses exactly the declared placeholders. */
class EndUserCatalogueTest {

    private static final EndUserCatalogue TR = EndUserCatalogue.turkish();

    @Test
    void everyDeclaredKeyIsPresentWithAText() {
        assertEquals(EndUserCatalogue.KEYS.keySet(), TR.keys());
        for (String key : EndUserCatalogue.KEYS.keySet()) {
            assertFalse(TR.text(key).isBlank(), key);
            assertEquals(TR.text(key), TR.text(key).strip(), key + " has surrounding whitespace");
        }
        assertEquals("tr-3", TR.version());
    }

    @Test
    void placeholdersAreConsistent() {
        Set<String> known = new HashSet<>(EndUserCatalogue.CONFIGURED);
        known.addAll(EndUserCatalogue.FILLED);
        Set<String> used = new HashSet<>();
        for (String key : TR.keys()) {
            assertEquals(EndUserCatalogue.KEYS.get(key), TR.placeholders(key), key);
            assertTrue(known.containsAll(TR.placeholders(key)), key + " uses an unknown placeholder");
            used.addAll(TR.placeholders(key));
        }
        assertEquals(known, used, "every known placeholder is used somewhere and nothing else is");
        // Values that must never be committed are placeholders, not text: no address, mail or link in the catalogue.
        for (String key : TR.keys()) {
            String t = TR.text(key);
            assertFalse(t.contains("@") || t.contains("http") || t.contains("www."), key + " holds a literal contact");
        }
    }

    @Test
    void theResourceHasNoDuplicateKeyAndNoOpenReviewMarker() throws Exception {
        List<String> lines = resourceLines();
        Set<String> seen = new HashSet<>();
        for (String line : lines) {
            // The PO approved the texts on 2026-10-31 (LR-1..LR-7); no open review marker remains.
            assertFalse(line.contains("LEGAL-REVIEW"), "open review marker: " + line);
            if (!line.isEmpty() && !line.startsWith("#")) {
                String key = line.substring(0, line.indexOf('='));
                assertTrue(seen.add(key), "duplicate key " + key);
                assertFalse(line.endsWith("\\"), key + " continues on the next line; keep one text per line");
            }
        }
    }

    @Test
    void textsAvoidJargonAndAbbreviations() {
        // Plain Turkish an employee understands (task brief): no product or security jargon, no abbreviation; the law is
        // named in full on first use and then "Kanun".
        List<String> banned = List.of("KVKK", "SIEM", "DLP", "proxy", "ICAP", "rwsafe", "vb.", "örn.", "vs.", "TCKN",
            "IBAN", "SSE", "API", "token", "redakte");
        // PR 22 review D-08: Turkish casing folds İ and I differently, so the text is folded both ways and compared with
        // the plain lower-case term (folding the term in Turkish too would turn "API" into "apı", which "yapın" holds).
        Locale turkish = Locale.forLanguageTag("tr");
        for (String key : TR.keys()) {
            String t = TR.text(key);
            for (String b : banned) {
                for (Locale l : List.of(Locale.ROOT, turkish)) {
                    assertFalse(t.toLowerCase(l).contains(b.toLowerCase(Locale.ROOT)),
                        key + " uses " + b + " (" + l + ")");
                }
            }
        }
        assertTrue(TR.text("notice.intro").contains("6698 sayılı Kişisel Verilerin Korunması Kanunu"));
        assertTrue(TR.text("notice.basis.text").contains("açık rızanıza dayanmaz"), "Q-32: consent is not a basis");
    }

    @Test
    void theWordingFollowsTheDecisionRecords() {
        // D-01 (Q-32, Q-35): the acknowledgement and the HR record are never an approval; "onay" appears only in the
        // sentence that says the record is not one.
        String ack = TR.text("notice.acknowledge.text");
        assertEquals(1, ack.split("onay", -1).length - 1, ack);
        assertTrue(ack.contains("bir onay ya da rıza değildir"));
        assertTrue(ack.contains("okuduğunuz kayda geçtiyse"));
        // PO legal review 2026-10-31 (LR-1, LR-2, LR-4): the full-text tier is not built, so no text names it; never
        // "unmodified" content either.
        for (String key : TR.keys()) {
            assertFalse(TR.text(key).contains("değiştirilmemiş"), key);
            assertFalse(TR.text(key).contains("tam met"), key + " names the full-text tier");
        }
        assertFalse(TR.keys().contains("notice.raw.text"));
        // LR-5: the objection sentence (content not stored on objection) is not offered.
        String rights = TR.text("notice.rights.text");
        assertFalse(rights.contains("İtiraz etmeniz"), rights);
        assertTrue(rights.endsWith("{{dpo_contact}} adresine başvurabilirsiniz."), rights);
        // D-04 (PC-5, SR-DLP-1): the no-exception sentence names all four fail-closed categories.
        String noException = TR.text("block.class.noexception");
        for (String category : List.of("müşteri bilgileri", "gizli bilgiler", "özel nitelikli kişisel veriler",
            "kurum içi kimlik bilgileri")) {
            assertTrue(noException.contains(category), category);
        }
    }

    @Test
    void anIncompleteOrWrongCatalogueIsRefused() {
        Map<String, String> good = new LinkedHashMap<>();
        for (String key : TR.keys()) {
            good.put(key, TR.text(key));
        }
        EndUserCatalogue.of(good);

        Map<String, String> missing = new LinkedHashMap<>(good);
        missing.remove("block.class.body");
        assertTrue(refusal(missing).contains("block.class.body: missing"));

        Map<String, String> empty = new LinkedHashMap<>(good);
        empty.put("coaching.body", "  ");
        assertTrue(refusal(empty).contains("coaching.body: empty"));

        Map<String, String> extra = new LinkedHashMap<>(good);
        extra.put("block.unused", "metin");
        assertTrue(refusal(extra).contains("block.unused: not a declared key"));

        Map<String, String> wrongPlaceholder = new LinkedHashMap<>(good);
        wrongPlaceholder.put("block.platform.body", "{{platfrom}} engellendi");
        assertTrue(refusal(wrongPlaceholder).contains("block.platform.body: placeholders"));

        Map<String, String> dropped = new LinkedHashMap<>(good);
        dropped.put("stream.terminated", "Yanıt kesildi. Referans: {{ref}}");
        assertTrue(refusal(dropped).contains("stream.terminated: placeholders"));

        Map<String, String> unclosed = new LinkedHashMap<>(good);
        unclosed.put("page.reference", "Referans: {{ref");
        assertTrue(refusal(unclosed).contains("page.reference: an unclosed placeholder"));

        Map<String, String> badVersion = new LinkedHashMap<>(good);
        badVersion.put("catalogue.version", "1");
        assertTrue(refusal(badVersion).contains("catalogue.version"));
    }

    private static String refusal(Map<String, String> texts) {
        return assertThrows(IllegalStateException.class, () -> EndUserCatalogue.of(texts)).getMessage();
    }

    static List<String> resourceLines() throws Exception {
        try (InputStream in = EndUserCatalogue.class.getResourceAsStream(EndUserCatalogue.RESOURCE)) {
            return new ArrayList<>(new String(in.readAllBytes(), StandardCharsets.UTF_8).lines().toList());
        }
    }
}
