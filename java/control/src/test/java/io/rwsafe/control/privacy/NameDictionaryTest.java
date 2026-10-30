package io.rwsafe.control.privacy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** The committed name lists: loadable, without duplicates, the allow list inside them, and fail closed when missing. */
class NameDictionaryTest {

    private static final String BASE = "io/rwsafe/control/privacy/names/";

    @Test
    void theCommittedDictionaryLoads() {
        NameDictionary d = NameDictionary.standard();
        assertNotNull(d);
        assertTrue(d.size() > 400, "given and family names: " + d.size());
        assertTrue(lines("given-names.txt").size() >= 300);
        assertTrue(lines("surnames.txt").size() >= 150);
    }

    @Test
    void listsHaveNoFoldedDuplicatesAndTheAllowListNamesOnlyNames() {
        Set<String> names = new HashSet<>();
        for (String file : List.of("given-names.txt", "surnames.txt", "common-words.txt")) {
            Set<String> seen = new HashSet<>();
            for (String word : lines(file)) {
                assertTrue(seen.add(NameDictionary.fold(word)), file + " repeats an entry");
            }
            if (!file.startsWith("common")) {
                names.addAll(seen);
            }
        }
        for (String word : lines("common-words.txt")) {
            assertTrue(names.contains(NameDictionary.fold(word)), "allow-list entry is not a name: " + word);
        }
    }

    @Test
    void foldingJoinsTheTurkishAndLatinLetters() {
        assertEquals("ibrahim", NameDictionary.fold("İBRAHİM"));
        assertEquals("ibrahim", NameDictionary.fold("ıbrahım"));
        assertEquals("gulsen ozturk", NameDictionary.fold("GÜLŞEN ÖZTÜRK"));
        assertEquals("cagla", NameDictionary.fold("Çağla"));
    }

    /** PR 26 review D-02: the best stem wins, compound endings, softened consonants, short stems flagged. */
    @Test
    void stemsStripCaseEndingsAndPreferTheLongestNameStem() {
        NameDictionary d = NameDictionary.standard();
        assertEquals("ayse", key(d, "aysenin"));
        assertEquals("mehmet", key(d, "mehmete"));
        assertEquals("gulay", key(d, "gulaya"), "Gülay, not the everyday Gül");
        assertEquals("gulay", key(d, "gulayla"));
        assertEquals("nuray", key(d, "nurayi"));
        assertEquals("gokay", key(d, "gokayla"));
        assertEquals("aysun", key(d, "aysunun"), "the longest stem");
        assertEquals("aysun", key(d, "aysundan"));
        assertEquals("berkay", key(d, "berkaya"));
        assertEquals("aysel", key(d, "aysele"));
        for (String compound : List.of("aysenin", "ayseninki", "ahmetine", "ahmetinden", "ahmetinde",
            "ahmetiyle", "zeynebe")) {
            assertNotNull(d.match(compound, false), compound);
        }
        assertEquals("mehmet", key(d, "mehmede"), "softened t");
        assertEquals("murat", key(d, "murada"));
        assertEquals("recep", key(d, "recebe"), "softened p");
        assertEquals("burak", key(d, "buraga"), "softened k");
        NameDictionary.Match cem = d.match("ceme", false);
        assertTrue(cem.shortStem() && cem.suffixed(), "a three-letter name with an ending is a short stem");
        assertEquals("oz", key(d, "ozun"));
        assertNull(d.match("osmanli", false), "no derivational ending");
        assertTrue((d.flags("metin") & NameDictionary.GIVEN) != 0, "metin is a given name");
        assertTrue((d.flags("metin") & NameDictionary.COMMON) != 0, "and an everyday word");
        assertEquals(0, d.flags("bugun"));
    }

    @Test
    void aMissingDictionaryLeavesMaskingUnavailable() {
        assertNull(NameDictionary.load(getClass().getClassLoader(), "io/rwsafe/control/privacy/missing/"));
        PrivacyKeys keys = PseudonymiserTest.keys(1);
        Masking off = new Masking(keys, new Pseudonymiser(keys), null);
        assertFalse(off.available());
        assertThrows(MaskingUnavailableException.class, off::masker);
        assertTrue(new Masking(keys, new Pseudonymiser(keys)).available());
    }

    private static String key(NameDictionary d, String folded) {
        NameDictionary.Match m = d.match(folded, false);
        return m == null ? null : m.key();
    }

    private static List<String> lines(String file) {
        List<String> out = new ArrayList<>();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(
            NameDictionaryTest.class.getClassLoader().getResourceAsStream(BASE + file), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                if (!line.isBlank() && !line.startsWith("#")) {
                    out.add(line.strip());
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return out;
    }
}
