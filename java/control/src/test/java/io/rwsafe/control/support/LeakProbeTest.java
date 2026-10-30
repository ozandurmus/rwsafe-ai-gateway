package io.rwsafe.control.support;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * The comparison itself (PR 24 review D-02): every written form of a canary that a screen could show is found, and a
 * text without one finds nothing. Values are built at runtime (AGENTS.md 4.5).
 */
class LeakProbeTest {

    private static Set<String> classes(LeakProbe probe, String text) {
        Set<String> out = new TreeSet<>();
        probe.scanText("test", text).forEach(h -> out.add(h.canaryClass()));
        return out;
    }

    @Test
    void turkishLettersMatchInEveryNormalisationAndCase() {
        LeakProbe probe = new LeakProbe();
        String name = "İlkay Gümüşdağ";
        probe.canary("NAME", name);
        assertEquals(Set.of("NAME"), classes(probe, "kayıt: " + name));
        assertEquals(Set.of("NAME"), classes(probe, Normalizer.normalize(name, Normalizer.Form.NFD).toUpperCase()));
        assertEquals(Set.of("NAME"), classes(probe, "ilkay gumusdag"), "the ASCII-folded form");
        assertEquals(Set.of("NAME"), classes(probe, "owner=gumusdag;"), "one word of a multi-word canary");
        assertEquals(Set.of("NAME"), classes(probe, "ILKAY"), "dotted capital I folds to i");
    }

    @Test
    void numbersAreFoundSpacedHyphenatedDottedGluedAndEncoded() {
        LeakProbe probe = new LeakProbe();
        String tckn = Synthetic.tckn(7);
        String iban = Synthetic.iban(8);
        String card = Synthetic.card(9);
        String mobile = "05" + tckn.substring(2, 11);
        probe.canary("TCKN", tckn);
        probe.canary("IBAN", iban);
        probe.canary("IBAN", iban.substring(2));
        probe.canary("CARD", card);
        probe.canary("MOBILE", mobile);
        probe.canary("MOBILE", mobile.substring(1));
        probe.canary("MOBILE", "9" + mobile);
        assertEquals(Set.of("TCKN"), classes(probe, "ref" + tckn + "x"), "glued to letters");
        assertEquals(Set.of("IBAN"), classes(probe, spaced(iban, 4)), "an IBAN in groups of four");
        assertEquals(Set.of("IBAN"), classes(probe, "odeme" + iban.toLowerCase()), "an IBAN glued to letters");
        assertEquals(Set.of("CARD"), classes(probe, String.join("-", card.substring(0, 4), card.substring(4, 8),
            card.substring(8, 12), card.substring(12))), "a hyphenated card");
        assertEquals(Set.of("MOBILE"), classes(probe, "tel: +90 " + mobile.substring(1, 4) + " "
            + mobile.substring(4, 7) + " " + mobile.substring(7, 9) + " " + mobile.substring(9)), "a spaced mobile");
        assertEquals(Set.of("MOBILE"), classes(probe, mobile.substring(0, 4) + "." + mobile.substring(4)), "dotted");
        assertEquals(Set.of("TCKN"), classes(probe, "q=" + URLEncoder.encode("kimlik " + tckn, StandardCharsets.UTF_8)
            .replace("+", "%20")), "percent-encoded");
    }

    @Test
    void compoundTokensAndTheirPartsAreFound() {
        LeakProbe probe = new LeakProbe();
        probe.canary("HOST", "srv-abcdef-12");
        String at = "@";
        probe.canary("MAIL", "user.name" + at + "corp-ghijkl.test");
        assertEquals(Set.of("HOST"), classes(probe, "EST-x-srv-abcdef-12-signing"));
        assertEquals(Set.of("MAIL"), classes(probe, "<User.Name" + at + "Corp-GHIJKL.test>"));
    }

    @Test
    void aTextWithoutCanariesFindsNothing() {
        LeakProbe probe = new LeakProbe();
        probe.canary("TCKN", Synthetic.tckn(11));
        probe.canary("NAME", "Şükrü Öztürk");
        for (String clean : List.of("USR-0123456789 TCKN-1a2b [REDACTED:TCKN] synthetic", "masked session",
            "EST-1a2b 240.1.2.0/24 " + Synthetic.tckn(12))) {
            assertTrue(classes(probe, clean).isEmpty(), "a false positive");
        }
    }

    private static String spaced(String s, int group) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length(); i += group) {
            if (i > 0) {
                b.append(' ');
            }
            b.append(s, i, Math.min(s.length(), i + group));
        }
        return b.toString();
    }
}
