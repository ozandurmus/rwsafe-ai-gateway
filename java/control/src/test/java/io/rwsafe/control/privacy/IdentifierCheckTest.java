package io.rwsafe.control.privacy;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.control.support.Synthetic;
import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.Test;

/**
 * The shared identifier shape (PR 24 reviews D-01, N-02): numbers glued to letters or written in groups, Turkish forms and
 * case variants of secret shapes are found; vocabulary values are not. Values are built at runtime (AGENTS.md 4.5).
 */
class IdentifierCheckTest {

    @Test
    void groupedAndGluedNumbersAreIdentifiers() {
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
            Synthetic.githubToken());
        for (String shape : shapes) {
            assertTrue(IdentifierCheck.identifierShape(shape), "an identifier shape was missed (form " + shapes.indexOf(shape)
                + ")");
        }
    }

    @Test
    void vocabularyValuesAreNotIdentifiers() {
        for (String value : List.of("SYNTHETIC_CHANGE", "class.TCKN@12", "api.anthropic.com", "v1.2.3", "Q4 2026",
            "grp-ops-12", "Hazine Müdürlüğü", "us-east-1", "SEED_FIXTURE")) {
            assertFalse(IdentifierCheck.identifierShape(value), "a vocabulary value was refused: " + value);
        }
    }

    @Test
    void foldingIsTurkishAware() {
        assertTrue(IdentifierCheck.fold("İSTANBUL Şube ĞÜÖÇı").equals("istanbul sube guoci"));
    }
}
