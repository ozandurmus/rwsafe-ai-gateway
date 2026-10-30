package io.rwsafe.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.text.Normalizer;
import org.junit.jupiter.api.Test;

/** The one comparison form of a group name (PR 20 review D-02, Q-2). */
class GroupNamesTest {

    @Test
    void turkishDottedAndDotlessIFoldTogether() {
        for (String i : new String[] {"İ", "I", "ı", "i"}) {
            assertEquals("i", GroupNames.normalise(i), i);
        }
        String expected = "iç-denetim";
        assertEquals(expected, GroupNames.normalise("İç-Denetim"));
        assertEquals(expected, GroupNames.normalise("IÇ-DENETİM"));
        assertEquals(expected, GroupNames.normalise("ıç-denetım"));
        assertEquals(expected, GroupNames.normalise("  iç-denetim  "));
        assertNull(GroupNames.normalise("  iç-denetim\t"), "a control character is refused, never stripped (review N-01)");
    }

    @Test
    void decomposedFormsCompareEqual() {
        String nfd = Normalizer.normalize("İç-Denetim ğşüö", Normalizer.Form.NFD);
        assertEquals("iç-denetim ğşüö", GroupNames.normalise(nfd));
        assertEquals("ix", GroupNames.normalise("i̇x"), "the residual combining dot after i is removed");
        assertEquals("ȧ", GroupNames.normalise("ȧ"), "a dot after another letter stays, composed by NFC");
    }

    @Test
    void invalidNamesAreRefused() {
        assertNull(GroupNames.normalise(null));
        assertNull(GroupNames.normalise("   "));
        assertNull(GroupNames.normalise("finance,audit"), "Q-2: a group name holds no comma");
        assertNull(GroupNames.normalise("fin\u0000ance"));
        assertNull(GroupNames.normalise("fin\u007fance"));
        assertNull(GroupNames.normalise("g".repeat(GroupNames.MAX_LENGTH + 1)));
        assertEquals("g".repeat(GroupNames.MAX_LENGTH),
            GroupNames.normalise("  " + "G".repeat(GroupNames.MAX_LENGTH) + "  "), "the length counts after strip");
    }
}
