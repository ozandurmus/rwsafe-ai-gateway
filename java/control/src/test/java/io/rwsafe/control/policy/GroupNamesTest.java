package io.rwsafe.control.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

/** The group-name normal form shared with the data plane (synthetic names only). */
class GroupNamesTest {

    @Test
    void theFourIFormsCaseAndSpaceFoldToOneName() {
        String expected = "grp-istanbul-iki";
        for (String raw : new String[] {
            "GRP-İSTANBUL-İKİ",
            "  grp-Istanbul-Iki ",
            "grp-ıstanbul-ıkı",
            "GRP-ISTANBUL-IKI",
            "grp-i̇stanbul-iki",
            "GRP-İSTANBUL-IKI"}) {
            assertEquals(expected, GroupNames.normalise(raw), raw);
        }
    }

    @Test
    void theResultIsNfcAndIdempotent() {
        assertEquals("grp-équipe", GroupNames.normalise("GRP-ÉQUIPE"));
        String once = GroupNames.normalise("GRP-İKİ-ALPHA");
        assertEquals(once, GroupNames.normalise(once));
    }

    @Test
    void shortNamesOnly() {
        for (String bad : new String[] {"", "   ", "grp-a,grp-b", "grp-\u0007", "grp-\u007f", "g".repeat(257), null}) {
            assertNull(GroupNames.normalise(bad), String.valueOf(bad));
        }
        assertEquals(256, GroupNames.normalise("G".repeat(256)).length());
    }

    @Test
    void aListIsOneToThirtyTwoDistinctNamesSorted() {
        assertEquals(List.of("grp-alpha", "grp-beta"), GroupNames.normaliseAll(List.of("GRP-BETA", " grp-alpha")));
        assertNull(GroupNames.normaliseAll(List.of()));
        assertNull(GroupNames.normaliseAll(List.of("GRP-İKİ", "grp-iki")), "duplicates after normalisation");
        assertNull(GroupNames.normaliseAll(IntStream.rangeClosed(1, 33).mapToObj(i -> "grp-" + i).toList()));
        assertEquals(32, GroupNames.normaliseAll(IntStream.rangeClosed(1, 32).mapToObj(i -> "grp-" + i).toList()).size());
        assertTrue(GroupNames.storedFormOk(List.of("grp-beta", "grp-alpha")));
        assertTrue(!GroupNames.storedFormOk(List.of("GRP-ALPHA")));
    }
}
