package io.rwsafe.control.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

/** The list rules over the shared java/policy normal form (synthetic names only). */
class ScopeGroupsTest {

    @Test
    void namesAreNormalisedByTheSharedRuleAndSorted() {
        assertEquals(List.of("grp-alpha", "grp-istanbul"),
            ScopeGroups.normalise(List.of("GRP-İSTANBUL", " Grp-Alpha ")));
        assertEquals(List.of("grp-istanbul"), ScopeGroups.normalise(List.of("grp-ıstanbul")));
    }

    @Test
    void aListIsOneToThirtyTwoDistinctValidNames() {
        assertNull(ScopeGroups.normalise(List.of()));
        assertNull(ScopeGroups.normalise(List.of("GRP-İKİ", "grp-iki")), "duplicates after normalisation");
        assertNull(ScopeGroups.normalise(List.of("grp-a,grp-b")), "a comma");
        assertNull(ScopeGroups.normalise(List.of("grp-\u0007")), "a control character");
        assertNull(ScopeGroups.normalise(IntStream.rangeClosed(1, 33).mapToObj(i -> "grp-" + i).toList()));
        assertEquals(32, ScopeGroups.normalise(IntStream.rangeClosed(1, 32).mapToObj(i -> "grp-" + i).toList()).size());
        assertTrue(ScopeGroups.storedFormOk(List.of("grp-beta", "grp-alpha")));
        assertFalse(ScopeGroups.storedFormOk(List.of("GRP-ALPHA")));
    }
}
