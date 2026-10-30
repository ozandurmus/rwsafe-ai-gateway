package io.rwsafe.dataplane.inspect;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.detect.DetectorSet;
import io.rwsafe.detect.Normaliser;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;

/** PR 17 recheck 2 D-10: the work of the layer scan is bounded and linear on nested input, counted in detector passes. */
class Base64LayersTest {

    private static final DetectorSet DETECTORS = DetectorSet.standard();

    private static String b64(String s) {
        return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    private static int scans(String text) {
        return Base64Layers.inspect(Normaliser.normalise(text), DETECTORS).scans();
    }

    /** A nested unit: a glued prefix (alignment readings), two layers, and second-layer runs that look like base64. */
    private static String unit(int i) {
        String inner = "synthetic note " + i + " " + b64("SyntheticToken" + i + "AbCdEfGh") + " configuration";
        return "x" + b64(b64(inner)) + "-";
    }

    @Test
    void oneNestedRunHasABoundedNumberOfScans() {
        int n = scans(unit(1));
        // depth 0: at most 8 readings of the run (whole, four alignments, untrimmed and trimmed), each one text scan or
        // five view scans; a text reading's own runs add at most as many again one layer down; nothing deeper.
        assertTrue(n > 0);
        assertTrue(n <= 8 * 5 + 8 * 8 * 5, "scans " + n);
    }

    @Test
    void scansGrowLinearlyWithTheInput() {
        StringBuilder one = new StringBuilder();
        StringBuilder two = new StringBuilder();
        for (int i = 0; i < 50; i++) {
            one.append(unit(i)).append(' ');
            two.append(unit(i)).append(' ').append(unit(i + 1000)).append(' ');
        }
        int s1 = scans(one.toString());
        int s2 = scans(two.toString());
        assertTrue(s2 <= 2 * s1 + 50, s1 + " then " + s2);
    }

    @Test
    void secondLayerRunsAreNeverDecoded() {
        // A third layer is classified, not decoded: its content adds no scan.
        String third = b64(b64(b64("synthetic third layer content")));
        Base64Layers.Outcome outcome = Base64Layers.inspect(Normaliser.normalise(third), DETECTORS);
        assertEquals("UNDECODABLE_BLOB", outcome.reason());
        assertEquals(2, outcome.scans(), "one text scan per decoded layer, none below the second");
    }

    @Test
    void thirdLayerNeedsARealBase64Shape() {
        assertFalse(Base64Layers.thirdLayer("configuration", 0));
        assertFalse(Base64Layers.thirdLayer("musteri_numarasi", 0));
        assertFalse(Base64Layers.thirdLayer("ABCDEFGHIJKLMNOPQRST", 0));
        assertFalse(Base64Layers.thirdLayer("12345678901234567890", 0));
        assertTrue(Base64Layers.thirdLayer("c3ludGhldGljIG5vdGU", 1));
    }
}
