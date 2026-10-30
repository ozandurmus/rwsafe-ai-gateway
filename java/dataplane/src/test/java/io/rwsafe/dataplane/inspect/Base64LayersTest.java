package io.rwsafe.dataplane.inspect;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.detect.DetectorSet;
import io.rwsafe.detect.Normaliser;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;

/**
 * PR 17 recheck 2 D-10, recheck 3 D-11: the work of the layer scan is bounded and linear on nested input, counted in
 * detector passes.
 */
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
    void thirdLayerRunsAreNeverDecoded() {
        // Recheck 3 D-11: three layers are decoded and read; a fourth is classified, not decoded: it adds no scan.
        String fourth = b64(b64(b64(b64("synthetic fourth layer content"))));
        Base64Layers.Outcome outcome = Base64Layers.inspect(Normaliser.normalise(fourth), DETECTORS);
        assertEquals("UNDECODABLE_BLOB", outcome.reason());
        assertEquals(3, outcome.scans(), "one text scan per decoded layer, none below the third");
    }

    @Test
    void aFourthLayerNeedsARealBase64Shape() {
        assertFalse(Base64Layers.base64Shaped("configuration", 0));
        assertFalse(Base64Layers.base64Shaped("musteri_numarasi", 0));
        assertFalse(Base64Layers.base64Shaped("ABCDEFGHIJKLMNOPQRST", 0));
        assertFalse(Base64Layers.base64Shaped("12345678901234567890", 0));
        assertTrue(Base64Layers.base64Shaped("c3ludGhldGljIG5vdGU", 1));
    }
}
