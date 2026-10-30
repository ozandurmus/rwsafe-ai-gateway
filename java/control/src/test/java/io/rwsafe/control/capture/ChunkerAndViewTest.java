package io.rwsafe.control.capture;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** Content-defined chunking (ADR-009 §2-§3) and the served text's framing (SEC-5, PR 25 review D-03). */
class ChunkerAndViewTest {

    private static byte[] text(long seed, int n) {
        byte[] b = new byte[n];
        Random r = new Random(seed);
        for (int i = 0; i < n; i++) {
            b[i] = (byte) ('a' + r.nextInt(26));
        }
        return b;
    }

    private static List<byte[]> pieces(byte[] data) {
        List<byte[]> out = new ArrayList<>();
        for (int[] c : Chunker.cut(data, data.length)) {
            out.add(Arrays.copyOfRange(data, c[0], c[0] + c[1]));
        }
        return out;
    }

    @Test
    void chunksAreBoundedCoverTheInputAndRepeatAfterAnInsertion() {
        byte[] context = text(1, 200 * 1024);
        List<int[]> cuts = Chunker.cut(context, context.length);
        int covered = 0;
        for (int i = 0; i < cuts.size(); i++) {
            assertEquals(covered, cuts.get(i)[0]);
            covered += cuts.get(i)[1];
            assertTrue(cuts.get(i)[1] <= Chunker.MAX);
            if (i < cuts.size() - 1) {
                assertTrue(cuts.get(i)[1] >= Chunker.MIN);
            }
        }
        assertEquals(context.length, covered);
        assertEquals(1, Chunker.cut(context, 1000).size(), "a short text is one chunk");

        // A coding agent resends the same context after a new instruction: the later chunks repeat exactly.
        byte[] prefix = "synthetic: a new instruction first\n".getBytes(StandardCharsets.UTF_8);
        byte[] resent = new byte[prefix.length + context.length];
        System.arraycopy(prefix, 0, resent, 0, prefix.length);
        System.arraycopy(context, 0, resent, prefix.length, context.length);
        List<byte[]> a = pieces(context);
        List<byte[]> b = pieces(resent);
        int shared = 0;
        for (byte[] x : b) {
            for (byte[] y : a) {
                if (Arrays.equals(x, y)) {
                    shared++;
                    break;
                }
            }
        }
        assertTrue(shared >= a.size() - 2, "content-defined boundaries resynchronise: " + shared + " of " + a.size());
        assertArrayEquals(context, Arrays.copyOfRange(resent, prefix.length, resent.length));
    }

    @Test
    void servedTextIsInert() {
        StringBuilder in = new StringBuilder("a\r\nb\tc");
        in.append((char) 0x1b).append("[31m").append((char) 0x9b).append((char) 0x7f).append((char) 0x00);
        char[] bidi = {0x061c, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069};
        for (char c : bidi) {
            in.append(c);
        }
        in.append((char) 0x2028).append((char) 0x2029).append("[REDACTED:TCKN]");
        String out = CaptureView.inert(in.toString());
        assertFalse(out.contains("\r"));
        assertTrue(out.startsWith("a\nb\tc"), "line feed and tab stay");
        for (char c : out.toCharArray()) {
            assertFalse(c != '\n' && c != '\t' && (c < 0x20 || (c >= 0x7f && c <= 0x9f)), "control " + (int) c);
            assertFalse(CaptureView.neutralised(c), "neutralised " + (int) c);
        }
        long replaced = out.chars().filter(c -> c == CaptureView.REPLACEMENT).count();
        assertEquals(4 + 12 + 2, replaced, "ESC, CSI, DEL, NUL, the 12 Bidi_Control and the 2 separators");
        assertTrue(out.endsWith("[REDACTED:TCKN]"));
    }

    @Test
    void theMaskedProjectionWithholdsTheText() {
        CaptureView v = new CaptureView(UUID.randomUUID(), "synthetic text", false, false, "rwmask-v1-slice1",
            Instant.now(), Instant.now(), 7);
        CaptureView masked = (CaptureView) v.masked(null);
        assertNull(masked.text());
        assertTrue(masked.withheld());
        assertEquals(7, masked.readId());
        assertFalse(v.toString().contains("synthetic text"));
    }
}
