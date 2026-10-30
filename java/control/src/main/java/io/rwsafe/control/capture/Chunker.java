package io.rwsafe.control.capture;

import java.util.ArrayList;
import java.util.List;
import java.util.SplittableRandom;

/**
 * Content-defined chunking (ADR-009 §2-§3: 8-64 KiB chunks): a Gear rolling hash over the bytes cuts where its top 13
 * bits are zero, never before {@link #MIN} bytes and always at {@link #MAX}. Equal runs of text (a coding agent resending
 * the same repository context) therefore cut at the same places whatever precedes them, so their chunks repeat and are
 * stored once. The gear table is a fixed function of a constant seed: boundaries never depend on a key or a run.
 */
final class Chunker {

    static final int MIN = 8 * 1024;
    static final int MAX = 64 * 1024;
    private static final long[] GEAR = new long[256];

    static {
        SplittableRandom r = new SplittableRandom(0x7277_7361_6665_4333L);
        for (int i = 0; i < GEAR.length; i++) {
            GEAR[i] = r.nextLong();
        }
    }

    private Chunker() {
    }

    /** The chunks of {@code data[0, len)} as {offset, length} pairs, in order; a text under {@link #MIN} is one chunk. */
    static List<int[]> cut(byte[] data, int len) {
        List<int[]> out = new ArrayList<>();
        int start = 0;
        long h = 0;
        for (int i = 0; i < len; i++) {
            h = (h << 1) + GEAR[data[i] & 0xff];
            int size = i - start + 1;
            if ((size >= MIN && (h >>> 51) == 0) || size == MAX) {
                out.add(new int[] {start, size});
                start = i + 1;
                h = 0;
            }
        }
        if (start < len) {
            out.add(new int[] {start, len - start});
        }
        return out;
    }
}
