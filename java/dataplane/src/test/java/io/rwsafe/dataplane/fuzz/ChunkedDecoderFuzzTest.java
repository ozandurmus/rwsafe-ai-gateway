package io.rwsafe.dataplane.fuzz;

import com.code_intelligence.jazzer.junit.FuzzTest;
import io.rwsafe.dataplane.icap.ChunkedDecoder;
import io.rwsafe.dataplane.icap.IcapProtocolException;
import java.net.URISyntaxException;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** Feeds the input in uneven slices: decoding is independent of how bytes arrive, and only refusals escape. */
class ChunkedDecoderFuzzTest {

    @FuzzTest(maxDuration = "60s")
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void decode(byte[] input) {
        ChunkedDecoder d = new ChunkedDecoder();
        long[] seen = new long[1];
        try {
            int i = 0;
            int step = 1;
            while (i < input.length && !d.done()) {
                int n = Math.min(step, input.length - i);
                int used = d.feed(input, i, n, (b, o, len) -> seen[0] += len);
                if (used < 0 || used > n) {
                    throw new AssertionError("consumed outside the slice");
                }
                i += used;
                if (used < n) {
                    break;
                }
                step = step * 3 % 97 + 1;
            }
        } catch (IcapProtocolException expected) {
            // refusal is the contract
        }
        if (seen[0] > input.length) {
            throw new AssertionError("decoded more than was fed");
        }
    }

    @Test
    void corpusIsOnTheClasspathWithASeed() throws URISyntaxException {
        CorpusCheck.hasSeed(getClass(), "decode");
    }
}
