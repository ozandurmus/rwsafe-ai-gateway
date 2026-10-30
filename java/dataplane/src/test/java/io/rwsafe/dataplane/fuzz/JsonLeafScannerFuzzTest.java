package io.rwsafe.dataplane.fuzz;

import com.code_intelligence.jazzer.junit.FuzzTest;
import io.rwsafe.dataplane.inspect.JsonLeaf;
import io.rwsafe.dataplane.inspect.JsonLeafScanner;
import java.net.URISyntaxException;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** Any input is valid JSON with in-bounds leaf spans, or Malformed; nothing else escapes (OFF2-6, SR-DP-3). */
class JsonLeafScannerFuzzTest {

    @FuzzTest(maxDuration = "60s")
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void scan(byte[] input) {
        try {
            List<JsonLeaf> leaves = JsonLeafScanner.scan(input, input.length);
            int last = -1;
            for (JsonLeaf leaf : leaves) {
                if (leaf.rawStart() <= last || leaf.rawEnd() > input.length || input[leaf.rawStart()] != '"'
                    || input[leaf.rawEnd() - 1] != '"') {
                    throw new AssertionError("leaf span out of order or out of bounds");
                }
                last = leaf.rawStart();
            }
        } catch (JsonLeafScanner.Malformed expected) {
            // refusal is the contract
        }
    }

    @Test
    void corpusIsOnTheClasspathWithASeed() throws URISyntaxException {
        CorpusCheck.hasSeed(getClass(), "scan");
    }
}
