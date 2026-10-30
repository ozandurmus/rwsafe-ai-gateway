package io.rwsafe.dataplane.fuzz;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.code_intelligence.jazzer.junit.FuzzTest;
import java.io.File;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Wires the Jazzer harness (SR-DP-4) before the ICAP and HTTP decoders exist: one placeholder target with the contract
 * every parser target will keep (any input yields an explicit verdict, never an exception; SR-DP-3).
 *
 * <p>Corpus: {@code src/test/resources/io/rwsafe/dataplane/fuzz/<Class>Inputs/<method>/}, replayed by {@code test}
 * (regression mode) and extended by {@code fuzzTest}. Seeds are synthetic (example.invalid, no prompt body). Replace this
 * class with {@code IcapDecoderFuzzTest}, {@code ChunkedDecoderFuzzTest} and the others the ICAP spec lists when the
 * decoders land: one {@code @FuzzTest} per class (one fuzzer per JVM), each with a per-input {@code @Timeout}, its own
 * corpus directory and a test that the directory is on the classpath and holds a seed.
 */
class PlaceholderParserFuzzTest {

    enum Verdict { REQUEST_LINE, MALFORMED }

    private static final int MAX_LINE = 8192;

    @FuzzTest(maxDuration = "60s")
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void parse(byte[] input) {
        assertNotNull(parseRequestLine(input));
    }

    /** A misnamed corpus directory would replay only Jazzer's empty input and pass silently. */
    @Test
    void corpusIsOnTheClasspathWithASeed() throws URISyntaxException {
        URL corpus = getClass().getResource("PlaceholderParserFuzzTestInputs/parse");
        assertNotNull(corpus, "corpus directory missing from the test classpath");
        File[] seeds = new File(corpus.toURI()).listFiles(File::isFile);
        assertTrue(seeds != null && seeds.length > 0, "corpus directory holds no seed");
    }

    /** A bounded request-line check standing in for the ICAP decoder: three tokens before the first CRLF. */
    static Verdict parseRequestLine(byte[] input) {
        int end = -1;
        for (int i = 0; i + 1 < input.length && i < MAX_LINE; i++) {
            if (input[i] == '\r' && input[i + 1] == '\n') {
                end = i;
                break;
            }
        }
        if (end <= 0) {
            return Verdict.MALFORMED;
        }
        String line = new String(input, 0, end, StandardCharsets.US_ASCII);
        int first = line.indexOf(' ');
        int last = line.lastIndexOf(' ');
        return first > 0 && last > first + 1 && last < line.length() - 1 ? Verdict.REQUEST_LINE : Verdict.MALFORMED;
    }
}
