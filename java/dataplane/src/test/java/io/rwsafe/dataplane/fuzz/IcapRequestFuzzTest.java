package io.rwsafe.dataplane.fuzz;

import com.code_intelligence.jazzer.junit.FuzzTest;
import io.rwsafe.dataplane.icap.IcapProtocolException;
import io.rwsafe.dataplane.icap.IcapRequest;
import java.net.URISyntaxException;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** SR-DP-3, SR-DP-4: any byte sequence parses or is refused with an ICAP status; nothing else escapes. */
class IcapRequestFuzzTest {

    @FuzzTest(maxDuration = "60s")
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void parse(byte[] input) {
        try {
            IcapRequest r = IcapRequest.parse(input, 0, input.length);
            r.preview();
            r.allows204();
            r.headerRange("req-hdr");
        } catch (IcapProtocolException expected) {
            // a refusal with a status is the contract
        }
    }

    @Test
    void corpusIsOnTheClasspathWithASeed() throws URISyntaxException {
        CorpusCheck.hasSeed(getClass(), "parse");
    }
}
