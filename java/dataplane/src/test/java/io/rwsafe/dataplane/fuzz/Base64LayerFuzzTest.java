package io.rwsafe.dataplane.fuzz;

import com.code_intelligence.jazzer.junit.FuzzTest;
import io.rwsafe.dataplane.icap.HeaderBlock;
import io.rwsafe.dataplane.inspect.BodyInspector;
import io.rwsafe.dataplane.inspect.CapturedBody;
import io.rwsafe.dataplane.inspect.InspectionResult;
import io.rwsafe.dataplane.inspect.JsonLeafScanner;
import io.rwsafe.detect.DetectorSet;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Any body, base64 layers and declared gzip or deflate included, gives findings or a named non-verdict, and a JSON
 * body's rewrite is valid JSON; nothing else escapes (OFF2-3, BY-PROTO-7, SR-DP-3). The first input byte picks the media
 * type and Content-Encoding.
 */
class Base64LayerFuzzTest {

    private static final BodyInspector INSPECTOR = new BodyInspector(DetectorSet.standard());
    private static final String[] HEADS = {
        "Content-Type: application/json\r\n",
        "Content-Type: text/plain\r\n",
        "Content-Type: application/json\r\nContent-Encoding: gzip\r\n",
        "Content-Type: text/plain\r\nContent-Encoding: deflate\r\n",
    };

    @FuzzTest(maxDuration = "60s")
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void inspect(byte[] input) throws JsonLeafScanner.Malformed {
        if (input.length == 0) {
            return;
        }
        String extra = HEADS[(input[0] & 0xff) % HEADS.length];
        byte[] head = ("POST /v1/messages HTTP/1.1\r\nHost: api.example.com\r\n" + extra + "\r\n")
            .getBytes(StandardCharsets.ISO_8859_1);
        HeaderBlock http = HeaderBlock.parse(head, 0, head.length, 8192, 64, 400);
        CapturedBody body = new CapturedBody(1024 * 1024);
        body.append(input, 1, input.length - 1);
        InspectionResult r = INSPECTOR.inspect(body, http);
        if (r.nonVerdict() != null && r.reason() == null) {
            throw new AssertionError("a non-verdict without a reason");
        }
        byte[] rewritten = r.redactedBody();
        if (rewritten != null) {
            JsonLeafScanner.scan(rewritten, rewritten.length);
        }
    }

    @Test
    void corpusIsOnTheClasspathWithASeed() throws URISyntaxException {
        CorpusCheck.hasSeed(getClass(), "inspect");
    }
}
