package io.rwsafe.dataplane.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.dataplane.boot.IcapServer;
import io.rwsafe.dataplane.events.EventSink;
import io.rwsafe.dataplane.events.VerdictEvent;
import io.rwsafe.dataplane.inspect.JsonLeafScanner;
import io.rwsafe.detect.DetectorSet;
import io.rwsafe.platform.verdict.Verdict;
import io.rwsafe.platform.verdict.DataClass;
import io.rwsafe.policy.Action;
import io.rwsafe.policy.PlatformRule;
import io.rwsafe.policy.PolicySnapshot;
import io.rwsafe.policy.Snapshots;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Decompression (BY-PROTO-7) and base64 layer decoding (OFF2-3) through a real engine over TCP: the redacted rewrite of a
 * gzip body is identity-encoded with a recomputed length, encoded secrets block, and what cannot be decoded is
 * {@code UNINSPECTABLE} on the fail-closed flow.
 */
class DecodingEndToEndTest {

    private static final ConcurrentLinkedQueue<VerdictEvent> EVENTS = new ConcurrentLinkedQueue<>();
    private static final String API = "POST /v1/messages HTTP/1.1\nHost: api.anthropic.com\nContent-Type: application/json\n";
    private static IcapServer server;
    private static int port;
    private static IcapServer failOpenServer;
    private static int failOpenPort;

    @BeforeAll
    static void start() throws InterruptedException {
        EventSink sink = EVENTS::add;
        EngineConfig config = EngineConfig.defaults().withBodyLimits(256 * 1024, 256L * 1024 * 1024)
            .withWindow(1024, 128).withTimeouts(400, 3_000);
        server = new IcapServer(new IcapEngine(Snapshots.builtinDevelopment(), DetectorSet.standard(), sink, config), 0);
        port = server.start("127.0.0.1", 0);
        // A synthetic snapshot whose flow is not fail-closed: a non-verdict alone allows, so findings must decide.
        PolicySnapshot failOpen = new PolicySnapshot(1, "synthetic-fail-open", Map.of(DataClass.SECRET, Action.BLOCK,
            DataClass.TCKN, Action.REDACT), false, List.of(new PlatformRule("claude", List.of("anthropic.com"),
            List.of("api.anthropic.com"), List.of())));
        failOpenServer = new IcapServer(new IcapEngine(failOpen, DetectorSet.standard(), sink, config), 0);
        failOpenPort = failOpenServer.start("127.0.0.1", 0);
    }

    @AfterAll
    static void stop() {
        server.close();
        failOpenServer.close();
    }

    @BeforeEach
    void clearEvents() {
        EVENTS.clear();
    }

    private static VerdictEvent awaitEvent() throws InterruptedException {
        for (int i = 0; i < 100; i++) {
            VerdictEvent e = EVENTS.poll();
            if (e != null) {
                return e;
            }
            Thread.sleep(20);
        }
        throw new AssertionError("no verdict event");
    }

    private static IcapTestClient.Response once(String head, byte[] body) throws Exception {
        return once(port, head, body);
    }

    private static IcapTestClient.Response once(int target, String head, byte[] body) throws Exception {
        Frames.Http http = Frames.http(head + "Content-Length: " + body.length + "\n", body);
        try (IcapTestClient c = new IcapTestClient(target)) {
            c.write(Frames.reqmod(http, -1, true));
            return c.read();
        }
    }

    @Test
    void gzipRequestWithATcknIsRewrittenIdentityEncoded() throws Exception {
        String tckn = Synthetic.tckn(201);
        byte[] plain = BodyDecodingTest.utf8(BodyDecodingTest.prompt("synthetic customer " + tckn + " asks"));
        IcapTestClient.Response r = once(API + "Content-Encoding: gzip\n", BodyDecodingTest.gzip(plain));
        assertEquals(200, r.status());
        String head = r.httpHead().toLowerCase(Locale.ROOT);
        assertTrue(head.startsWith("post /v1/messages http/1.1"));
        assertFalse(head.contains("content-encoding"), "a decoded rewrite is identity-encoded");
        assertTrue(r.httpHead().contains("Content-Length: " + r.body().length));
        JsonLeafScanner.scan(r.body(), r.body().length);
        assertFalse(r.bodyText().contains(tckn));
        assertTrue(r.bodyText().contains("[REDACTED:TCKN]"));
        assertEquals(Verdict.REDACT, awaitEvent().verdict());
    }

    @Test
    void cleanGzipRequestIsAllowedUnchanged() throws Exception {
        byte[] plain = BodyDecodingTest.utf8(BodyDecodingTest.prompt("synthetic release notes"));
        assertEquals(204, once(API + "Content-Encoding: gzip\n", BodyDecodingTest.gzip(plain)).status());
        assertEquals(Verdict.ALLOW, awaitEvent().verdict());
    }

    @Test
    void gzipRatioBombIsUninspectableAndBlocked() throws Exception {
        IcapTestClient.Response r = once(API + "Content-Encoding: gzip\n", BodyDecodingTest.gzip(new byte[512 * 1024]));
        assertTrue(r.httpHead().startsWith("HTTP/1.1 403"));
        VerdictEvent e = awaitEvent();
        assertEquals(Verdict.UNINSPECTABLE, e.verdict());
        assertEquals("ENCODED", e.reason());
    }

    @Test
    void base64CloudKeyIsBlocked() throws Exception {
        String key = Synthetic.awsKey();
        IcapTestClient.Response r = once(API, BodyDecodingTest.utf8(
            BodyDecodingTest.prompt("synthetic deploy " + BodyDecodingTest.b64(key))));
        assertTrue(r.httpHead().startsWith("HTTP/1.1 403"));
        assertTrue(r.httpHead().contains("X-RWSAFE-Reason: secret"));
        assertFalse(r.bodyText().contains(key));
        assertEquals(Verdict.BLOCK, awaitEvent().verdict());
        // Recheck 2 D-10, Q-1: double encoded, the key is second-layer content, not a third layer: BLOCK on the secret.
        IcapTestClient.Response twice = once(API, BodyDecodingTest.utf8(
            BodyDecodingTest.prompt("synthetic deploy " + BodyDecodingTest.b64(BodyDecodingTest.b64(key)))));
        assertTrue(twice.httpHead().startsWith("HTTP/1.1 403"));
        assertTrue(twice.httpHead().contains("X-RWSAFE-Reason: secret"));
        VerdictEvent e = awaitEvent();
        assertEquals(Verdict.BLOCK, e.verdict());
        assertEquals(1, e.findings().get("SECRET"));
    }

    @Test
    void base64TcknIsRedactedAsOneToken() throws Exception {
        String tckn = Synthetic.tckn(202);
        String encoded = BodyDecodingTest.b64("synthetic customer " + tckn);
        IcapTestClient.Response r = once(API, BodyDecodingTest.utf8(BodyDecodingTest.prompt("look at " + encoded)));
        assertEquals(200, r.status());
        assertTrue(r.bodyText().contains("\"content\":\"[REDACTED:TCKN]\""), r.bodyText());
        assertFalse(r.bodyText().contains(encoded));
        assertEquals(Verdict.REDACT, awaitEvent().verdict());
    }

    @Test
    void undecodableBlobAndEmbeddedFileAreUninspectable() throws Exception {
        String[] reasons = {"UNDECODABLE_BLOB", "EMBEDDED_FILE"};
        String[] values = {BodyDecodingTest.b64(BodyDecodingTest.random(300, 11)),
            BodyDecodingTest.b64(BodyDecodingTest.utf8("%PDF-1.7\nsynthetic\n%%EOF\n"))};
        for (int i = 0; i < values.length; i++) {
            IcapTestClient.Response r = once(API, BodyDecodingTest.utf8(BodyDecodingTest.prompt(values[i])));
            assertTrue(r.httpHead().startsWith("HTTP/1.1 403"), reasons[i]);
            VerdictEvent e = awaitEvent();
            assertEquals(Verdict.UNINSPECTABLE, e.verdict(), reasons[i]);
            assertEquals(reasons[i], e.reason());
        }
    }

    @Test
    void smallImagesAndShortTokensAreAllowed() throws Exception {
        String body = "{\"model\":\"synthetic\",\"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"image\",\"source\":"
            + "{\"type\":\"base64\",\"media_type\":\"image/png\",\"data\":\"" + BodyDecodingTest.b64(BodyDecodingTest.png(120))
            + "\"}},{\"type\":\"text\",\"text\":\"synthetic: describe msg_01SyntheticIdentifierAbCdEf\"}]}]}";
        assertEquals(204, once(API, body.getBytes(StandardCharsets.UTF_8)).status());
        assertEquals(Verdict.ALLOW, awaitEvent().verdict());
    }

    @Test
    void gzipResponseWithATcknIsRewrittenIdentityEncoded() throws Exception {
        String tckn = Synthetic.tckn(203);
        byte[] plain = BodyDecodingTest.utf8("{\"content\":[{\"type\":\"text\",\"text\":\"synthetic " + tckn + "\"}]}");
        byte[] gz = BodyDecodingTest.gzip(plain);
        Frames.Http request = Frames.fixture("claude/api/messages.http", "synthetic hi");
        try (IcapTestClient c = new IcapTestClient(port)) {
            c.write(Frames.respmod(request, "HTTP/1.1 200 OK\nContent-Type: application/json\nContent-Encoding: gzip\n"
                + "Content-Length: " + gz.length + "\n", gz, 4096));
            IcapTestClient.Response r = c.read();
            assertEquals(200, r.status());
            assertFalse(r.httpHead().toLowerCase(Locale.ROOT).contains("content-encoding"));
            assertTrue(r.httpHead().contains("Content-Length: " + r.body().length));
            assertFalse(r.bodyText().contains(tckn));
            assertTrue(r.bodyText().contains("[REDACTED:TCKN]"));
        }
        assertEquals(Verdict.REDACT, awaitEvent().verdict());
    }

    // ---- PR 17 second review D-01 ----

    private static byte[] secretBesideABlob(String secret) {
        return BodyDecodingTest.utf8("{\"model\":\"synthetic\",\"messages\":[{\"role\":\"user\",\"content\":\"synthetic "
            + secret + "\"},{\"role\":\"user\",\"content\":\"" + BodyDecodingTest.b64(BodyDecodingTest.random(300, 41))
            + "\"}]}");
    }

    /** D-01: on the fail-closed flow the request blocks and the event keeps the finding classes. */
    @Test
    void findingsBesideABlobAreCountedOnTheFailClosedFlow() throws Exception {
        IcapTestClient.Response r = once(API, secretBesideABlob(Synthetic.awsKey()));
        assertTrue(r.httpHead().startsWith("HTTP/1.1 403"));
        VerdictEvent e = awaitEvent();
        assertEquals(Verdict.UNINSPECTABLE, e.verdict());
        assertEquals(1, e.findings().get("SECRET"));
    }

    /** D-01: where a non-verdict alone would allow, a blocking finding still blocks and a redaction still applies. */
    @Test
    void findingsBesideABlobStillDecideOnAFailOpenFlow() throws Exception {
        String key = Synthetic.awsKey();
        IcapTestClient.Response blocked = once(failOpenPort, API, secretBesideABlob(key));
        assertTrue(blocked.httpHead().startsWith("HTTP/1.1 403"));
        assertFalse(blocked.bodyText().contains(key));
        assertEquals(Verdict.BLOCK, awaitEvent().verdict());
        String tckn = Synthetic.tckn(42);
        IcapTestClient.Response redacted = once(failOpenPort, API, secretBesideABlob(tckn));
        assertEquals(200, redacted.status());
        assertTrue(redacted.httpHead().startsWith("POST /v1/messages"));
        assertFalse(redacted.bodyText().contains(tckn));
        assertTrue(redacted.bodyText().contains("[REDACTED:TCKN]"));
        VerdictEvent e = awaitEvent();
        assertEquals(Verdict.REDACT, e.verdict());
        assertEquals(1, e.findings().get("TCKN"));
    }

    /** D-01: a whole-body response with a finding beside an embedded image, or with a blob, never ends in a 204. */
    @Test
    void responseWithAFindingBesideAFileOrWithABlobIsTerminated() throws Exception {
        String tckn = Synthetic.tckn(43);
        // The third case is recheck D-06: an embedded file before the blob must not mask it.
        String[] contents = {"synthetic " + tckn + "\"},{\"type\":\"image\",\"data\":\""
            + BodyDecodingTest.b64(BodyDecodingTest.png(400)), BodyDecodingTest.b64(BodyDecodingTest.random(300, 44)),
            BodyDecodingTest.b64(BodyDecodingTest.utf8("%PDF-1.4\n")) + "\"},{\"type\":\"text\",\"text\":\""
                + BodyDecodingTest.b64(BodyDecodingTest.random(300, 45))};
        for (String content : contents) {
            byte[] body = BodyDecodingTest.utf8("{\"content\":[{\"type\":\"text\",\"text\":\"" + content + "\"}]}");
            Frames.Http request = Frames.fixture("claude/api/messages.http", "synthetic hi");
            try (IcapTestClient c = new IcapTestClient(port)) {
                c.write(Frames.respmod(request, "HTTP/1.1 200 OK\nContent-Type: application/json\nContent-Length: "
                    + body.length + "\n", body, 4096));
                IcapTestClient.Response r = c.read();
                assertEquals(200, r.status());
                assertFalse(r.bodyText().contains(tckn));
                assertTrue(r.httpHead().contains("text/plain"));
            }
            VerdictEvent e = awaitEvent();
            assertEquals(Verdict.STREAM_ABORTED, e.verdict());
        }
    }

    // ---- PR 17 second confirmation review ----

    /** Recheck 2 D-08: secrets that reach the finding limit inside a decoded layer still block on a fail-open flow. */
    @Test
    void encodedSecretsAtTheFindingLimitStillBlockOnAFailOpenFlow() throws Exception {
        String key = Synthetic.awsKey();
        for (int copies : new int[] {70, 1000}) {
            String encoded = BodyDecodingTest.b64((key + " ").repeat(copies));
            IcapTestClient.Response r = once(failOpenPort, API, BodyDecodingTest.utf8(BodyDecodingTest.prompt(encoded)));
            assertTrue(r.httpHead().startsWith("HTTP/1.1 403"), copies + " copies");
            assertFalse(r.bodyText().contains(key));
            VerdictEvent e = awaitEvent();
            assertEquals(Verdict.BLOCK, e.verdict(), copies + " copies");
            assertTrue(e.findings().get("SECRET") >= copies, copies + " copies");
        }
    }

    /** Recheck 2 D-10: a TCKN inside double base64 beside an ordinary long word is redacted, not a blob. */
    @Test
    void doubleEncodedTcknBesideAWordIsRedacted() throws Exception {
        String tckn = Synthetic.tckn(61);
        String encoded = BodyDecodingTest.b64(BodyDecodingTest.b64("configuration musteri_numarasi " + tckn));
        IcapTestClient.Response r = once(API, BodyDecodingTest.utf8(BodyDecodingTest.prompt(encoded)));
        assertEquals(200, r.status());
        assertTrue(r.bodyText().contains("\"content\":\"[REDACTED:TCKN]\""), r.bodyText());
        assertEquals(Verdict.REDACT, awaitEvent().verdict());
    }
}
