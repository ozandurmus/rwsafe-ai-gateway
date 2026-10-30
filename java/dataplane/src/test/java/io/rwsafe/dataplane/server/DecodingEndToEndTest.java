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
import io.rwsafe.policy.Snapshots;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
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

    @BeforeAll
    static void start() throws InterruptedException {
        EventSink sink = EVENTS::add;
        EngineConfig config = EngineConfig.defaults().withBodyLimits(256 * 1024, 256L * 1024 * 1024)
            .withWindow(1024, 128).withTimeouts(400, 3_000);
        server = new IcapServer(new IcapEngine(Snapshots.builtinDevelopment(), DetectorSet.standard(), sink, config), 0);
        port = server.start("127.0.0.1", 0);
    }

    @AfterAll
    static void stop() {
        server.close();
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
        Frames.Http http = Frames.http(head + "Content-Length: " + body.length + "\n", body);
        try (IcapTestClient c = new IcapTestClient(port)) {
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
            BodyDecodingTest.prompt("synthetic deploy " + BodyDecodingTest.b64(BodyDecodingTest.b64(key)))));
        assertTrue(r.httpHead().startsWith("HTTP/1.1 403"));
        assertTrue(r.httpHead().contains("X-RWSAFE-Reason: secret"));
        assertFalse(r.bodyText().contains(key));
        assertEquals(Verdict.BLOCK, awaitEvent().verdict());
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
}
