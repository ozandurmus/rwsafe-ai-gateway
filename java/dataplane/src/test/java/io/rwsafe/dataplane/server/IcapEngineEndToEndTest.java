package io.rwsafe.dataplane.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.dataplane.boot.IcapServer;
import io.rwsafe.dataplane.events.EventSink;
import io.rwsafe.dataplane.events.VerdictEvent;
import io.rwsafe.detect.DetectorSet;
import io.rwsafe.platform.verdict.Verdict;
import io.rwsafe.policy.Snapshots;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Drives a real engine over TCP with the synthetic fixtures: every council-mandated frame of ICAP spec §5 that this slice
 * implements, plus the ordinary allow, redact and block paths for four platforms.
 */
class IcapEngineEndToEndTest {

    private static final ConcurrentLinkedQueue<VerdictEvent> EVENTS = new ConcurrentLinkedQueue<>();
    private static IcapServer server;
    private static int port;

    @BeforeAll
    static void start() throws InterruptedException {
        EventSink sink = EVENTS::add;
        EngineConfig config = new EngineConfig(64 * 1024, 128 * 1024, 1024, 128, 400, 3_000, 30, 300);
        server = new IcapServer(new IcapEngine(Snapshots.builtinDevelopment(), DetectorSet.standard(), sink, config));
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

    @Test
    void optionsAdvertisesTheService() throws Exception {
        try (IcapTestClient c = new IcapTestClient(port)) {
            c.write(Frames.options("/reqmod-ai"));
            IcapTestClient.Response r = c.read();
            assertEquals(200, r.status());
            assertEquals("REQMOD", r.header("Methods"));
            assertEquals("4096", r.header("Preview"));
            assertNotNull(r.header("ISTag"));
        }
    }

    @Test
    void cleanPromptsAreAllowedOnEveryPlatform() throws Exception {
        for (String fixture : List.of("openai/web/chat.http", "claude/api/messages.http", "copilot/ide/chat.http",
            "gemini/api/generate.http")) {
            try (IcapTestClient c = new IcapTestClient(port)) {
                c.write(Frames.reqmod(Frames.fixture(fixture, "synthetic: summarise the release notes"), -1, true));
                assertEquals(204, c.read().status(), fixture);
            }
            VerdictEvent e = awaitEvent();
            assertEquals(Verdict.ALLOW, e.verdict());
        }
    }

    @Test
    void customerIdentifierIsRedactedInPlace() throws Exception {
        String tckn = Synthetic.tckn(42);
        try (IcapTestClient c = new IcapTestClient(port)) {
            c.write(Frames.reqmod(Frames.fixture("claude/api/messages.http",
                "synthetic: customer " + tckn + " asks about fees"), -1, true));
            IcapTestClient.Response r = c.read();
            assertEquals(200, r.status());
            assertTrue(r.httpHead().startsWith("POST /v1/messages HTTP/1.1"));
            String body = r.bodyText();
            assertFalse(body.contains(tckn));
            assertTrue(body.contains("[REDACTED:TCKN]"));
            assertTrue(r.httpHead().contains("Content-Length: " + r.body().length));
        }
        VerdictEvent e = awaitEvent();
        assertEquals(Verdict.REDACT, e.verdict());
        assertEquals(1, e.findings().get("TCKN"));
        assertEquals("claude", e.platform());
        assertEquals("api", e.surface());
    }

    @Test
    void secretFromTheChatSpaIsBlockedWithATurkishJsonError() throws Exception {
        String key = Synthetic.awsKey();
        try (IcapTestClient c = new IcapTestClient(port)) {
            c.write(Frames.reqmod(Frames.fixture("openai/web/chat.http", "synthetic deploy with " + key), -1, true));
            IcapTestClient.Response r = c.read();
            assertEquals(200, r.status());
            assertTrue(r.httpHead().startsWith("HTTP/1.1 403"));
            assertTrue(r.httpHead().contains("X-RWSAFE-Reason: secret"));
            assertTrue(r.bodyText().contains("rwsafe_blocked"));
            assertTrue(r.bodyText().contains("kurumsal politika"));
            assertFalse(r.bodyText().contains(key));
        }
        assertEquals(Verdict.BLOCK, awaitEvent().verdict());
    }

    @Test
    void browserNavigationGetsTheTurkishBlockPage() throws Exception {
        String key = Synthetic.awsKey();
        byte[] body = ("prompt=synthetic+" + key).getBytes(StandardCharsets.UTF_8);
        Frames.Http http = Frames.http("POST /share HTTP/1.1\nHost: chatgpt.com\nAccept: text/html,application/xhtml+xml\n"
            + "Content-Type: application/x-www-form-urlencoded\nContent-Length: " + body.length + "\n", body);
        try (IcapTestClient c = new IcapTestClient(port)) {
            c.write(Frames.reqmod(http, -1, true));
            IcapTestClient.Response r = c.read();
            assertTrue(r.httpHead().contains("text/html"));
            assertTrue(r.bodyText().contains("İstek engellendi"));
            assertFalse(r.bodyText().contains(key));
        }
    }

    @Test
    void apiClientsGetAJsonBlock() throws Exception {
        try (IcapTestClient c = new IcapTestClient(port)) {
            c.write(Frames.reqmod(Frames.fixture("copilot/ide/chat.http", "synthetic " + Synthetic.githubToken()),
                -1, true));
            IcapTestClient.Response r = c.read();
            assertTrue(r.httpHead().contains("application/json"));
            assertTrue(r.bodyText().contains("rwsafe_blocked"));
        }
    }

    /** OFF2-1: a benign prefix filling the preview cannot buy an allow for what follows it. */
    @Test
    void secretAfterThePreviewBoundaryIsStillBlocked() throws Exception {
        String prompt = "synthetic filler ".repeat(300) + Synthetic.awsKey();
        Frames.Http http = Frames.fixture("claude/api/messages.http", prompt);
        assertTrue(http.body().length > 4096);
        try (IcapTestClient c = new IcapTestClient(port)) {
            c.write(Frames.reqmod(http, 4096, true));
            assertEquals(100, c.read().status());
            c.write(Frames.rest(http.body(), 4096));
            IcapTestClient.Response r = c.read();
            assertTrue(r.httpHead().startsWith("HTTP/1.1 403"));
        }
    }

    @Test
    void wholeBodyInsideThePreviewIsDecidedWithout100Continue() throws Exception {
        try (IcapTestClient c = new IcapTestClient(port)) {
            c.write(Frames.reqmod(Frames.fixture("gemini/api/generate.http", "synthetic hello"), 4096, false));
            assertEquals(204, c.read().status());
        }
    }

    /** OFF2-6: a secret in a field no schema knows is still inspected. */
    @Test
    void secretInAnUnknownFieldIsDetected() throws Exception {
        byte[] body = ("{\"synthetic\":true,\"x_unknown_vendor_field\":{\"nested\":[\"" + Synthetic.awsKey() + "\"]}}")
            .getBytes(StandardCharsets.UTF_8);
        Frames.Http http = Frames.http("POST /v1/messages HTTP/1.1\nHost: api.anthropic.com\n"
            + "Content-Type: application/json\nContent-Length: " + body.length + "\n", body);
        try (IcapTestClient c = new IcapTestClient(port)) {
            c.write(Frames.reqmod(http, -1, true));
            assertTrue(c.read().httpHead().startsWith("HTTP/1.1 403"));
        }
    }

    /** OFF2-2: above the body limit the request is UNINSPECTABLE and a fail-closed flow blocks. */
    @Test
    void oversizeBodyIsBlockedOnTheFailClosedFlow() throws Exception {
        String prompt = "synthetic ".repeat(8000);
        try (IcapTestClient c = new IcapTestClient(port)) {
            c.write(Frames.reqmod(Frames.fixture("openai/web/chat.http", prompt), -1, true));
            assertTrue(c.read().httpHead().startsWith("HTTP/1.1 403"));
        }
        VerdictEvent e = awaitEvent();
        assertEquals(Verdict.UNINSPECTABLE, e.verdict());
        assertEquals("OVERSIZE", e.reason());
    }

    @Test
    void malformedJsonIsAVerdictNotAnAllow() throws Exception {
        byte[] body = "{\"synthetic\": [unterminated".getBytes(StandardCharsets.UTF_8);
        Frames.Http http = Frames.http("POST /v1/messages HTTP/1.1\nHost: api.anthropic.com\n"
            + "Content-Type: application/json\nContent-Length: " + body.length + "\n", body);
        try (IcapTestClient c = new IcapTestClient(port)) {
            c.write(Frames.reqmod(http, -1, true));
            assertTrue(c.read().httpHead().startsWith("HTTP/1.1 403"));
        }
        assertEquals(Verdict.MALFORMED, awaitEvent().verdict());
    }

    /** OFF2-10: a body held open past the receive timeout ends in INSPECTION_TIMEOUT and the connection closes. */
    @Test
    void slowBodyTimesOut() throws Exception {
        Frames.Http http = Frames.fixture("claude/api/messages.http", "synthetic slow");
        byte[] frame = Frames.reqmod(http, -1, true);
        try (IcapTestClient c = new IcapTestClient(port)) {
            c.write(java.util.Arrays.copyOf(frame, frame.length - 20));
            IcapTestClient.Response r = c.read();
            assertTrue(r.httpHead().startsWith("HTTP/1.1 403"));
            assertTrue(c.closedByServer());
        }
        assertEquals(Verdict.INSPECTION_TIMEOUT, awaitEvent().verdict());
    }

    @Test
    void keepAliveServesSeveralTransactions() throws Exception {
        try (IcapTestClient c = new IcapTestClient(port)) {
            for (int i = 0; i < 3; i++) {
                c.write(Frames.reqmod(Frames.fixture("openai/web/chat.http", "synthetic turn " + i), -1, true));
                assertEquals(204, c.read().status());
            }
        }
    }

    @Test
    void malformedIcapHeadIs400AndCloses() throws Exception {
        try (IcapTestClient c = new IcapTestClient(port)) {
            c.write("REQMOD icap://icap.example.invalid/reqmod-ai ICAP/1.0\r\n folded: header\r\n\r\n"
                .getBytes(StandardCharsets.US_ASCII));
            assertEquals(400, c.read().status());
            assertTrue(c.closedByServer());
        }
    }

    @Test
    void unknownServiceIs404() throws Exception {
        try (IcapTestClient c = new IcapTestClient(port)) {
            c.write(Frames.options("/other"));
            assertEquals(404, c.read().status());
        }
    }

    @Test
    void identityClaimTravelsInTheEventOnly() throws Exception {
        try (IcapTestClient c = new IcapTestClient(port)) {
            c.write(Frames.reqmodWithIdentity(Frames.fixture("openai/web/chat.http", "synthetic hi"),
                "U1lOVEhFVElDXHVzZXI=", "192.0.2.10"));
            assertEquals(204, c.read().status());
        }
        VerdictEvent e = awaitEvent();
        assertEquals("U1lOVEhFVElDXHVzZXI=", e.userClaim());
        assertEquals("plain_allowlisted", e.transport());
    }

    @Test
    void cleanResponseInThePreviewIs204() throws Exception {
        Frames.Http request = Frames.fixture("claude/api/messages.http", "synthetic hi");
        byte[] body = "{\"content\":[{\"type\":\"text\",\"text\":\"synthetic answer\"}]}".getBytes(StandardCharsets.UTF_8);
        try (IcapTestClient c = new IcapTestClient(port)) {
            c.write(Frames.respmod(request, "HTTP/1.1 200 OK\nContent-Type: application/json\nContent-Length: "
                + body.length + "\n", body, 4096));
            assertEquals(204, c.read().status());
        }
    }

    /** ICAP spec §4.4: a leak in a later window ends the stream; the offending window never leaves the engine. */
    @Test
    void streamedResponseWithALeakIsAbortedBeforeTheLeakLeaves() throws Exception {
        String tckn = Synthetic.tckn(77);
        StringBuilder sse = new StringBuilder();
        for (int i = 0; i < 40; i++) {
            sse.append("event: delta\ndata: {\"text\":\"synthetic token ").append(i).append("\"}\n\n");
        }
        sse.append("event: delta\ndata: {\"text\":\"customer ").append(tckn).append("\"}\n\n");
        for (int i = 0; i < 40; i++) {
            sse.append("event: delta\ndata: {\"text\":\"synthetic tail ").append(i).append("\"}\n\n");
        }
        byte[] body = sse.toString().getBytes(StandardCharsets.UTF_8);
        Frames.Http request = Frames.fixture("openai/web/chat.http", "synthetic hi");
        try (IcapTestClient c = new IcapTestClient(port)) {
            c.write(Frames.respmod(request, "HTTP/1.1 200 OK\nContent-Type: text/event-stream\n", body, 512));
            IcapTestClient.Response cont = c.read();
            assertEquals(100, cont.status());
            c.write(Frames.rest(body, 512));
            IcapTestClient.Response r = c.read();
            assertEquals(200, r.status());
            String forwarded = r.bodyText();
            assertFalse(forwarded.contains(tckn));
            assertTrue(forwarded.contains("rwsafe_stream_terminated"));
            assertFalse(forwarded.contains("synthetic tail 39"));
        }
        assertEquals(Verdict.STREAM_ABORTED, awaitEvent().verdict());
    }

    @Test
    void cleanStreamIsRelayedCompletely() throws Exception {
        StringBuilder sse = new StringBuilder();
        for (int i = 0; i < 100; i++) {
            sse.append("data: {\"text\":\"synthetic token ").append(i).append("\"}\n\n");
        }
        byte[] body = sse.toString().getBytes(StandardCharsets.UTF_8);
        Frames.Http request = Frames.fixture("openai/web/chat.http", "synthetic hi");
        List<String> got = new ArrayList<>();
        try (IcapTestClient c = new IcapTestClient(port)) {
            c.write(Frames.respmod(request, "HTTP/1.1 200 OK\nContent-Type: text/event-stream\n", body, -1));
            IcapTestClient.Response r = c.read();
            got.add(r.bodyText());
            assertTrue(r.httpHead().startsWith("HTTP/1.1 200 OK"));
        }
        assertEquals(sse.toString(), got.get(0));
        assertEquals(Verdict.ALLOW, awaitEvent().verdict());
    }

    // ---- PR 11 second review (Argon) findings ----

    private static Frames.Http rawHttp(String head, String body) {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        return Frames.http(head.replace("{{LEN}}", Integer.toString(b.length)), b);
    }

    private static IcapTestClient.Response once(byte[] frame) throws Exception {
        try (IcapTestClient c = new IcapTestClient(port)) {
            c.write(frame);
            return c.read();
        }
    }

    /** D-01: the finding limit is a non-verdict that blocks, never a partial redaction. */
    @Test
    void findingLimitBlocksInsteadOfPartiallyRedacting() throws Exception {
        StringBuilder prompt = new StringBuilder("synthetic ");
        for (int i = 0; i < 1001; i++) {
            prompt.append(Synthetic.tckn(i)).append(' ');
        }
        String iban = Synthetic.iban(5);
        prompt.append(iban);
        IcapTestClient.Response r = once(Frames.reqmod(Frames.fixture("claude/api/messages.http", prompt.toString()),
            -1, true));
        assertTrue(r.httpHead().startsWith("HTTP/1.1 403"));
        assertFalse(r.bodyText().contains(iban));
        VerdictEvent e = awaitEvent();
        assertEquals(Verdict.UNINSPECTABLE, e.verdict());
        assertEquals("FINDING_LIMIT", e.reason());
    }

    /** D-02: a percent-encoded identifier in a form body is decoded and found; form bodies are not rewritable. */
    @Test
    void formEncodedIdentifierIsBlocked() throws Exception {
        String tckn = Synthetic.tckn(9);
        StringBuilder enc = new StringBuilder();
        for (char c : tckn.toCharArray()) {
            enc.append('%').append(Integer.toHexString(c).toUpperCase(java.util.Locale.ROOT));
        }
        IcapTestClient.Response r = once(Frames.reqmod(rawHttp("POST /batchexecute HTTP/1.1\nHost: gemini.google.com\n"
            + "Content-Type: application/x-www-form-urlencoded\nContent-Length: {{LEN}}\n", "f.req=synthetic+" + enc),
            -1, true));
        assertTrue(r.httpHead().startsWith("HTTP/1.1 403"));
        assertEquals(Verdict.BLOCK, awaitEvent().verdict());
    }

    /** D-02: bodies the engine cannot read yet are UNINSPECTABLE, which blocks on the fail-closed flow. */
    @Test
    void unreadableBodiesAreUninspectable() throws Exception {
        record Case(String contentType, byte[] body, String reason) {
        }
        byte[] gzip = {(byte) 0x1f, (byte) 0x8b, 8, 0, 0, 0, 0, 0, 0, 3, 's', 'y', 'n'};
        List<Case> cases = List.of(
            new Case("multipart/form-data; boundary=synthetic", "--synthetic\r\n\r\nx\r\n--synthetic--"
                .getBytes(StandardCharsets.US_ASCII), "MULTIPART"),
            new Case("text/plain", gzip, "BINARY"),
            new Case("application/octet-stream", "synthetic".getBytes(StandardCharsets.US_ASCII), "UNSUPPORTED_MEDIA"),
            new Case("text/plain", new byte[] {'s', (byte) 0xc3, (byte) 0x28, 'y'}, "BINARY"));
        for (Case c : cases) {
            Frames.Http http = Frames.http("POST /upload HTTP/1.1\nHost: chatgpt.com\nContent-Type: " + c.contentType()
                + "\nContent-Length: " + c.body().length + "\n", c.body());
            assertTrue(once(Frames.reqmod(http, -1, true)).httpHead().startsWith("HTTP/1.1 403"), c.reason());
            VerdictEvent e = awaitEvent();
            assertEquals(Verdict.UNINSPECTABLE, e.verdict(), c.reason());
            assertEquals(c.reason(), e.reason());
        }
    }

    /** D-03: duplicate framing or type headers are MALFORMED under the flow rule; the connection closes. */
    @Test
    void duplicateFramingHeadersAreMalformed() throws Exception {
        Frames.Http http = rawHttp("POST /v1/messages HTTP/1.1\nHost: api.anthropic.com\nContent-Type: text/plain\n"
            + "Content-Type: application/json\nContent-Length: {{LEN}}\n", "{\"synthetic\":true}");
        try (IcapTestClient c = new IcapTestClient(port)) {
            c.write(Frames.reqmod(http, -1, true));
            assertTrue(c.read().httpHead().startsWith("HTTP/1.1 403"));
            assertTrue(c.closedByServer());
        }
        assertEquals(Verdict.MALFORMED, awaitEvent().verdict());
    }

    /** D-03: any non-identity token in Content-Encoding makes the body UNINSPECTABLE. */
    @Test
    void stackedContentEncodingIsUninspectable() throws Exception {
        Frames.Http http = rawHttp("POST /v1/messages HTTP/1.1\nHost: api.anthropic.com\nContent-Type: application/json\n"
            + "Content-Encoding: identity, gzip\nContent-Length: {{LEN}}\n", "{\"synthetic\":true}");
        assertTrue(once(Frames.reqmod(http, -1, true)).httpHead().startsWith("HTTP/1.1 403"));
        assertEquals("ENCODED", awaitEvent().reason());
    }

    /** D-04: an identifier sent as an unquoted JSON number is a leaf too. */
    @Test
    void identifierAsJsonNumberIsRedacted() throws Exception {
        String tckn = Synthetic.tckn(13);
        Frames.Http http = rawHttp("POST /v1/messages HTTP/1.1\nHost: api.anthropic.com\nContent-Type: application/json\n"
            + "Content-Length: {{LEN}}\n", "{\"synthetic\":true,\"customer\":" + tckn + "}");
        IcapTestClient.Response r = once(Frames.reqmod(http, -1, true));
        assertFalse(r.bodyText().contains(tckn));
        assertTrue(r.bodyText().contains("\"customer\":\"[REDACTED:TCKN]\""));
    }

    /** D-06: format characters between the halves of a value cannot push it out of the window overlap. */
    @Test
    void valueSplitAcrossWindowsWithFormatPaddingIsCaught() throws Exception {
        String tckn = Synthetic.tckn(31);
        String filler = "synthetic ".repeat(95);
        String text = filler + tckn.substring(0, 6) + "\u200b".repeat(700) + tckn.substring(6) + " synthetic end";
        byte[] body = ("data: " + text + "\n\n").getBytes(StandardCharsets.UTF_8);
        Frames.Http request = Frames.fixture("openai/web/chat.http", "synthetic hi");
        try (IcapTestClient c = new IcapTestClient(port)) {
            c.write(Frames.respmod(request, "HTTP/1.1 200 OK\nContent-Type: text/event-stream\n", body, -1));
            IcapTestClient.Response r = c.read();
            assertTrue(r.bodyText().contains("rwsafe_stream_terminated"));
            assertFalse(r.bodyText().contains(tckn.substring(6)));
        }
        assertEquals(Verdict.STREAM_ABORTED, awaitEvent().verdict());
    }

    /** D-07: " 101 " inside a reason phrase is not an upgrade; the body is inspected. */
    @Test
    void reasonPhraseContaining101IsNotAnUpgrade() throws Exception {
        byte[] body = ("synthetic " + Synthetic.tckn(2)).getBytes(StandardCharsets.UTF_8);
        Frames.Http request = Frames.fixture("openai/web/chat.http", "synthetic hi");
        IcapTestClient.Response r = once(Frames.respmod(request, "HTTP/1.1 200 OK 101 synthetic\n"
            + "Content-Type: text/plain\nContent-Length: " + body.length + "\n", body, 4096));
        assertEquals(200, r.status());
        assertTrue(r.bodyText().contains("Yanıt kesildi"));
    }

    /** D-07: a secret in a previewed response is never partially forwarded. */
    @Test
    void secretInAPreviewedJsonResponseReplacesTheWholeBody() throws Exception {
        String pem = "-----BEGIN RSA " + "PRIVATE KEY-----\nsyntheticbodyline\n-----END RSA " + "PRIVATE KEY-----";
        byte[] body = ("{\"text\":\"" + pem.replace("\n", "\\n") + "\"}").getBytes(StandardCharsets.UTF_8);
        Frames.Http request = Frames.fixture("claude/api/messages.http", "synthetic hi");
        IcapTestClient.Response r = once(Frames.respmod(request, "HTTP/1.1 200 OK\nContent-Type: application/json\n"
            + "Content-Length: " + body.length + "\n", body, 4096));
        assertFalse(r.bodyText().contains("syntheticbodyline"));
        assertTrue(r.httpHead().contains("text/plain"));
    }

    /** D-08: without a preview and without Allow 204, an allow is a 200 echo with a correct Content-Length. */
    @Test
    void allowWithout204PermissionEchoesWithCorrectLength() throws Exception {
        Frames.Http http = Frames.fixture("claude/api/messages.http", "synthetic hi");
        IcapTestClient.Response r = once(Frames.reqmod(http, -1, false));
        assertEquals(200, r.status());
        assertTrue(r.httpHead().contains("Content-Length: " + r.body().length));
        assertTrue(r.bodyText().contains("synthetic hi"));
    }

    /** D-08: after 100 Continue there is no 204 unless the client sent Allow 204. */
    @Test
    void no204AfterContinueWithoutAllow() throws Exception {
        String prompt = "synthetic filler ".repeat(300);
        Frames.Http http = Frames.fixture("claude/api/messages.http", prompt);
        try (IcapTestClient c = new IcapTestClient(port)) {
            c.write(Frames.reqmod(http, 4096, false));
            assertEquals(100, c.read().status());
            c.write(Frames.rest(http.body(), 4096));
            IcapTestClient.Response r = c.read();
            assertEquals(200, r.status());
            assertEquals(http.body().length, r.body().length);
        }
    }

    /** D-10: a head that never completes is closed by the transaction deadline. */
    @Test
    void stalledHeadIsClosed() throws Exception {
        try (IcapTestClient c = new IcapTestClient(port)) {
            c.write("REQMOD icap://icap.example.invalid/reqmod-ai ICAP/1.0\r\nHost: synth".getBytes(StandardCharsets.US_ASCII));
            assertTrue(c.closedByServer());
        }
    }

    /** D-10: an abort before the proxy finished sending closes the connection instead of resynchronising. */
    @Test
    void abortMidStreamClosesTheConnection() throws Exception {
        String key = Synthetic.awsKey();
        byte[] first = ("data: synthetic " + key + "\n\n").getBytes(StandardCharsets.UTF_8);
        byte[] padded = new byte[2048];
        System.arraycopy(first, 0, padded, 0, first.length);
        java.util.Arrays.fill(padded, first.length, padded.length, (byte) ' ');
        Frames.Http request = Frames.fixture("openai/web/chat.http", "synthetic hi");
        byte[] frame = Frames.respmod(request, "HTTP/1.1 200 OK\nContent-Type: text/event-stream\n", padded, -1);
        try (IcapTestClient c = new IcapTestClient(port)) {
            c.write(java.util.Arrays.copyOf(frame, frame.length - 5));
            IcapTestClient.Response r = c.read();
            assertTrue(r.bodyText().contains("rwsafe_stream_terminated"));
            assertTrue(c.closedByServer());
        }
    }

    /** D-12: the absolute request target decides the platform, not a conflicting Host header. */
    @Test
    void absoluteTargetWinsOverHost() throws Exception {
        Frames.Http http = rawHttp("POST https://api.anthropic.com./v1/messages HTTP/1.1\nHost: other.example.invalid\n"
            + "Content-Type: application/json\nContent-Length: {{LEN}}\n", "{\"synthetic\":true}");
        assertEquals(204, once(Frames.reqmod(http, -1, true)).status());
        assertEquals("claude", awaitEvent().platform());
    }

    @Test
    void eventToStringHidesIdentity() throws Exception {
        once(Frames.reqmodWithIdentity(Frames.fixture("openai/web/chat.http", "synthetic hi"), "U1lOVEhFVElD", "192.0.2.10"));
        String printed = awaitEvent().toString();
        assertFalse(printed.contains("U1lOVEhFVElD"));
        assertFalse(printed.contains("192.0.2.10"));
    }

    // ---- PR 11 confirmation review (Argon) findings ----

    /** N-01: a previewed response that reaches the finding limit is terminated, never passed. */
    @Test
    void responseAtTheFindingLimitIsTerminated() throws Exception {
        StringBuilder text = new StringBuilder("{\"text\":\"synthetic");
        for (int i = 0; i < 1001; i++) {
            text.append(' ').append(Synthetic.tckn(1000 + i));
        }
        byte[] body = text.append("\"}").toString().getBytes(StandardCharsets.UTF_8);
        Frames.Http request = Frames.fixture("claude/api/messages.http", "synthetic hi");
        IcapTestClient.Response r = once(Frames.respmod(request, "HTTP/1.1 200 OK\nContent-Type: application/json\n"
            + "Content-Length: " + body.length + "\n", body, 65536));
        assertEquals(200, r.status());
        assertTrue(r.bodyText().contains("Yanıt kesildi"));
        assertFalse(r.bodyText().contains(Synthetic.tckn(1000)));
        VerdictEvent e = awaitEvent();
        assertEquals(Verdict.STREAM_ABORTED, e.verdict());
        assertEquals("FINDING_LIMIT", e.reason());
    }

    /** N-02 (1): a multi-byte character split exactly at a window that ends the buffered bytes. */
    @Test
    void characterSplitAtAnExactWindowBoundaryIsCaught() throws Exception {
        String tckn = Synthetic.tckn(41);
        String text = "data: " + "s".repeat(1010) + " " + tckn.substring(0, 6) + "\u200b" + tckn.substring(6) + " end\n\n";
        byte[] body = text.getBytes(StandardCharsets.UTF_8);
        Frames.Http request = Frames.fixture("openai/web/chat.http", "synthetic hi");
        try (IcapTestClient c = new IcapTestClient(port)) {
            c.write(Frames.respmodChunked(request, "HTTP/1.1 200 OK\nContent-Type: text/event-stream\n", body, 1024));
            IcapTestClient.Response r = c.read();
            assertTrue(r.bodyText().contains("rwsafe_stream_terminated"));
            assertFalse(r.bodyText().contains(tckn.substring(6)));
        }
        assertEquals(Verdict.STREAM_ABORTED, awaitEvent().verdict());
    }

    /** N-02 (2): a window of pure format padding cannot release the held window that starts a split value. */
    @Test
    void formatPaddingWindowDoesNotReleaseTheHeldPrefix() throws Exception {
        String tckn = Synthetic.tckn(43);
        String w1 = "data: " + "s".repeat(1024 - 6 - 1 - 6) + " " + tckn.substring(0, 6);
        String text = w1 + "\u200b".repeat(400) + tckn.substring(6) + " end\n\n";
        byte[] body = text.getBytes(StandardCharsets.UTF_8);
        Frames.Http request = Frames.fixture("openai/web/chat.http", "synthetic hi");
        try (IcapTestClient c = new IcapTestClient(port)) {
            c.write(Frames.respmodChunked(request, "HTTP/1.1 200 OK\nContent-Type: text/event-stream\n", body, 1024));
            IcapTestClient.Response r = c.read();
            assertTrue(r.bodyText().contains("rwsafe_stream_terminated"));
            assertFalse(r.bodyText().contains(tckn.substring(0, 6)));
        }
        assertEquals(Verdict.STREAM_ABORTED, awaitEvent().verdict());
    }

    /** N-03: a declared non-UTF-8 charset, NUL-interleaved text and invalid UTF-8 in JSON are not readable. */
    @Test
    void unreadableEncodingsAreNotAllowed() throws Exception {
        String key = Synthetic.awsKey();
        StringBuilder interleaved = new StringBuilder();
        for (char ch : ("synthetic " + key).toCharArray()) {
            interleaved.append(ch).append('\u0000');
        }
        byte[] nul = interleaved.toString().getBytes(StandardCharsets.ISO_8859_1);
        Frames.Http charset = Frames.http("POST /v1/messages HTTP/1.1\nHost: api.anthropic.com\n"
            + "Content-Type: text/plain; charset=utf-16le\nContent-Length: " + nul.length + "\n", nul);
        assertTrue(once(Frames.reqmod(charset, -1, true)).httpHead().startsWith("HTTP/1.1 403"));
        assertEquals("UNSUPPORTED_CHARSET", awaitEvent().reason());
        Frames.Http bare = Frames.http("POST /v1/messages HTTP/1.1\nHost: api.anthropic.com\n"
            + "Content-Type: text/plain\nContent-Length: " + nul.length + "\n", nul);
        assertTrue(once(Frames.reqmod(bare, -1, true)).httpHead().startsWith("HTTP/1.1 403"));
        assertEquals("BINARY", awaitEvent().reason());
        byte[] json = {'{', '"', 's', '"', ':', '"', (byte) 0xff, 'x', '"', '}'};
        Frames.Http badJson = Frames.http("POST /v1/messages HTTP/1.1\nHost: api.anthropic.com\n"
            + "Content-Type: application/json\nContent-Length: " + json.length + "\n", json);
        assertTrue(once(Frames.reqmod(badJson, -1, true)).httpHead().startsWith("HTTP/1.1 403"));
        assertEquals(Verdict.MALFORMED, awaitEvent().verdict());
    }

    /** N-04: "://" inside an origin-form query does not override Host. */
    @Test
    void schemeInsideAQueryDoesNotOverrideHost() throws Exception {
        Frames.Http http = rawHttp("POST /backend-api/conversation?ref=https://api.anthropic.com/x HTTP/1.1\n"
            + "Host: chatgpt.com\nContent-Type: application/json\nContent-Length: {{LEN}}\n", "{\"synthetic\":true}");
        assertEquals(204, once(Frames.reqmod(http, -1, true)).status());
        assertEquals("openai", awaitEvent().platform());
    }
}
