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
        EngineConfig config = new EngineConfig(64 * 1024, 128 * 1024, 1024, 128, 400, 30, 300);
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
}
