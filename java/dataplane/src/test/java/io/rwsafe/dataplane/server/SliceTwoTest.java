package io.rwsafe.dataplane.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import io.rwsafe.dataplane.boot.IcapServer;
import io.rwsafe.dataplane.controlplane.EventShipper;
import io.rwsafe.dataplane.controlplane.SnapshotPoller;
import io.rwsafe.dataplane.events.BoundedEventQueue;
import io.rwsafe.dataplane.events.EventSink;
import io.rwsafe.dataplane.events.VerdictEvent;
import io.rwsafe.dataplane.metrics.PrometheusText;
import io.rwsafe.detect.DetectorSet;
import io.rwsafe.platform.verdict.Verdict;
import io.rwsafe.policy.SnapshotVerifier;
import io.rwsafe.policy.Snapshots;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** MVP slice 2: signed policy pull, admission, drain, event backpressure and spool, metrics, Secure ICAP. */
class SliceTwoTest {

    @TempDir
    Path tmp;

    private static final EngineConfig BASE = EngineConfig.defaults().withBodyLimits(64 * 1024, 256L * 1024 * 1024)
        .withTimeouts(2_000, 3_000);

    // ---- signed snapshots (POLICY_SNAPSHOT_CONTRACT.md) ----

    private static String snapshotJson(long version, Instant issuedAt, String tcknAction) {
        return "{\"format\":1,\"version\":" + version + ",\"id\":\"registry-synthetic\",\"issuedAt\":\"" + issuedAt
            + "\",\"enforceFailClosed\":true,\"classActions\":{\"SECRET\":\"BLOCK\",\"TCKN\":\"" + tcknAction
            + "\",\"TR_IBAN\":\"REDACT\",\"PAYMENT_CARD\":\"REDACT\"},\"platforms\":[{\"platform\":\"claude\","
            + "\"hostSuffixes\":[\"anthropic.com\"],\"apiHosts\":[\"api.anthropic.com\"],\"loginHosts\":[]}]}";
    }

    private static String sign(KeyPair kp, byte[] body) throws Exception {
        Signature s = Signature.getInstance("Ed25519");
        s.initSign(kp.getPrivate());
        s.update(body);
        return "ed25519:" + Base64.getEncoder().encodeToString(s.sign());
    }

    private static String pem(PublicKey key) {
        return "-----BEGIN PUBLIC KEY-----\n" + Base64.getMimeEncoder().encodeToString(key.getEncoded())
            + "\n-----END PUBLIC KEY-----\n";
    }

    /** A control plane stand-in that serves whatever body and signature the test sets. */
    private static final class FakeControlPlane implements AutoCloseable {
        final HttpServer http;
        final AtomicReference<byte[]> body = new AtomicReference<>();
        final AtomicReference<String> signature = new AtomicReference<>();
        final AtomicInteger eventStatus = new AtomicInteger(200);
        final ConcurrentLinkedQueue<String> eventBatches = new ConcurrentLinkedQueue<>();

        FakeControlPlane() throws IOException {
            http = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 8);
            http.createContext("/internal/v1/policy/snapshot", ex -> {
                byte[] b = body.get();
                ex.getResponseHeaders().set("X-RWSAFE-Key-Id", "k1");
                ex.getResponseHeaders().set("X-RWSAFE-Signature", signature.get());
                ex.sendResponseHeaders(200, b.length);
                try (OutputStream out = ex.getResponseBody()) {
                    out.write(b);
                }
            });
            http.createContext("/internal/v1/verdict-events", ex -> {
                byte[] b = ex.getRequestBody().readAllBytes();
                int status = eventStatus.get();
                if (status == 200) {
                    eventBatches.add(new String(b, StandardCharsets.UTF_8));
                }
                ex.sendResponseHeaders(status, -1);
                ex.close();
            });
            http.start();
        }

        URI uri(String path) {
            return URI.create("http://127.0.0.1:" + http.getAddress().getPort() + path);
        }

        @Override
        public void close() {
            http.stop(0);
        }
    }

    @Test
    void signedSnapshotMakesTheEngineReadyAndOnlyMovesForward() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        Instant now = Instant.parse("2026-10-30T18:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        IcapEngine engine = new IcapEngine(null, DetectorSet.standard(), e -> { }, BASE);
        try (FakeControlPlane cp = new FakeControlPlane(); IcapServer server = new IcapServer(engine, 0)) {
            int port = server.start("127.0.0.1", 0);
            try (IcapTestClient c = new IcapTestClient(port)) {
                c.write(Frames.options("/reqmod-ai"));
                assertEquals(503, c.read().status(), "not ready before the first snapshot");
            }
            SnapshotVerifier verifier = new SnapshotVerifier(Map.of("k1", SnapshotVerifier.publicKeyFromPem(pem(kp.getPublic()))));
            SnapshotPoller poller = new SnapshotPoller(engine, cp.uri("/internal/v1/policy/snapshot"), verifier,
                tmp.resolve("cache"), clock, Duration.ofSeconds(30));

            byte[] v5 = snapshotJson(5, now.minusSeconds(60), "BLOCK").getBytes(StandardCharsets.UTF_8);
            cp.body.set(v5);
            cp.signature.set(sign(kp, v5));
            poller.pollOnce();
            assertEquals(5, engine.policy().snapshot().version());
            String tag;
            try (IcapTestClient c = new IcapTestClient(port)) {
                c.write(Frames.options("/reqmod-ai"));
                IcapTestClient.Response r = c.read();
                assertEquals(200, r.status());
                tag = r.header("ISTag");
            }
            // TCKN is BLOCK in v5: the decision follows the pulled policy, not the built-in one.
            try (IcapTestClient c = new IcapTestClient(port)) {
                c.write(Frames.reqmod(Frames.fixture("claude/api/messages.http", "synthetic " + Synthetic.tckn(3)), -1, true));
                assertTrue(c.read().httpHead().startsWith("HTTP/1.1 403"));
            }

            byte[] v4 = snapshotJson(4, now.minusSeconds(30), "REDACT").getBytes(StandardCharsets.UTF_8);
            cp.body.set(v4);
            cp.signature.set(sign(kp, v4));
            poller.pollOnce();
            assertEquals(5, engine.policy().snapshot().version(), "an older signed snapshot never loads (OFF2-11)");

            byte[] v6 = snapshotJson(6, now.minusSeconds(10), "REDACT").getBytes(StandardCharsets.UTF_8);
            cp.body.set(v6);
            cp.signature.set(sign(kp, snapshotJson(7, now, "REDACT").getBytes(StandardCharsets.UTF_8)));
            poller.pollOnce();
            assertEquals(5, engine.policy().snapshot().version(), "a body that does not match its signature never loads");

            byte[] weak = snapshotJson(8, now, "ALLOW").getBytes(StandardCharsets.UTF_8);
            cp.body.set(weak);
            cp.signature.set(sign(kp, weak));
            poller.pollOnce();
            assertEquals(5, engine.policy().snapshot().version(), "a fail-closed class cannot be weakened");

            byte[] stale = snapshotJson(9, now.minus(Duration.ofHours(25)), "REDACT").getBytes(StandardCharsets.UTF_8);
            cp.body.set(stale);
            cp.signature.set(sign(kp, stale));
            poller.pollOnce();
            assertEquals(5, engine.policy().snapshot().version(), "a stale snapshot never loads");

            cp.body.set(v6);
            cp.signature.set(sign(kp, v6));
            poller.pollOnce();
            assertEquals(6, engine.policy().snapshot().version());
            try (IcapTestClient c = new IcapTestClient(port)) {
                c.write(Frames.options("/reqmod-ai"));
                assertNotEquals(tag, c.read().header("ISTag"), "ISTag changes with the policy");
            }
            Map<String, Long> refused = poller.refusals();
            assertEquals(1L, refused.get("NOT_NEWER"));
            assertEquals(1L, refused.get("BAD_SIGNATURE"));
            assertEquals(1L, refused.get("FAIL_CLOSED_WEAKENED"));
            assertEquals(1L, refused.get("STALE"));

            IcapEngine restarted = new IcapEngine(null, DetectorSet.standard(), e -> { }, BASE);
            new SnapshotPoller(restarted, cp.uri("/nowhere"), verifier, tmp.resolve("cache"), clock,
                Duration.ofSeconds(30)).loadCache();
            assertEquals(6, restarted.policy().snapshot().version(), "the cached snapshot is verified and used at start");
        }
    }

    // ---- admission (OFF2-10, PLAT-F1) ----

    @Test
    void oneIdentityCannotExhaustThePool() throws Exception {
        ConcurrentLinkedQueue<VerdictEvent> events = new ConcurrentLinkedQueue<>();
        EngineConfig config = BASE.withAdmission(100, 1, 4, List.of());
        IcapEngine engine = new IcapEngine(Snapshots.builtinDevelopment(), DetectorSet.standard(), events::add, config);
        try (IcapServer server = new IcapServer(engine, 0)) {
            int port = server.start("127.0.0.1", 0);
            byte[] held = Frames.reqmodWithIdentity(Frames.fixture("claude/api/messages.http", "synthetic hold"),
                "U1lOVEhFVElDLWE=", "192.0.2.10");
            try (IcapTestClient a1 = new IcapTestClient(port)) {
                a1.write(java.util.Arrays.copyOf(held, held.length - 10));
                Thread.sleep(150);
                try (IcapTestClient a2 = new IcapTestClient(port)) {
                    a2.write(held);
                    assertTrue(a2.read().httpHead().startsWith("HTTP/1.1 403"), "the second transaction of A is capped");
                }
                try (IcapTestClient b = new IcapTestClient(port)) {
                    b.write(Frames.reqmodWithIdentity(Frames.fixture("claude/api/messages.http", "synthetic b"),
                        "U1lOVEhFVElDLWI=", "192.0.2.11"));
                    assertEquals(204, b.read().status(), "another identity is unaffected");
                }
            }
            assertTrue(events.stream().anyMatch(e -> "IDENTITY_LIMIT".equals(e.reason())));
            assertEquals(1, engine.admission().identityCapped());
        }
    }

    @Test
    void bodyBudgetExhaustionAnswers503() throws Exception {
        EngineConfig config = BASE.withBodyLimits(64 * 1024, 2 * 1024);
        IcapEngine engine = new IcapEngine(Snapshots.builtinDevelopment(), DetectorSet.standard(), e -> { }, config);
        try (IcapServer server = new IcapServer(engine, 0)) {
            int port = server.start("127.0.0.1", 0);
            try (IcapTestClient c = new IcapTestClient(port)) {
                c.write(Frames.reqmod(Frames.fixture("claude/api/messages.http", "synthetic ".repeat(500)), -1, true));
                assertEquals(503, c.read().status());
                assertTrue(c.closedByServer());
            }
            assertEquals(0, engine.admission().bodyBytesHeld(), "reserved bytes are released");
            assertEquals(0, engine.admission().inflight());
        }
    }

    // ---- drain (ICAP spec §7) ----

    @Test
    void drainingServesWithConnectionCloseThenRefuses() throws Exception {
        IcapEngine engine = new IcapEngine(Snapshots.builtinDevelopment(), DetectorSet.standard(), e -> { },
            BASE.withDrainServeMillis(400));
        try (IcapServer server = new IcapServer(engine, 400)) {
            int port = server.start("127.0.0.1", 0);
            engine.startDraining();
            try (IcapTestClient c = new IcapTestClient(port)) {
                c.write(Frames.options("/reqmod-ai"));
                assertEquals(503, c.read().status(), "OPTIONS deselects the engine at once");
            }
            try (IcapTestClient c = new IcapTestClient(port)) {
                c.write(Frames.reqmod(Frames.fixture("openai/web/chat.http", "synthetic hi"), -1, true));
                IcapTestClient.Response r = c.read();
                assertEquals(204, r.status(), "transactions are still served during the window");
                assertEquals("close", r.header("Connection"));
                assertTrue(c.closedByServer());
            }
            Thread.sleep(500);
            try (IcapTestClient c = new IcapTestClient(port)) {
                c.write(Frames.reqmod(Frames.fixture("openai/web/chat.http", "synthetic hi"), -1, true));
                assertEquals(503, c.read().status(), "after the window new transactions are refused");
            }
        }
    }

    // ---- event backpressure and spool (SR-DP-12, ADR-010 §3) ----

    @Test
    void saturatedEventPathBlocksFailClosedFlows() throws Exception {
        EventSink full = new EventSink() {
            @Override
            public void emit(VerdictEvent event) {
            }

            @Override
            public boolean saturated() {
                return true;
            }
        };
        IcapEngine engine = new IcapEngine(Snapshots.builtinDevelopment(), DetectorSet.standard(), full, BASE);
        try (IcapServer server = new IcapServer(engine, 0)) {
            int port = server.start("127.0.0.1", 0);
            try (IcapTestClient c = new IcapTestClient(port)) {
                c.write(Frames.reqmod(Frames.fixture("openai/web/chat.http", "synthetic hi"), -1, true));
                assertTrue(c.read().httpHead().startsWith("HTTP/1.1 403"));
            }
            assertEquals(1, engine.metrics().transactions(io.rwsafe.dataplane.metrics.EngineMetrics.Method.REQMOD,
                Verdict.INSPECTION_FAILED));
        }
    }

    @Test
    void eventsSpoolDuringAnOutageAndReplayInOrder() throws Exception {
        try (FakeControlPlane cp = new FakeControlPlane()) {
            cp.eventStatus.set(503);
            BoundedEventQueue queue = new BoundedEventQueue(100);
            EventShipper shipper = new EventShipper(queue, cp.uri("/internal/v1/verdict-events"), tmp.resolve("spool"),
                1024 * 1024, Duration.ofMillis(20));
            Thread t = new Thread(shipper);
            t.start();
            for (int i = 0; i < 3; i++) {
                queue.emit(event("first-" + i));
            }
            long deadline = System.currentTimeMillis() + 5_000;
            while (shipper.spoolBytes() == 0 && System.currentTimeMillis() < deadline) {
                Thread.sleep(20);
            }
            assertTrue(shipper.spoolBytes() > 0, "an outage spools instead of dropping");
            queue.emit(event("second"));
            Thread.sleep(200);
            cp.eventStatus.set(200);
            deadline = System.currentTimeMillis() + 5_000;
            while ((shipper.spoolBytes() > 0 || queue.size() > 0 || cp.eventBatches.size() < 2)
                && System.currentTimeMillis() < deadline) {
                Thread.sleep(20);
            }
            shipper.stop();
            t.join(2_000);
            List<String> all = new ArrayList<>(cp.eventBatches);
            String joined = String.join("\n", all);
            assertTrue(joined.indexOf("first-0") >= 0 && joined.indexOf("first-0") < joined.indexOf("second"),
                "spooled events are replayed before newer ones");
            assertEquals(0, shipper.spoolBytes());
            assertFalse(Files.exists(tmp.resolve("spool").resolve("verdict-spool.jsonl")));
        }
    }

    private static VerdictEvent event(String correlation) {
        return new VerdictEvent(UUID.randomUUID(), Instant.now(), "reqmod", "claude", "api", "chat", Verdict.ALLOW, null,
            Map.of(), 10, 5, null, null, "plain_allowlisted", 1, correlation, List.of(), List.of());
    }

    // ---- metrics (ICAP spec §8) ----

    @Test
    void metricsCarryOnlyFixedLabels() throws Exception {
        ConcurrentLinkedQueue<VerdictEvent> events = new ConcurrentLinkedQueue<>();
        IcapEngine engine = new IcapEngine(Snapshots.builtinDevelopment(), DetectorSet.standard(), events::add, BASE);
        try (IcapServer server = new IcapServer(engine, 0)) {
            int port = server.start("127.0.0.1", 0);
            try (IcapTestClient c = new IcapTestClient(port)) {
                c.write(Frames.reqmodWithIdentity(Frames.fixture("openai/web/chat.http", "synthetic " + Synthetic.awsKey()),
                    "U1lOVEhFVElDLW0=", "192.0.2.12"));
                c.read();
            }
            Thread.sleep(100);
            String text = PrometheusText.render(engine.metrics(), new PrometheusText.Gauges(0, 0, 0, 0, 0, 0, 0, 0,
                1, true, Map.of("NOT_NEWER", 1L)));
            assertTrue(text.contains("icap_transactions_total{method=\"reqmod\",verdict=\"BLOCK\"} 1"));
            assertFalse(text.contains("U1lOVEhFVElDLW0="));
            assertFalse(text.contains("192.0.2.12"));
            assertFalse(text.contains("chatgpt"));
        }
    }

    // ---- Secure ICAP (ICAP spec §2) ----

    @Test
    void secureIcapRequiresTheProxyCertificateAndMarksTheTransport() throws Exception {
        TestPki pki = new TestPki(tmp);

        ConcurrentLinkedQueue<VerdictEvent> events = new ConcurrentLinkedQueue<>();
        IcapEngine engine = new IcapEngine(Snapshots.builtinDevelopment(), DetectorSet.standard(), events::add, BASE);
        try (IcapServer server = new IcapServer(engine, 0)) {
            int port = server.startSecure("127.0.0.1", 0, pki.serverFiles.chain(), pki.serverFiles.key(),
                pki.serverFiles.caFile());

            try (IcapTestClient c = new IcapTestClient(pki.proxySocket(port))) {
                c.write(Frames.reqmod(Frames.fixture("openai/web/chat.http", "synthetic hi"), -1, true));
                assertEquals(204, c.read().status());
            }
            Thread.sleep(100);
            assertEquals("mtls_verified", events.peek().transport());

            SSLSocket noCert = pki.anonymousSocket(port);
            assertThrows(IOException.class, () -> {
                noCert.startHandshake();
                try (IcapTestClient c = new IcapTestClient(noCert)) {
                    c.write(Frames.options("/reqmod-ai"));
                    c.read();
                }
            }, "a client without the proxy certificate is refused");
            noCert.close();
            Socket plain = new Socket("127.0.0.1", port);
            try (IcapTestClient c = new IcapTestClient(plain)) {
                c.write(Frames.options("/reqmod-ai"));
                assertThrows(IOException.class, c::read, "plain ICAP is not served on the TLS listener");
            }
        }
    }
}
