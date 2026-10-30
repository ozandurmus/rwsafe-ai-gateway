package io.rwsafe.dataplane.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.dataplane.boot.IcapServer;
import io.rwsafe.dataplane.events.EventSink;
import io.rwsafe.dataplane.events.VerdictEvent;
import io.rwsafe.dataplane.events.VerdictEventJson;
import io.rwsafe.detect.DetectorSet;
import io.rwsafe.platform.verdict.Verdict;
import io.rwsafe.policy.Snapshots;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Redacted capture on the data plane (Q-4 b, ADR-009 C3): only a REDACT verdict whose body the engine rewrote carries
 * content, and that content is the rewrite (class tokens), never the original bytes; a block, an allow and a disabled
 * capture carry none; the bound cuts long rewrites; no event's {@code toString()} prints the content.
 */
class RedactedCaptureEndToEndTest {

    private final ConcurrentLinkedQueue<VerdictEvent> events = new ConcurrentLinkedQueue<>();
    private IcapServer server;
    private int port;

    private void start(int captureBytes) throws InterruptedException {
        EventSink sink = events::add;
        EngineConfig config = EngineConfig.defaults().withBodyLimits(64 * 1024, 256L * 1024 * 1024).withWindow(1024, 128)
            .withTimeouts(400, 3_000).withCapture(captureBytes);
        server = new IcapServer(new IcapEngine(Snapshots.builtinDevelopment(), DetectorSet.standard(), sink, config), 0);
        port = server.start("127.0.0.1", 0);
    }

    @AfterEach
    void stop() {
        if (server != null) {
            server.close();
        }
    }

    private VerdictEvent awaitEvent() throws InterruptedException {
        for (int i = 0; i < 100; i++) {
            VerdictEvent e = events.poll();
            if (e != null) {
                return e;
            }
            Thread.sleep(20);
        }
        throw new AssertionError("no verdict event");
    }

    private VerdictEvent send(String prompt) throws Exception {
        try (IcapTestClient c = new IcapTestClient(port)) {
            c.write(Frames.reqmod(Frames.fixture("claude/api/messages.http", prompt), -1, true));
            c.read();
        }
        return awaitEvent();
    }

    @Test
    void aRedactVerdictCarriesTheRewriteNeverTheOriginal() throws Exception {
        start(EngineConfig.DEFAULT_CAPTURE_BYTES);
        String tckn = Synthetic.tckn(7);
        VerdictEvent e = send("synthetic: customer " + tckn + " asks about fees");
        assertEquals(Verdict.REDACT, e.verdict());
        assertNotNull(e.capture());
        String text = e.capture().text();
        assertTrue(text.contains("[REDACTED:TCKN]"));
        assertTrue(text.contains("asks about fees"));
        assertFalse(text.contains(tckn));
        assertFalse(e.capture().truncated());
        // AGENTS.md 4.14: printing the event or its content holder shows no content.
        assertFalse(e.toString().contains("fees"));
        assertFalse(e.capture().toString().contains("fees"));
        String json = VerdictEventJson.array(List.of(e));
        assertTrue(json.contains("\"capture\":{\"text\":"));
        assertFalse(json.contains(tckn));
    }

    @Test
    void aBlockAnAllowAndCaptureOffCarryNoContent() throws Exception {
        start(EngineConfig.DEFAULT_CAPTURE_BYTES);
        VerdictEvent blocked = send("synthetic deploy with " + Synthetic.awsKey() + " and " + Synthetic.tckn(9));
        assertEquals(Verdict.BLOCK, blocked.verdict());
        assertNull(blocked.capture(), "a secret blocks: nothing travels, the rewrite included");
        VerdictEvent allowed = send("synthetic: summarise the release notes");
        assertEquals(Verdict.ALLOW, allowed.verdict());
        assertNull(allowed.capture(), "an unchanged body is the original bytes: never carried");
        assertFalse(VerdictEventJson.array(List.of(blocked, allowed)).contains("\"capture\""),
            "events without content keep the earlier field set");
        stop();

        start(0);
        VerdictEvent off = send("synthetic: customer " + Synthetic.tckn(11) + " asks about fees");
        assertEquals(Verdict.REDACT, off.verdict());
        assertNull(off.capture(), "capture off: metadata and verdict only");
    }

    @Test
    void theBoundCutsALongRewrite() throws Exception {
        start(64);
        VerdictEvent e = send("synthetic: customer " + Synthetic.tckn(13) + " " + "lorem ".repeat(40));
        assertNotNull(e.capture());
        assertTrue(e.capture().truncated());
        assertTrue(e.capture().text().length() <= 64);
        assertTrue(e.capture().redactedBytes() > 64);
    }

    @Test
    void theCaptureSettingIsExact() {
        assertEquals(0, EngineConfig.captureBytesFromSetting(null, null));
        assertEquals(0, EngineConfig.captureBytesFromSetting("raw", "100"));
        assertEquals(0, EngineConfig.captureBytesFromSetting("REDACTED", null));
        assertEquals(EngineConfig.DEFAULT_CAPTURE_BYTES, EngineConfig.captureBytesFromSetting("redacted", ""));
        assertEquals(4096, EngineConfig.captureBytesFromSetting("redacted", "4096"));
        assertThrows(IllegalArgumentException.class, () -> EngineConfig.captureBytesFromSetting("redacted", "0"));
        assertThrows(IllegalArgumentException.class,
            () -> EngineConfig.captureBytesFromSetting("redacted", String.valueOf(EngineConfig.MAX_CAPTURE_BYTES + 1)));
    }
}
