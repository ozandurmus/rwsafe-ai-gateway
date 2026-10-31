package io.rwsafe.dataplane.boot;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.dataplane.events.VerdictEvent;
import io.rwsafe.dataplane.server.EngineConfig;
import io.rwsafe.dataplane.server.IcapEngine;
import io.rwsafe.detect.DetectorSet;
import io.rwsafe.platform.verdict.DataClass;
import io.rwsafe.platform.verdict.Verdict;
import io.rwsafe.policy.Action;
import io.rwsafe.policy.PolicySnapshot;
import io.rwsafe.policy.Snapshots;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentLinkedQueue;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The synthetic probe against a real engine over TCP (the same harness as the engine's end-to-end tests). */
class IcapProbeTest {

    @TempDir
    Path dir;

    private static IcapServer start(PolicySnapshot snapshot, ConcurrentLinkedQueue<VerdictEvent> events) {
        EngineConfig config = EngineConfig.defaults();
        return new IcapServer(new IcapEngine(snapshot, DetectorSet.standard(), events::add, config),
            config.drainServeMillis());
    }

    @Test
    void everyScenarioHasTheExpectedOutcomeUnderTheSeedActions() throws Exception {
        ConcurrentLinkedQueue<VerdictEvent> events = new ConcurrentLinkedQueue<>();
        IcapServer server = start(Snapshots.builtinDevelopment(), events);
        try {
            int port = server.start("127.0.0.1", 0);
            Path report = dir.resolve("report");
            int code = IcapProbe.execute(Map.of("RWSAFE_PROBE_TARGET", "icap://127.0.0.1:" + port,
                "RWSAFE_PROBE_REPORT", report.toString()));
            String text = Files.readString(report);
            assertEquals(0, code, text);
            assertTrue(text.endsWith("probe result: PASS (7/7 as expected)\n"), text);
            assertEquals(8, text.lines().count());
            // The seed's three actions are all exercised.
            assertTrue(text.contains("expected redact     got redact"), text);
            assertTrue(text.contains("expected block      got block"), text);
            assertTrue(text.contains("expected allow      got allow"), text);
            // The report carries no prompt and no synthetic value.
            assertFalse(text.contains("synthetic"), text);
            assertFalse(text.contains("AK" + "IA"), text);
            assertFalse(text.contains("T" + "R"), text);
        } finally {
            server.close();
        }
        // Six verdict events (OPTIONS makes none), every one under the probe's fixed identity.
        List<VerdictEvent> seen = await(events, 6);
        assertEquals(6, seen.size());
        for (VerdictEvent e : seen) {
            assertEquals(IcapProbe.PROBE_USER, e.userClaim());
            assertEquals(IcapProbe.PROBE_CLIENT, e.clientAddress());
        }
        assertEquals(2, seen.stream().filter(e -> e.verdict() == Verdict.ALLOW).count());
        assertEquals(2, seen.stream().filter(e -> e.verdict() == Verdict.REDACT).count());
        assertEquals(2, seen.stream().filter(e -> e.verdict() == Verdict.BLOCK).count());
    }

    @Test
    void aChangedOutcomeFailsTheProbe() throws Exception {
        PolicySnapshot dev = Snapshots.builtinDevelopment();
        // TCKN blocked instead of redacted (a fail-closed class is never allowed): the TCKN scenario no longer matches.
        PolicySnapshot weakened = new PolicySnapshot(2, "weakened", Map.of(DataClass.SECRET, Action.BLOCK,
            DataClass.TCKN, Action.BLOCK, DataClass.TR_IBAN, Action.REDACT, DataClass.PAYMENT_CARD, Action.REDACT),
            true, dev.platforms());
        IcapServer server = start(weakened, new ConcurrentLinkedQueue<>());
        try {
            int port = server.start("127.0.0.1", 0);
            List<IcapProbe.Result> results = IcapProbe.run("127.0.0.1", port, 5_000, new Random(7));
            List<String> failed = results.stream().filter(r -> !r.passed()).map(IcapProbe.Result::name).toList();
            assertEquals(List.of("claude customer TCKN"), failed);
            IcapProbe.Result tckn = results.stream().filter(r -> r.name().equals("claude customer TCKN")).findFirst()
                .orElseThrow();
            assertEquals(IcapProbe.Outcome.BLOCK, tckn.actual());
            String text = IcapProbe.report(results);
            assertTrue(text.contains("MISMATCH"), text);
            assertTrue(text.endsWith("probe result: FAIL (6/7 as expected)\n"), text);
        } finally {
            server.close();
        }
    }

    @Test
    void anUnreachableEngineIsAnErrorAndExitsNonZero() throws IOException {
        int port;
        try (ServerSocket s = new ServerSocket(0)) {
            port = s.getLocalPort();
        }
        Path report = dir.resolve("report");
        int code = IcapProbe.execute(Map.of("RWSAFE_PROBE_TARGET", "icap://127.0.0.1:" + port,
            "RWSAFE_PROBE_REPORT", report.toString(), "RWSAFE_PROBE_TIMEOUT_MILLIS", "2000"));
        String text = Files.readString(report);
        assertEquals(1, code);
        assertEquals(7, text.lines().filter(l -> l.contains("got error")).count(), text);
        assertTrue(text.endsWith("probe result: FAIL (0/7 as expected)\n"), text);
    }

    /** PR 40 review D-03: a bad setting is named by a fixed token; the configured value never reaches the report. */
    @Test
    void aBadSettingIsRefusedWithAFixedTokenOnly() throws IOException {
        Path report = dir.resolve("report");
        for (String target : List.of("http://127.0.0.1:1344", "icap://synthetic-user:pw@127.0.0.1:1344",
            "icap://[not a host", "icap://127.0.0.1:99999", "icap:///reqmod-ai", "icap://127.0.0.1:1344/?q=synthetic")) {
            assertEquals(1, IcapProbe.execute(Map.of("RWSAFE_PROBE_TARGET", target,
                "RWSAFE_PROBE_REPORT", report.toString())), target);
            assertEquals("probe result: FAIL (configuration: invalid_target)\n", Files.readString(report), target);
        }
        for (String timeout : List.of("x", "0", "-5", "600000", "1e3")) {
            assertEquals(1, IcapProbe.execute(Map.of("RWSAFE_PROBE_TARGET", "icap://127.0.0.1:1344",
                "RWSAFE_PROBE_TIMEOUT_MILLIS", timeout, "RWSAFE_PROBE_REPORT", report.toString())), timeout);
            assertEquals("probe result: FAIL (configuration: invalid_timeout)\n", Files.readString(report), timeout);
        }
    }

    /** PR 40 review D-03: a response cut short is an error, never a truncated answer that could be classified. */
    @Test
    void aTruncatedResponseIsAnError() {
        String head = "ICAP/1.0 200 OK\r\nEncapsulated: req-hdr=0, null-body=40\r\n\r\n";
        byte[] cut = (head + "POST /v1 HTTP/1.1\r\n").getBytes(StandardCharsets.ISO_8859_1);
        assertThrows(IOException.class, () -> new IcapProbe.Reader(new ByteArrayInputStream(cut)).response());
        String chunked = "ICAP/1.0 200 OK\r\nEncapsulated: req-hdr=0, req-body=4\r\n\r\nPOST10\r\nshort";
        assertThrows(IOException.class, () -> new IcapProbe.Reader(
            new ByteArrayInputStream(chunked.getBytes(StandardCharsets.ISO_8859_1))).response());
    }

    @Test
    void aLeakedValueIsNeverARedaction() {
        String value = IcapProbe.tckn(new Random(3));
        IcapProbe.Response leaked = new IcapProbe.Response(200, "ICAP/1.0 200 OK\r\n\r\n",
            "POST /v1/messages HTTP/1.1\r\n",
            ("{\"x\":\"" + value + " " + DataClass.TCKN.redactionToken() + "\"}").getBytes(StandardCharsets.UTF_8));
        assertEquals(IcapProbe.Outcome.OTHER, IcapProbe.classify(leaked, value, DataClass.TCKN.redactionToken()));
        IcapProbe.Response wrongToken = new IcapProbe.Response(200, "ICAP/1.0 200 OK\r\n\r\n",
            "POST /v1/messages HTTP/1.1\r\n", DataClass.TR_IBAN.redactionToken().getBytes(StandardCharsets.UTF_8));
        assertEquals(IcapProbe.Outcome.OTHER, IcapProbe.classify(wrongToken, value, DataClass.TCKN.redactionToken()));
    }

    /** The probe's built-in requests are the committed synthetic fixtures, so replay.py and the probe send the same. */
    @Test
    void builtInRequestsAreTheCommittedFixtures() throws IOException {
        for (Map.Entry<String, String> e : IcapProbe.FIXTURES.entrySet()) {
            try (InputStream in = IcapProbeTest.class.getResourceAsStream("/fixtures/icap/" + e.getKey())) {
                assertTrue(in != null, e.getKey());
                assertEquals(new String(in.readAllBytes(), StandardCharsets.UTF_8), e.getValue(), e.getKey());
            }
        }
        for (IcapProbe.Scenario s : IcapProbe.SCENARIOS) {
            assertTrue(IcapProbe.FIXTURES.containsKey(s.fixture()), s.name());
        }
    }

    @Test
    void syntheticValuesCarryValidChecksums() {
        Random r = new Random(11);
        for (int i = 0; i < 50; i++) {
            String t = IcapProbe.tckn(r);
            assertEquals(11, t.length());
            String iban = IcapProbe.iban(r);
            assertEquals(26, iban.length());
            String rearranged = iban.substring(4) + "2927" + iban.substring(2, 4);
            int rem = 0;
            for (char c : rearranged.toCharArray()) {
                rem = (rem * 10 + (c - '0')) % 97;
            }
            assertEquals(1, rem, "IBAN mod 97");
        }
    }

    private static List<VerdictEvent> await(ConcurrentLinkedQueue<VerdictEvent> events, int n)
        throws InterruptedException {
        List<VerdictEvent> out = new ArrayList<>();
        for (int i = 0; i < 200 && out.size() < n; i++) {
            VerdictEvent e = events.poll();
            if (e == null) {
                Thread.sleep(20);
            } else {
                out.add(e);
            }
        }
        return out;
    }
}
