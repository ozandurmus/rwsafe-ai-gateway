package io.rwsafe.dataplane.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.rwsafe.dataplane.boot.IcapServer;
import io.rwsafe.dataplane.events.VerdictEvent;
import io.rwsafe.dataplane.events.VerdictEventJson;
import io.rwsafe.detect.DetectorSet;
import io.rwsafe.platform.verdict.DataClass;
import io.rwsafe.platform.verdict.Verdict;
import io.rwsafe.policy.Action;
import io.rwsafe.policy.PolicySnapshot;
import io.rwsafe.policy.ScopedRule;
import io.rwsafe.policy.Snapshots;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Snapshot format 2 on a real engine, over plain ICAP and over Secure ICAP (POLICY_SNAPSHOT_CONTRACT.md "Format 2: scoped
 * rules", PO decision Q-39, ICAP spec identity row, OFF2-12). The ANY scope is the built-in development policy (SECRET
 * BLOCK, customer identifiers REDACT); three scoped rules sit on top of it.
 */
class ScopedPolicyEndToEndTest {

    /** Stricter than ANY for TCKN, scoped to one group. */
    private static final String STRICT = "tckn.finance@1";
    /** Looser than ANY for SECRET (REDACT instead of BLOCK; never ALLOW or WARN for a fail-closed class). */
    private static final String LOOSE = "secret.devs@1";
    /** Monitor only: would block an IBAN for the finance group. */
    private static final String MONITOR = "iban.watch@1";

    private static final ConcurrentLinkedQueue<VerdictEvent> EVENTS = new ConcurrentLinkedQueue<>();
    private static IcapServer server;
    private static int plainPort;
    private static int securePort;
    private static TestPki pki;

    @TempDir
    static Path tmp;

    private static PolicySnapshot scoped;
    private static final EngineConfig BASE = EngineConfig.defaults().withBodyLimits(64 * 1024, 256L * 1024 * 1024)
        .withTimeouts(2_000, 3_000);

    @BeforeAll
    static void start() throws Exception {
        PolicySnapshot any = Snapshots.builtinDevelopment();
        Map<DataClass, Action> anyActions = new java.util.EnumMap<>(DataClass.class);
        for (DataClass c : DataClass.values()) {
            anyActions.put(c, any.actionFor(c));
        }
        scoped = new PolicySnapshot(2, "registry-synthetic-scoped", anyActions, true, any.platforms(),
            null, List.of(
                new ScopedRule(STRICT, Set.of("finance"), ScopedRule.Mode.ENFORCE, Map.of(DataClass.TCKN, Action.BLOCK)),
                new ScopedRule(LOOSE, Set.of("platform-devs"), ScopedRule.Mode.ENFORCE,
                    Map.of(DataClass.SECRET, Action.REDACT)),
                new ScopedRule(MONITOR, Set.of("finance"), ScopedRule.Mode.MONITOR,
                    Map.of(DataClass.TR_IBAN, Action.BLOCK))));
        EngineConfig config = BASE.withGroupClaimEncoding(EngineConfig.GroupClaimEncoding.PLAIN);
        server = new IcapServer(new IcapEngine(scoped, DetectorSet.standard(), EVENTS::add, config), 0);
        plainPort = server.start("127.0.0.1", 0);
        pki = new TestPki(tmp);
        securePort = server.startSecure("127.0.0.1", 0, pki.serverFiles.chain(), pki.serverFiles.key(),
            pki.serverFiles.caFile());
    }

    @AfterAll
    static void stop() {
        server.close();
    }

    @BeforeEach
    void clearEvents() {
        EVENTS.clear();
    }

    private record Outcome(IcapTestClient.Response response, VerdictEvent event) {
    }

    private static Outcome send(boolean mtls, String groups, String prompt) throws Exception {
        return sendTo(mtls ? securePort : plainPort, mtls, groups, prompt);
    }

    private static Outcome sendTo(int port, boolean mtls, String groups, String prompt) throws Exception {
        Socket socket = mtls ? pki.proxySocket(port) : new Socket("127.0.0.1", port);
        IcapTestClient.Response r;
        try (IcapTestClient c = new IcapTestClient(socket)) {
            c.write(Frames.reqmodWithGroups(Frames.fixture("claude/api/messages.http", prompt), groups));
            r = c.read();
        }
        for (int i = 0; i < 100; i++) {
            VerdictEvent e = EVENTS.poll();
            if (e != null) {
                assertEquals(mtls ? "mtls_verified" : "plain_allowlisted", e.transport());
                return new Outcome(r, e);
            }
            Thread.sleep(20);
        }
        throw new AssertionError("no verdict event");
    }

    private static String tcknPrompt() {
        return "synthetic: customer " + Synthetic.tckn(7) + " asks about fees";
    }

    private static String secretPrompt() {
        return "synthetic: deploy with " + Synthetic.awsKey();
    }

    private static String ibanPrompt() {
        return "synthetic: pay to " + Synthetic.iban(9);
    }

    private static boolean blocked(IcapTestClient.Response r) {
        return r.httpHead().startsWith("HTTP/1.1 403");
    }

    @Test
    void plainConnectionStricterGroupRuleAppliesToAUserWithNoGroup() throws Exception {
        Outcome o = send(false, null, tcknPrompt());
        assertTrue(blocked(o.response()), "TCKN is REDACT for ANY, but the finance rule is stricter");
        assertEquals(Verdict.BLOCK, o.event().verdict());
        assertEquals(List.of(STRICT), o.event().appliedRuleIds());

        Outcome claimed = send(false, "platform-devs", tcknPrompt());
        assertEquals(Verdict.BLOCK, claimed.event().verdict(), "a plain-ICAP group claim selects nothing");
    }

    @Test
    void plainConnectionLooserGroupRuleHasNoEffect() throws Exception {
        Outcome o = send(false, "platform-devs", secretPrompt());
        assertTrue(blocked(o.response()));
        assertEquals(Verdict.BLOCK, o.event().verdict(), "the claim is untrusted: SECRET stays BLOCK");
        assertEquals(List.of(), o.event().appliedRuleIds());
    }

    @Test
    void mutualTlsGroupClaimSelectsTheGroupRule() throws Exception {
        Outcome devs = send(true, " Other-Group , PLATFORM-DEVS", secretPrompt());
        assertEquals(Verdict.REDACT, devs.event().verdict(), "the looser rule applies to its group on Secure ICAP");
        assertFalse(blocked(devs.response()));
        assertFalse(devs.response().bodyText().contains(Synthetic.awsKey()));
        assertEquals(List.of(LOOSE), devs.event().appliedRuleIds());

        Outcome devsTckn = send(true, "platform-devs", tcknPrompt());
        assertEquals(Verdict.REDACT, devsTckn.event().verdict(), "the finance rule does not reach another group");
        assertEquals(List.of(), devsTckn.event().appliedRuleIds());

        Outcome finance = send(true, "finance", tcknPrompt());
        assertEquals(Verdict.BLOCK, finance.event().verdict());
        assertEquals(List.of(STRICT), finance.event().appliedRuleIds());

        Outcome upper = send(true, "OTHER-GROUP, FINANCE", tcknPrompt());
        assertEquals(List.of(STRICT), upper.event().appliedRuleIds(), "one comparison form on both sides (D-02)");
    }

    @Test
    void mutualTlsWithoutAReadableClaimTakesTheStrictest() throws Exception {
        assertEquals(Verdict.BLOCK, send(true, null, secretPrompt()).event().verdict(), "missing header");
        Outcome tckn = send(true, null, tcknPrompt());
        assertEquals(Verdict.BLOCK, tckn.event().verdict());
        assertEquals(List.of(STRICT), tckn.event().appliedRuleIds());
        assertEquals(Verdict.BLOCK, send(true, " , ,", secretPrompt()).event().verdict(), "no group in the header");
    }

    @Test
    void monitorRuleLeavesTheVerdictAndIsReported() throws Exception {
        Outcome finance = send(true, "finance", ibanPrompt());
        assertEquals(Verdict.REDACT, finance.event().verdict());
        assertFalse(blocked(finance.response()));
        assertEquals(List.of(MONITOR), finance.event().monitorRuleIds());
        assertEquals(List.of(), finance.event().appliedRuleIds());

        Outcome plain = send(false, null, ibanPrompt());
        assertEquals(Verdict.REDACT, plain.event().verdict());
        assertEquals(List.of(MONITOR), plain.event().monitorRuleIds());
    }

    @Test
    void eventsCarryRuleIdsNeverGroupNames() throws Exception {
        VerdictEvent e = send(true, "finance,platform-devs", tcknPrompt()).event();
        String json = VerdictEventJson.array(List.of(e));
        assertTrue(json.contains("\"appliedRuleIds\":[\"" + STRICT + "\"]"));
        assertFalse(json.contains("platform-devs"));
        assertFalse(json.contains("\"finance\""));
        assertFalse(e.toString().contains("finance"));

        VerdictEvent clean = send(true, "finance", "synthetic: summarise the release notes").event();
        String cleanJson = VerdictEventJson.array(List.of(clean));
        assertFalse(cleanJson.contains("RuleIds"), "no scoped rule took part: the field set is unchanged");
    }

    // ---- PR 20 second review (Argon) ----

    private static int[] startOther(IcapServer other) throws Exception {
        return new int[] {other.start("127.0.0.1", 0), other.startSecure("127.0.0.1", 0, pki.serverFiles.chain(),
            pki.serverFiles.key(), pki.serverFiles.caFile())};
    }

    /** D-01, Q-1: the encoding is configured; base64 decodes a single all-alphabet group, a plain value is no claim. */
    @Test
    void base64EncodingIsConfiguredNeverGuessed() throws Exception {
        EngineConfig config = BASE.withGroupClaimEncoding(EngineConfig.GroupClaimEncoding.BASE64);
        try (IcapServer other = new IcapServer(new IcapEngine(scoped, DetectorSet.standard(), EVENTS::add, config), 0)) {
            int secure = startOther(other)[1];
            String devs = Base64.getEncoder().encodeToString("platform-devs".getBytes(StandardCharsets.UTF_8));
            Outcome o = sendTo(secure, true, devs, secretPrompt());
            assertEquals(Verdict.REDACT, o.event().verdict(), "the base64 claim selects the looser group rule");
            assertEquals(List.of(LOOSE), o.event().appliedRuleIds());
            String finance = Base64.getEncoder().encodeToString("finance".getBytes(StandardCharsets.UTF_8));
            assertEquals(List.of(STRICT), sendTo(secure, true, finance, tcknPrompt()).event().appliedRuleIds(),
                "a single group of base64-alphabet letters is decoded, never read literally");
            assertEquals(Verdict.BLOCK, sendTo(secure, true, "platform-devs", secretPrompt()).event().verdict(),
                "a value that is not base64 is no claim: strictest");
        }
    }

    /** D-01: unset (or any other value) disables group claims: strictest for everyone, also on Secure ICAP. */
    @Test
    void groupClaimsAreDisabledByDefault() throws Exception {
        try (IcapServer other = new IcapServer(new IcapEngine(scoped, DetectorSet.standard(), EVENTS::add, BASE), 0)) {
            int secure = startOther(other)[1];
            Outcome o = sendTo(secure, true, "platform-devs", secretPrompt());
            assertEquals(Verdict.BLOCK, o.event().verdict());
            assertEquals(List.of(), o.event().appliedRuleIds());
        }
    }

    /** D-06: a streamed response aborted on a finding reports the scoped rules behind the class action. */
    @Test
    void streamedAbortReportsTheRuleIds() throws Exception {
        String tckn = Synthetic.tckn(11);
        byte[] body = ("data: " + "s".repeat(2000) + " customer " + tckn + " end\n\n").getBytes(StandardCharsets.UTF_8);
        Frames.Http request = Frames.fixture("openai/web/chat.http", "synthetic hi");
        try (IcapTestClient c = new IcapTestClient(plainPort)) {
            c.write(Frames.respmodChunked(request, "HTTP/1.1 200 OK\nContent-Type: text/event-stream\n", body, 1024));
            IcapTestClient.Response r = c.read();
            assertFalse(r.bodyText().contains(tckn));
        }
        VerdictEvent e = null;
        for (int i = 0; i < 100 && e == null; i++) {
            e = EVENTS.poll();
            if (e == null) {
                Thread.sleep(20);
            }
        }
        assertEquals(Verdict.STREAM_ABORTED, e.verdict());
        assertEquals(List.of(STRICT), e.appliedRuleIds(), "plain ICAP: the stricter finance rule set TCKN to BLOCK");
        assertEquals(List.of(), e.monitorRuleIds());
    }
}
