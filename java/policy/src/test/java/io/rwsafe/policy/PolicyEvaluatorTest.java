package io.rwsafe.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.rwsafe.platform.verdict.DataClass;
import io.rwsafe.platform.verdict.Finding;
import io.rwsafe.platform.verdict.Verdict;
import java.util.List;
import org.junit.jupiter.api.Test;

class PolicyEvaluatorTest {

    private final PolicySnapshot snapshot = Snapshots.builtinDevelopment();
    private final PolicyEvaluator evaluator = new PolicyEvaluator(snapshot);
    private final FlowClassifier classifier = new FlowClassifier(snapshot);

    @Test
    void secretBeatsRedaction() {
        Decision d = evaluator.onFindings(List.of(new Finding(DataClass.TCKN, 0, 11),
            new Finding(DataClass.SECRET, 20, 40)), true);
        assertEquals(Verdict.BLOCK, d.verdict());
        assertEquals(DataClass.SECRET, d.decidingClass());
    }

    @Test
    void customerDataIsRedactedWhenTheBodyCanBeRewritten() {
        assertEquals(Verdict.REDACT, evaluator.onFindings(List.of(new Finding(DataClass.TCKN, 0, 11)), true).verdict());
        assertEquals(Verdict.BLOCK, evaluator.onFindings(List.of(new Finding(DataClass.TCKN, 0, 11)), false).verdict());
    }

    @Test
    void noFindingAllows() {
        assertEquals(Action.ALLOW, evaluator.onFindings(List.of(), true).action());
    }

    @Test
    void nonVerdictBlocksOnAFailClosedFlow() {
        Decision d = evaluator.onNonVerdict(Verdict.UNINSPECTABLE, "OVERSIZE");
        assertEquals(Action.BLOCK, d.action());
        assertEquals(Verdict.UNINSPECTABLE, d.verdict());
    }

    @Test
    void classifiesPlatformsSurfacesAndSteps() {
        assertEquals(new Flow("openai", Flow.Surface.WEB, Flow.Step.CHAT),
            classifier.classify("chatgpt.com", "POST", "application/json", "Mozilla/5.0"));
        assertEquals(new Flow("claude", Flow.Surface.API, Flow.Step.CHAT),
            classifier.classify("api.anthropic.com:443", "POST", "application/json", "python-httpx"));
        assertEquals(new Flow("claude", Flow.Surface.CLI, Flow.Step.CHAT),
            classifier.classify("api.anthropic.com", "POST", "application/json", "claude-cli/2.0"));
        assertEquals(Flow.Step.LOGIN,
            classifier.classify("login.microsoftonline.com", "POST", "application/x-www-form-urlencoded", "").step());
        assertEquals("unknown", classifier.classify("relay.example.invalid", "POST", "application/json", "").platform());
    }

    @Test
    void isTagIsQuotedAndShort() {
        String tag = snapshot.isTag();
        assertEquals('"', tag.charAt(0));
        assertEquals(true, tag.length() <= 32);
    }
}
