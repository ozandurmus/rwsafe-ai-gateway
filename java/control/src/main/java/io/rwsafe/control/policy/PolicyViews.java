package io.rwsafe.control.policy;

import io.rwsafe.control.privacy.MaskedView;
import io.rwsafe.control.privacy.TextMasker;
import io.rwsafe.persistence.PolicyRuleVersion;
import io.rwsafe.persistence.PolicySnapshotStore.IssuedSnapshot;
import io.rwsafe.platform.verdict.Verdict;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The registry API's response types. A rule holds vocabulary, vendor host names and pseudonyms (the author and the
 * approvers are {@code USR-} pseudonyms or {@code system:} actors), never a prompt or an estate name; the masked
 * projection still passes every host and id through the text masker so the estate dictionary applies.
 */
public final class PolicyViews {

    private PolicyViews() {
    }

    public record ApprovalView(String role, String approver, Instant approvedAt) {
    }

    /** One rule version; {@code inSnapshot} is true when the latest issued snapshot compiled it. */
    public record VersionView(String ruleId, int version, String action, Boolean enforceFailClosed,
                              List<String> hostSuffixes, List<String> apiHosts, List<String> loginHosts, String mode,
                              String rolloutStage, String status, String source, String author, String reasonCode,
                              Instant createdAt, Instant activatedAt, Instant supersededAt,
                              List<ApprovalView> approvals, boolean inSnapshot) implements MaskedView {

        static VersionView of(PolicyRuleVersion v, Set<String> inSnapshot) {
            return new VersionView(v.ruleId(), v.version(), v.action(), v.enforceFailClosed(), v.hostSuffixes(),
                v.apiHosts(), v.loginHosts(), v.mode(), v.rolloutStage(), v.status(), v.source(), v.authorFingerprint(),
                v.reasonCode(), v.createdAt(), v.activatedAt(), v.supersededAt(), v.approvals().stream()
                    .map(a -> new ApprovalView(a.role(), a.approverFingerprint(), a.approvedAt())).toList(),
                inSnapshot.contains(v.key()));
        }

        @Override
        public VersionView masked(TextMasker m) {
            return new VersionView(m.mask(ruleId), version, action, enforceFailClosed, mask(m, hostSuffixes),
                mask(m, apiHosts), mask(m, loginHosts), mode, rolloutStage, status, source, author, reasonCode, createdAt,
                activatedAt, supersededAt, approvals, inSnapshot);
        }
    }

    /**
     * One rule with every version, newest first. {@code subject} is the class name, the platform id or
     * {@code ai-category}; {@code failClosed} rules never take ALLOW or WARN, nor an exception.
     */
    public record RuleView(String ruleId, String kind, String subject, boolean failClosed, List<VersionView> versions) {

        RuleView masked(TextMasker m) {
            return new RuleView(m.mask(ruleId), kind, m.mask(subject), failClosed,
                versions.stream().map(v -> v.masked(m)).toList());
        }
    }

    /** The latest issued snapshot as the screens show it (the document itself is served to the data plane only). */
    public record SnapshotView(long version, String id, Instant issuedAt, String documentSha256,
                               List<String> ruleVersions, List<String> approvers, String keyId) {

        static SnapshotView of(IssuedSnapshot s, String keyId) {
            return new SnapshotView(s.version(), s.snapshotId(), s.issuedAt(), s.documentSha256(), s.ruleVersions(),
                s.approvers(), keyId);
        }
    }

    public record RegistryView(List<RuleView> rules, SnapshotView snapshot, List<String> failClosedClasses,
                               List<String> actions, List<String> modes, List<String> stages) implements MaskedView {

        static RegistryView of(List<PolicyRuleVersion> versions, IssuedSnapshot latest, String keyId) {
            Set<String> compiled = latest == null ? Set.of() : Set.copyOf(latest.ruleVersions());
            Map<String, List<PolicyRuleVersion>> byRule = new LinkedHashMap<>();
            for (PolicyRuleVersion v : versions) {
                byRule.computeIfAbsent(v.ruleId(), k -> new ArrayList<>()).add(v);
            }
            List<RuleView> rules = new ArrayList<>();
            for (var e : byRule.entrySet()) {
                PolicyRuleVersion first = e.getValue().get(0);
                String subject = switch (first.kind()) {
                    case RegistryVocabulary.KIND_CLASS -> first.dataClass();
                    case RegistryVocabulary.KIND_PLATFORM -> first.platformId();
                    default -> e.getKey().substring("flow.".length());
                };
                rules.add(new RuleView(e.getKey(), first.kind(), subject, RegistryVocabulary.failClosedRule(e.getKey()),
                    e.getValue().stream().map(v -> VersionView.of(v, compiled)).toList()));
            }
            return new RegistryView(rules, latest == null ? null : SnapshotView.of(latest, keyId),
                RegistryVocabulary.failClosedClasses(), RegistryVocabulary.ACTIONS, RegistryVocabulary.MODES,
                RegistryVocabulary.STAGES);
        }

        @Override
        public RegistryView masked(TextMasker m) {
            return new RegistryView(rules.stream().map(r -> r.masked(m)).toList(), snapshot, failClosedClasses, actions,
                modes, stages);
        }
    }

    public record TransitionView(Verdict from, Verdict to, long events) {
    }

    /** The simulation stub's answer: counts and vocabulary only. */
    public record SimulationView(String ruleId, String dataClass, String currentAction, String proposedAction,
                                 Instant from, Instant to, long eventsInWindow, long eventsWithClass,
                                 long eventsChanged, long eventsNotReevaluated, List<TransitionView> transitions)
        implements MaskedView {

        static SimulationView of(PolicyRegistryService.Simulation s) {
            return new SimulationView(s.ruleId(), s.dataClass(), s.currentAction(), s.proposedAction(), s.from(), s.to(),
                s.eventsInWindow(), s.eventsWithClass(), s.eventsChanged(), s.eventsNotReevaluated(),
                s.transitions().stream().map(t -> new TransitionView(t.from(), t.to(), t.events())).toList());
        }

        @Override
        public SimulationView masked(TextMasker m) {
            return this;
        }
    }

    private static List<String> mask(TextMasker m, List<String> values) {
        return values == null ? null : values.stream().map(m::mask).toList();
    }
}
