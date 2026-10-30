package io.rwsafe.control.policy;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.rwsafe.persistence.PolicyRuleVersion;
import io.rwsafe.persistence.PolicySnapshotStore;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.springframework.http.HttpStatus;

/**
 * Compiles the registry's active versions into the snapshot document of POLICY_SNAPSHOT_CONTRACT, format 2 (PO decision
 * Q-39). {@code classActions}, the flow and the platform rows come from the active {@code enforce} versions with scope
 * {@code ANY} at rollout stage {@code all} (a legacy staged row stays out, as in format 1); {@code scopedRules} come from
 * the active group-scoped class versions, {@code enforce} and {@code monitor}, each with its id
 * {@code <rule id>@<version>}, its groups, its mode and the partial class map it sets, ordered by rule id and version so
 * the same registry yields the same bytes. An {@code ANY} {@code monitor} version is simulation only. The compiler
 * refuses (and nothing is issued) when a DLP class or the flow has no baseline, when a fail-closed class would be ALLOW
 * or WARN in any scope (the data plane refuses such a snapshot whatever {@code enforceFailClosed} says), when the flow
 * is relaxed, when the platform rows are defective, or when a scoped rule breaks the contract's shape. Group names are
 * operator data: no refusal message names one.
 */
public final class SnapshotCompiler implements PolicySnapshotStore.Compiler {

    public static final int FORMAT = 2;
    /** POLICY_SNAPSHOT_CONTRACT format 2: at most 256 scoped rules, each with 1 to 32 groups of 1 to 256 characters. */
    public static final int MAX_SCOPED_RULES = 256;
    public static final int MAX_SCOPE_GROUPS = GroupNames.MAX_GROUPS;
    /** A scoped rule id ({@code <rule id>@<version>}) is at most 128 characters (the data plane's bound). */
    public static final int MAX_RULE_ID_LENGTH = 128;
    private static final ObjectMapper JSON = new ObjectMapper();

    @Override
    public PolicySnapshotStore.Compiled compile(List<PolicyRuleVersion> active) {
        List<PolicyRuleVersion> baseline = active.stream()
            .filter(v -> "active".equals(v.status()) && "enforce".equals(v.mode()) && "all".equals(v.rolloutStage())
                && !v.scopedToGroups())
            .sorted(Comparator.comparing(PolicyRuleVersion::ruleId)).toList();
        List<PolicyRuleVersion> scoped = active.stream()
            .filter(v -> "active".equals(v.status()) && "all".equals(v.rolloutStage()) && v.scopedToGroups())
            .sorted(Comparator.comparing(PolicyRuleVersion::ruleId).thenComparingInt(PolicyRuleVersion::version))
            .toList();

        Map<String, Object> classActions = new LinkedHashMap<>();
        for (String dataClass : RegistryVocabulary.failClosedClasses()) {
            PolicyRuleVersion v = baseline.stream().filter(r -> ("class." + dataClass).equals(r.ruleId())).findFirst()
                .orElseThrow(() -> incomplete("a DLP class has no active enforce baseline"));
            if (!RegistryVocabulary.ACTIONS.contains(v.action())) {
                throw incomplete("a DLP class has an unknown action");
            }
            if (RegistryVocabulary.RELAXING_ACTIONS.contains(v.action())) {
                throw new RegistryRefusal(HttpStatus.SERVICE_UNAVAILABLE, "SNAPSHOT_FAIL_CLOSED_RELAXED",
                    "A fail-closed class would be ALLOW or WARN; no snapshot is compiled.");
            }
            classActions.put(dataClass, v.action());
        }
        PolicyRuleVersion flow = baseline.stream().filter(r -> RegistryVocabulary.FLOW_RULE.equals(r.ruleId()))
            .findFirst().orElseThrow(() -> incomplete("the AI-category flow has no active enforce baseline"));
        if (!Boolean.TRUE.equals(flow.enforceFailClosed())) {
            throw new RegistryRefusal(HttpStatus.SERVICE_UNAVAILABLE, "SNAPSHOT_FAIL_CLOSED_RELAXED",
                "The AI-category flow would not be fail-closed; no snapshot is compiled.");
        }
        List<PlatformRow> rows = baseline.stream().filter(r -> RegistryVocabulary.KIND_PLATFORM.equals(r.kind()))
            .map(r -> new PlatformRow(r.platformId(), r.hostSuffixes(), r.apiHosts(), r.loginHosts())).toList();
        if (rows.isEmpty()) {
            throw incomplete("no platform row is active");
        }
        List<Map<String, Object>> scopedRules = scopedRules(scoped);
        List<PolicyRuleVersion> compiled = new ArrayList<>(baseline);
        compiled.addAll(scoped);
        // PR 16 review D-01: every compiled version is the fixture's seed or carries its two approvals, whatever the
        // database says about its status.
        for (PolicyRuleVersion v : compiled) {
            if (!approved(v)) {
                throw new RegistryRefusal(HttpStatus.SERVICE_UNAVAILABLE, "SNAPSHOT_APPROVAL_MISSING",
                    "An active rule version has neither the seed's provenance nor two approvals; no snapshot is "
                        + "compiled.");
            }
        }
        String defect = PlatformRow.defect(rows);
        if (defect != null) {
            throw incomplete("the platform rows are defective: " + defect);
        }
        List<Map<String, Object>> platforms = new ArrayList<>();
        for (PlatformRow r : rows) {
            Map<String, Object> p = new LinkedHashMap<>();
            p.put("platform", r.platform());
            p.put("hostSuffixes", r.hostSuffixes());
            p.put("apiHosts", r.apiHosts());
            p.put("loginHosts", r.loginHosts());
            platforms.add(p);
        }

        Map<String, Object> content = new LinkedHashMap<>();
        content.put("enforceFailClosed", true);
        content.put("classActions", classActions);
        content.put("platforms", platforms);
        content.put("scopedRules", scopedRules);
        String digest = sha256(write(content));
        List<String> ruleVersions = compiled.stream().map(PolicyRuleVersion::key).toList();
        TreeSet<String> approvers = new TreeSet<>();
        for (PolicyRuleVersion v : compiled) {
            if (v.approvals().isEmpty()) {
                approvers.add(v.authorFingerprint());
            } else {
                v.approvals().forEach(a -> approvers.add(a.approverFingerprint()));
            }
        }
        return new Compiled(digest, ruleVersions, List.copyOf(approvers), content);
    }

    private record Compiled(String rulesDigest, List<String> ruleVersions, List<String> approvers,
                            Map<String, Object> content) implements PolicySnapshotStore.Compiled {

        @Override
        public PolicySnapshotStore.Rendered render(long version, Instant issuedAt) {
            String id = "registry-" + rulesDigest.substring(0, 12);
            Map<String, Object> doc = new LinkedHashMap<>();
            doc.put("format", FORMAT);
            doc.put("version", version);
            doc.put("id", id);
            doc.put("issuedAt", issuedAt.truncatedTo(ChronoUnit.SECONDS).toString());
            doc.putAll(content);
            return new PolicySnapshotStore.Rendered(id, write(doc));
        }
    }

    /**
     * The format 2 {@code scopedRules}: one entry per active group-scoped class version, with its groups trimmed and
     * ordered case-insensitively (then by their exact text), so the order the operator typed them never changes the
     * bytes.
     */
    private static List<Map<String, Object>> scopedRules(List<PolicyRuleVersion> scoped) {
        if (scoped.size() > MAX_SCOPED_RULES) {
            throw incomplete("more than " + MAX_SCOPED_RULES + " group-scoped rules are active");
        }
        List<Map<String, Object>> out = new ArrayList<>();
        Set<String> ids = new HashSet<>();
        for (PolicyRuleVersion v : scoped) {
            // A scoped rule sets at least one class: a class rule always names its class and action.
            if (!RegistryVocabulary.KIND_CLASS.equals(v.kind()) || !RegistryVocabulary.ACTIONS.contains(v.action())
                || v.dataClass() == null || !v.ruleId().equals("class." + v.dataClass())
                || RegistryVocabulary.dataClassOf(v.ruleId()) == null || !RegistryVocabulary.MODES.contains(v.mode())) {
                throw incomplete("a group-scoped rule is not a DLP class rule with a known action and mode");
            }
            if (RegistryVocabulary.failClosedClass(v.dataClass())
                && RegistryVocabulary.RELAXING_ACTIONS.contains(v.action())) {
                throw new RegistryRefusal(HttpStatus.SERVICE_UNAVAILABLE, "SNAPSHOT_FAIL_CLOSED_RELAXED",
                    "A fail-closed class would be ALLOW or WARN for a group; no snapshot is compiled.");
            }
            List<String> groups = groups(v.scopeGroups());
            if (groups == null) {
                throw incomplete("a group-scoped rule has an invalid group list");
            }
            String id = v.ruleId() + "@" + v.version();
            if (id.length() > MAX_RULE_ID_LENGTH || !ids.add(id)) {
                throw incomplete("a scoped rule id is repeated");
            }
            Map<String, Object> rule = new LinkedHashMap<>();
            rule.put("id", id);
            rule.put("groups", groups);
            rule.put("mode", v.mode());
            Map<String, Object> actions = new LinkedHashMap<>();
            actions.put(v.dataClass(), v.action());
            rule.put("classActions", actions);
            out.add(rule);
        }
        return out;
    }

    /**
     * A stored group list as the contract carries it: every name already in the {@link GroupNames} normal form, 1 to 32,
     * none twice, sorted; null when the stored list breaks any of these (the compiler never emits what the data plane
     * refuses).
     */
    static List<String> groups(List<String> stored) {
        if (stored == null || !GroupNames.storedFormOk(stored)) {
            return null;
        }
        return stored.stream().sorted().toList();
    }

    /**
     * A seed version is version 1 by the seed actor with no approval; any other version holds exactly two approvals,
     * one per approver role, by two different people (AGENTS.md section 6).
     */
    static boolean approved(PolicyRuleVersion v) {
        if ("seed".equals(v.source())) {
            return v.version() == 1 && RegistrySeed.SEED_ACTOR.equals(v.authorFingerprint()) && v.approvals().isEmpty();
        }
        Set<String> roles = new HashSet<>();
        Set<String> people = new HashSet<>();
        for (PolicyRuleVersion.PolicyApproval a : v.approvals()) {
            roles.add(a.role());
            people.add(a.approverFingerprint());
        }
        return "registry".equals(v.source()) && v.approvals().size() == 2 && people.size() == 2
            && roles.equals(Set.of("security_admin", "privacy_officer"));
    }

    private static RegistryRefusal incomplete(String why) {
        return new RegistryRefusal(HttpStatus.SERVICE_UNAVAILABLE, "SNAPSHOT_REGISTRY_INCOMPLETE",
            "No snapshot can be compiled: " + why + ".");
    }

    private static String write(Object value) {
        try {
            return JSON.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("the snapshot document cannot be written", e);
        }
    }

    static String sha256(String s) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is part of every JDK", e);
        }
    }
}
