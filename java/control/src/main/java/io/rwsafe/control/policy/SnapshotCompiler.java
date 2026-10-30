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
import java.util.Set;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import org.springframework.http.HttpStatus;

/**
 * Compiles the registry's active versions into the snapshot document of POLICY_SNAPSHOT_CONTRACT, format 1. Only active
 * {@code enforce} versions at rollout stage {@code all} are compiled: format 1 carries no group targeting, so a staged
 * version keeps being shown and approved but the data plane keeps enforcing the {@code all} baseline until a version
 * reaches {@code all}; a {@code monitor} version is simulation only. The compiler refuses (and nothing is issued) when a
 * DLP class or the flow has no baseline, when a fail-closed class would be ALLOW or WARN (the data plane refuses such a
 * snapshot whatever {@code enforceFailClosed} says), when the flow is relaxed, or when the platform rows are defective.
 */
public final class SnapshotCompiler implements PolicySnapshotStore.Compiler {

    public static final int FORMAT = 1;
    private static final ObjectMapper JSON = new ObjectMapper();

    @Override
    public PolicySnapshotStore.Compiled compile(List<PolicyRuleVersion> active) {
        List<PolicyRuleVersion> baseline = active.stream()
            .filter(v -> "active".equals(v.status()) && "enforce".equals(v.mode()) && "all".equals(v.rolloutStage()))
            .sorted(Comparator.comparing(PolicyRuleVersion::ruleId)).toList();

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
        // PR 16 review D-01: every compiled version is the fixture's seed or carries its two approvals, whatever the
        // database says about its status.
        for (PolicyRuleVersion v : baseline) {
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
        String digest = sha256(write(content));
        List<String> ruleVersions = baseline.stream().map(PolicyRuleVersion::key).toList();
        TreeSet<String> approvers = new TreeSet<>();
        for (PolicyRuleVersion v : baseline) {
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
