package io.rwsafe.persistence;

import java.time.Instant;
import java.util.List;

/**
 * One version of a policy-registry rule (AGENTS.md section 6) as stored. The vocabulary is the registry's: {@code kind} is
 * {@code class_action}, {@code platform} or {@code flow}; {@code mode} {@code monitor} or {@code enforce};
 * {@code rolloutStage} {@code all} (the percentage stages {@code pilot}, {@code pct25}, {@code pct50} survive on old rows
 * only, PO decision Q-39); {@code status} {@code pending}, {@code active}, {@code superseded}, {@code retired} (a
 * platform row only, Q-40) or {@code withdrawn} (a group-scoped class version, Q-41); {@code source} {@code seed} (the
 * committed fixture) or {@code registry}; {@code scopeKind} {@code ANY} (everyone) or {@code GROUPS} with 1 to 32
 * directory group names in {@code scopeGroups} (runtime data typed by the operator: never logged, never a metrics label).
 * A withdrawal request names the version it withdraws in {@code withdrawsVersion}, with its reason; it is never compiled.
 * Fields that do not belong to the kind are null.
 */
public record PolicyRuleVersion(String ruleId, int version, String kind, String dataClass, String action,
                                String platformId, List<String> hostSuffixes, List<String> apiHosts,
                                List<String> loginHosts, Boolean enforceFailClosed, String mode, String rolloutStage,
                                String status, String source, String authorFingerprint, String reasonCode,
                                Instant createdAt, Instant activatedAt, Instant supersededAt,
                                List<PolicyApproval> approvals, String scopeKind, List<String> scopeGroups,
                                Retirement retirement, Integer withdrawsVersion, String withdrawalReason,
                                Instant withdrawnAt) {

    /** A version that is not a withdrawal request and was not withdrawn. */
    public PolicyRuleVersion(String ruleId, int version, String kind, String dataClass, String action,
                             String platformId, List<String> hostSuffixes, List<String> apiHosts,
                             List<String> loginHosts, Boolean enforceFailClosed, String mode, String rolloutStage,
                             String status, String source, String authorFingerprint, String reasonCode,
                             Instant createdAt, Instant activatedAt, Instant supersededAt,
                             List<PolicyApproval> approvals, String scopeKind, List<String> scopeGroups,
                             Retirement retirement) {
        this(ruleId, version, kind, dataClass, action, platformId, hostSuffixes, apiHosts, loginHosts, enforceFailClosed,
            mode, rolloutStage, status, source, authorFingerprint, reasonCode, createdAt, activatedAt, supersededAt,
            approvals, scopeKind, scopeGroups, retirement, null, null, null);
    }

    /** True for a withdrawal request (Q-41): it names a version to withdraw and is never compiled. */
    public boolean withdrawalRequest() {
        return withdrawsVersion != null;
    }

    public static final String SCOPE_ANY = "ANY";
    public static final String SCOPE_GROUPS = "GROUPS";

    public PolicyRuleVersion {
        hostSuffixes = hostSuffixes == null ? null : List.copyOf(hostSuffixes);
        apiHosts = apiHosts == null ? null : List.copyOf(apiHosts);
        loginHosts = loginHosts == null ? null : List.copyOf(loginHosts);
        approvals = List.copyOf(approvals);
        scopeKind = scopeKind == null ? SCOPE_ANY : scopeKind;
        scopeGroups = scopeGroups == null ? List.of() : List.copyOf(scopeGroups);
    }

    /** A version with scope {@code ANY} and no retirement (the V2 shape). */
    public PolicyRuleVersion(String ruleId, int version, String kind, String dataClass, String action,
                             String platformId, List<String> hostSuffixes, List<String> apiHosts,
                             List<String> loginHosts, Boolean enforceFailClosed, String mode, String rolloutStage,
                             String status, String source, String authorFingerprint, String reasonCode,
                             Instant createdAt, Instant activatedAt, Instant supersededAt,
                             List<PolicyApproval> approvals) {
        this(ruleId, version, kind, dataClass, action, platformId, hostSuffixes, apiHosts, loginHosts, enforceFailClosed,
            mode, rolloutStage, status, source, authorFingerprint, reasonCode, createdAt, activatedAt, supersededAt,
            approvals, SCOPE_ANY, List.of(), null, null, null, null);
    }

    /** {@code rule@vN}: the ledger's row key and the snapshot's rule-version reference. */
    public String key() {
        return ruleId + "@v" + version;
    }

    public boolean scopedToGroups() {
        return SCOPE_GROUPS.equals(scopeKind);
    }

    /**
     * An approval of a pending version; {@code role} is {@code security_admin} or {@code privacy_officer}.
     *
     * @param approverFingerprint the approver's {@code USR-} pseudonym, never a name
     */
    public record PolicyApproval(String role, String approverFingerprint, Instant approvedAt) {
    }

    /**
     * How a platform row left service (PO decision Q-40): when, by which administrator's pseudonym, and the reason the
     * administrator gave.
     */
    public record Retirement(Instant retiredAt, String retiredBy, String reason) {
    }

    /** The content of a new version; the store assigns the version number, the status and the times. */
    public record Draft(String ruleId, String kind, String dataClass, String action, String platformId,
                        List<String> hostSuffixes, List<String> apiHosts, List<String> loginHosts,
                        Boolean enforceFailClosed, String mode, String rolloutStage, String authorFingerprint,
                        String reasonCode, String scopeKind, List<String> scopeGroups) {

        public Draft {
            hostSuffixes = hostSuffixes == null ? null : List.copyOf(hostSuffixes);
            apiHosts = apiHosts == null ? null : List.copyOf(apiHosts);
            loginHosts = loginHosts == null ? null : List.copyOf(loginHosts);
            scopeKind = scopeKind == null ? SCOPE_ANY : scopeKind;
            scopeGroups = scopeGroups == null ? List.of() : List.copyOf(scopeGroups);
        }

        /** A draft with scope {@code ANY}. */
        public Draft(String ruleId, String kind, String dataClass, String action, String platformId,
                     List<String> hostSuffixes, List<String> apiHosts, List<String> loginHosts,
                     Boolean enforceFailClosed, String mode, String rolloutStage, String authorFingerprint,
                     String reasonCode) {
            this(ruleId, kind, dataClass, action, platformId, hostSuffixes, apiHosts, loginHosts, enforceFailClosed, mode,
                rolloutStage, authorFingerprint, reasonCode, SCOPE_ANY, List.of());
        }
    }
}
