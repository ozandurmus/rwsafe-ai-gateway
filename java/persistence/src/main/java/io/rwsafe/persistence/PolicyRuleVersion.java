package io.rwsafe.persistence;

import java.time.Instant;
import java.util.List;

/**
 * One version of a policy-registry rule (AGENTS.md section 6) as stored. The vocabulary is the registry's: {@code kind} is
 * {@code class_action}, {@code platform} or {@code flow}; {@code mode} {@code monitor} or {@code enforce};
 * {@code rolloutStage} {@code pilot}, {@code pct25}, {@code pct50} or {@code all}; {@code status} {@code pending},
 * {@code active} or {@code superseded}; {@code source} {@code seed} (the committed fixture) or {@code registry}. Fields
 * that do not belong to the kind are null.
 */
public record PolicyRuleVersion(String ruleId, int version, String kind, String dataClass, String action,
                                String platformId, List<String> hostSuffixes, List<String> apiHosts,
                                List<String> loginHosts, Boolean enforceFailClosed, String mode, String rolloutStage,
                                String status, String source, String authorFingerprint, String reasonCode,
                                Instant createdAt, Instant activatedAt, Instant supersededAt,
                                List<PolicyApproval> approvals) {

    public PolicyRuleVersion {
        hostSuffixes = hostSuffixes == null ? null : List.copyOf(hostSuffixes);
        apiHosts = apiHosts == null ? null : List.copyOf(apiHosts);
        loginHosts = loginHosts == null ? null : List.copyOf(loginHosts);
        approvals = List.copyOf(approvals);
    }

    /** {@code rule@vN}: the ledger's row key and the snapshot's rule-version reference. */
    public String key() {
        return ruleId + "@v" + version;
    }

    /**
     * An approval of a pending version; {@code role} is {@code security_admin} or {@code privacy_officer}.
     *
     * @param approverFingerprint the approver's {@code USR-} pseudonym, never a name
     */
    public record PolicyApproval(String role, String approverFingerprint, Instant approvedAt) {
    }

    /** The content of a new version; the store assigns the version number, the status and the times. */
    public record Draft(String ruleId, String kind, String dataClass, String action, String platformId,
                        List<String> hostSuffixes, List<String> apiHosts, List<String> loginHosts,
                        Boolean enforceFailClosed, String mode, String rolloutStage, String authorFingerprint,
                        String reasonCode) {

        public Draft {
            hostSuffixes = hostSuffixes == null ? null : List.copyOf(hostSuffixes);
            apiHosts = apiHosts == null ? null : List.copyOf(apiHosts);
            loginHosts = loginHosts == null ? null : List.copyOf(loginHosts);
        }
    }
}
