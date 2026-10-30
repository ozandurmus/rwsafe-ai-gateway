package io.rwsafe.control.policy;

import io.rwsafe.control.api.ApiError;
import io.rwsafe.control.policy.PolicyViews.RegistryView;
import io.rwsafe.control.policy.PolicyViews.RetiredView;
import io.rwsafe.control.policy.PolicyViews.SimulationView;
import io.rwsafe.control.policy.PolicyViews.VersionView;
import java.time.Instant;
import java.util.Set;
import java.util.TreeSet;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * The registry API of the Policies and Platforms screens (ARCHITECTURE.md §3.4). Reads are open to every role (the
 * masked role through the funnel); a draft needs {@code security_admin}; an approval needs the role it is given in
 * ({@code security_admin} or {@code privacy_officer}); the masked role never changes anything (SecurityConfig).
 */
@RestController
@RequestMapping("/api/v1/policy")
public class PolicyApiController {

    private final PolicyRegistryService registry;
    private final SnapshotSigner signer;

    public PolicyApiController(PolicyRegistryService registry, SnapshotSigner signer) {
        this.registry = registry;
        this.signer = signer;
    }

    public record ApprovalRequest(String role) {
    }

    @GetMapping("/rules")
    public RegistryView rules() {
        return RegistryView.of(registry.versions(), registry.latestSnapshot().orElse(null), signer.keyId());
    }

    @PostMapping("/rules/{ruleId}/versions")
    public ResponseEntity<VersionView> draft(@PathVariable("ruleId") String ruleId,
                                             @RequestBody PolicyRegistryService.DraftRequest body, Authentication auth) {
        VersionView created = VersionView.of(registry.draft(ruleId, body, auth.getName()), Set.of());
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @PostMapping("/rules/{ruleId}/versions/{version}/approvals")
    public VersionView approve(@PathVariable("ruleId") String ruleId, @PathVariable("version") int version,
                               @RequestBody ApprovalRequest body, Authentication auth) {
        return VersionView.of(registry.approve(ruleId, version, body == null ? null : body.role(), auth.getName(),
            roles(auth)), Set.of());
    }

    /**
     * Retires a platform row (PO decision Q-40): {@code security_admin} only (SecurityConfig and the service), with a
     * reason; the viewer, the privacy officer alone and the masked role get 403.
     */
    @PostMapping("/rules/{ruleId}/retirement")
    public RetiredView retire(@PathVariable("ruleId") String ruleId,
                              @RequestBody PolicyRegistryService.RetireRequest body, Authentication auth) {
        return new RetiredView(registry.retirePlatform(ruleId, body, auth.getName(), roles(auth)).stream()
            .map(v -> VersionView.of(v, Set.of())).toList());
    }

    private static Set<String> roles(Authentication auth) {
        Set<String> roles = new TreeSet<>();
        for (GrantedAuthority a : auth.getAuthorities()) {
            roles.add(a.getAuthority().substring("ROLE_".length()));
        }
        return roles;
    }

    /** Always refused today: every rule the registry holds is fail-closed or a platform row (ADR-010, PC-5). */
    @PostMapping("/rules/{ruleId}/exceptions")
    public ResponseEntity<ApiError> exception(@PathVariable("ruleId") String ruleId) {
        registry.refuseException(ruleId);
        return ResponseEntity.status(HttpStatus.CONFLICT).body(ApiError.of("EXCEPTION_NOT_APPLICABLE",
            "No exception was recorded."));
    }

    @GetMapping("/simulation")
    public SimulationView simulate(@RequestParam("ruleId") String ruleId, @RequestParam("action") String action,
                                   @RequestParam(name = "to", required = false) Instant to) {
        return SimulationView.of(registry.simulate(ruleId, action, to));
    }
}
