package io.rwsafe.control.policy;

import io.rwsafe.control.config.ControlProperties;
import io.rwsafe.control.identity.Roles;
import io.rwsafe.control.privacy.PrivacyKeys;
import io.rwsafe.control.privacy.Pseudonymiser;
import io.rwsafe.persistence.AuditContext;
import io.rwsafe.persistence.Database;
import io.rwsafe.persistence.PolicyRuleVersion;
import io.rwsafe.persistence.PolicyRuleVersion.Draft;
import io.rwsafe.persistence.PolicySnapshotStore.IssuedSnapshot;
import io.rwsafe.persistence.RegistryConflict;
import io.rwsafe.persistence.VerdictQueries;
import io.rwsafe.platform.verdict.Verdict;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.jooq.exception.DataAccessException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * The policy registry's use cases (AGENTS.md section 6, ARCHITECTURE.md §3.2 {@code policy}): list, draft, approve, the
 * simulation stub, the exception refusal for fail-closed rules, and the current signed snapshot. Validation here names
 * the reason; the V2 triggers and checks refuse the same things again underneath.
 */
@Service
public class PolicyRegistryService {

    public static final String ISSUER = "system:snapshot-issuer";
    static final Duration SCHEDULE_INTERVAL = Duration.ofMinutes(5);
    private static final Logger LOG = LoggerFactory.getLogger(PolicyRegistryService.class);
    private static final Set<String> APPROVER_ROLES = Set.of(Roles.SECURITY_ADMIN, Roles.PRIVACY_OFFICER);

    private final Database database;
    private final ControlProperties.Policy config;
    private final Pseudonymiser pseudonymiser;
    private final PrivacyKeys keys;
    private final SnapshotCompiler compiler = new SnapshotCompiler();
    private final Clock clock;

    public PolicyRegistryService(Database database, ControlProperties properties, Pseudonymiser pseudonymiser,
                                 PrivacyKeys keys) {
        this.database = database;
        this.config = properties.policy();
        this.pseudonymiser = pseudonymiser;
        this.keys = keys;
        this.clock = Clock.systemUTC();
    }

    /** The body of a draft: the fields of the rule's kind, its mode, rollout stage and reason code. */
    public record DraftRequest(String action, Boolean enforceFailClosed, List<String> hostSuffixes,
                               List<String> apiHosts, List<String> loginHosts, String mode, String rolloutStage,
                               String reasonCode) {
    }

    /** How the stored events of the window would change under a proposed action for one class (counts only). */
    public record Simulation(String ruleId, String dataClass, String currentAction, String proposedAction, Instant from,
                             Instant to, long eventsInWindow, long eventsWithClass, long eventsChanged,
                             long eventsNotReevaluated, List<Transition> transitions) {
    }

    public record Transition(Verdict from, Verdict to, long events) {
    }

    public List<PolicyRuleVersion> versions() {
        return database.policyRegistry().versions();
    }

    public Optional<IssuedSnapshot> latestSnapshot() {
        return database.policySnapshots().latest();
    }

    public IssuedSnapshot currentSnapshot() {
        return currentSnapshot(clock.instant());
    }

    /**
     * The snapshot to serve at {@code now}: the latest when the active rules are unchanged and it is younger than the
     * refresh interval, else the next version, issued and ledgered.
     */
    public IssuedSnapshot currentSnapshot(Instant now) {
        return currentSnapshot(now, config.snapshotRefresh());
    }

    private IssuedSnapshot currentSnapshot(Instant now, Duration refresh) {
        return database.policySnapshots().current(compiler, now.truncatedTo(ChronoUnit.SECONDS), refresh,
            new AuditContext(ISSUER, "policy_snapshot.issue", "ACTIVE_POLICY_SIGNED", UUID.randomUUID().toString()));
    }

    /**
     * The scheduled re-sign (POLICY_SNAPSHOT_CONTRACT): the active policy is re-issued under the next version with a
     * fresh {@code issuedAt} at least every refresh interval (at most 6 hours), even when no data plane polls and no rule
     * changed, so a data plane never runs into the 24-hour staleness limit. The check runs every 5 minutes and re-issues
     * one interval early, so no snapshot outlives the refresh interval between two checks.
     */
    @Scheduled(initialDelayString = "PT1M", fixedDelayString = "PT5M")
    public void reissueWhenDue() {
        Duration early = config.snapshotRefresh().minus(SCHEDULE_INTERVAL);
        try {
            currentSnapshot(clock.instant(), early.compareTo(Duration.ofMinutes(1)) < 0 ? Duration.ofMinutes(1) : early);
        } catch (RegistryRefusal e) {
            LOG.warn("policy snapshot not issued: {}", e.reason());
        } catch (DataAccessException e) {
            LOG.warn("policy snapshot not issued: {}", e.getClass().getSimpleName());
        }
    }

    /** Adds the next version of a rule as pending, authored by the signed-in {@code loginName} (as its pseudonym). */
    public PolicyRuleVersion draft(String ruleId, DraftRequest body, String loginName) {
        String kind = RegistryVocabulary.kindOf(ruleId);
        if (kind == null) {
            throw new RegistryRefusal(HttpStatus.NOT_FOUND, "UNKNOWN_RULE", "The registry knows no such rule id.");
        }
        List<PolicyRuleVersion> all = database.policyRegistry().versions();
        if (!kind.equals(RegistryVocabulary.KIND_PLATFORM) && all.stream().noneMatch(v -> v.ruleId().equals(ruleId))) {
            throw new RegistryRefusal(HttpStatus.NOT_FOUND, "UNKNOWN_RULE",
                "Class and flow rules come from the seed fixture; this one is not in the registry.");
        }
        if (body == null || !RegistryVocabulary.MODES.contains(body.mode())
            || !RegistryVocabulary.STAGES.contains(body.rolloutStage())
            || !RegistryVocabulary.reasonCode(body.reasonCode())) {
            throw invalid("A draft needs mode (monitor, enforce), rolloutStage (pilot, pct25, pct50, all) and an "
                + "upper-case reasonCode.");
        }
        String author = pseudonym(loginName);
        Draft draft = switch (kind) {
            case RegistryVocabulary.KIND_CLASS -> classDraft(ruleId, body, author);
            case RegistryVocabulary.KIND_FLOW -> flowDraft(ruleId, body, author);
            default -> platformDraft(ruleId, body, author, all);
        };
        try {
            return database.policyRegistry().draft(draft, new AuditContext(author, "policy.draft", body.reasonCode(),
                UUID.randomUUID().toString()));
        } catch (RegistryConflict e) {
            throw conflict(e);
        }
    }

    private Draft classDraft(String ruleId, DraftRequest b, String author) {
        if (b.action() == null || b.enforceFailClosed() != null || b.hostSuffixes() != null || b.apiHosts() != null
            || b.loginHosts() != null || !RegistryVocabulary.ACTIONS.contains(b.action())) {
            throw invalid("A class rule takes an action (ALLOW, WARN, REDACT, BLOCK) and nothing else.");
        }
        String dataClass = RegistryVocabulary.dataClassOf(ruleId);
        if (RegistryVocabulary.failClosedClass(dataClass) && RegistryVocabulary.RELAXING_ACTIONS.contains(b.action())) {
            throw new RegistryRefusal(HttpStatus.CONFLICT, "FAIL_CLOSED_CLASS_NOT_RELAXABLE",
                "A fail-closed class is never ALLOW or WARN, in monitor or enforce mode.");
        }
        return new Draft(ruleId, RegistryVocabulary.KIND_CLASS, dataClass, b.action(), null, null, null, null, null,
            b.mode(), b.rolloutStage(), author, b.reasonCode());
    }

    private Draft flowDraft(String ruleId, DraftRequest b, String author) {
        if (b.enforceFailClosed() == null || b.action() != null || b.hostSuffixes() != null || b.apiHosts() != null
            || b.loginHosts() != null) {
            throw invalid("The flow rule takes enforceFailClosed and nothing else.");
        }
        if (!b.enforceFailClosed()) {
            throw new RegistryRefusal(HttpStatus.CONFLICT, "FAIL_CLOSED_FLOW_NOT_RELAXABLE",
                "The AI-category flow stays fail-closed (ADR-010).");
        }
        return new Draft(ruleId, RegistryVocabulary.KIND_FLOW, null, null, null, null, null, null, true, b.mode(),
            b.rolloutStage(), author, b.reasonCode());
    }

    private Draft platformDraft(String ruleId, DraftRequest b, String author, List<PolicyRuleVersion> all) {
        if (b.hostSuffixes() == null || b.apiHosts() == null || b.loginHosts() == null || b.action() != null
            || b.enforceFailClosed() != null) {
            throw invalid("A platform rule takes hostSuffixes, apiHosts and loginHosts and nothing else.");
        }
        String id = ruleId.substring("platform.".length());
        PlatformRow row = new PlatformRow(id, lower(b.hostSuffixes()), lower(b.apiHosts()), lower(b.loginHosts()));
        List<PlatformRow> rows = new ArrayList<>();
        rows.add(row);
        for (PolicyRuleVersion v : all) {
            if (RegistryVocabulary.KIND_PLATFORM.equals(v.kind()) && "active".equals(v.status())
                && !v.platformId().equals(id) && "all".equals(v.rolloutStage()) && "enforce".equals(v.mode())) {
                rows.add(new PlatformRow(v.platformId(), v.hostSuffixes(), v.apiHosts(), v.loginHosts()));
            }
        }
        String defect = PlatformRow.defect(rows);
        if (defect != null) {
            throw new RegistryRefusal(HttpStatus.CONFLICT, "INVALID_PLATFORM_ROW", "The platform row is refused: "
                + defect + ".");
        }
        // Vendor-published endpoints only (PLATFORM_MATRIX §2): a host that names an estate term is refused.
        for (String term : keys.estateTerms()) {
            String t = term.toLowerCase(Locale.ROOT);
            for (List<String> hosts : List.of(row.hostSuffixes(), row.apiHosts(), row.loginHosts())) {
                if (!t.isBlank() && hosts.stream().anyMatch(h -> h.contains(t))) {
                    throw new RegistryRefusal(HttpStatus.CONFLICT, "ESTATE_NAME_REFUSED",
                        "A platform row names vendor endpoints only; a host matches the estate dictionary.");
                }
            }
        }
        return new Draft(ruleId, RegistryVocabulary.KIND_PLATFORM, null, null, id, row.hostSuffixes(), row.apiHosts(),
            row.loginHosts(), null, b.mode(), b.rolloutStage(), author, b.reasonCode());
    }

    /**
     * Records the signed-in user's approval in {@code role}; with the second approval (the other role, another person)
     * the version becomes active.
     */
    public PolicyRuleVersion approve(String ruleId, int version, String role, String loginName, Set<String> sessionRoles) {
        if (!APPROVER_ROLES.contains(role)) {
            throw new RegistryRefusal(HttpStatus.BAD_REQUEST, "INVALID_APPROVAL",
                "The approval role is security_admin or privacy_officer.");
        }
        if (!sessionRoles.contains(role) || sessionRoles.contains(Roles.REPLAY_VIEWER)) {
            throw new RegistryRefusal(HttpStatus.FORBIDDEN, "APPROVER_ROLE_MISSING",
                "Your session does not hold the role this approval is given in.");
        }
        String approver = pseudonym(loginName);
        String correlation = UUID.randomUUID().toString();
        try {
            return database.policyRegistry().approve(ruleId, version, role, approver,
                new AuditContext(approver, "policy.approve", "APPROVAL_" + role.toUpperCase(Locale.ROOT), correlation),
                new AuditContext(approver, "policy.activate", "TWO_APPROVALS", correlation));
        } catch (RegistryConflict e) {
            throw conflict(e);
        }
    }

    /** Exceptions with an expiry exist for non-fail-closed rules only; a fail-closed class or flow never takes one. */
    public void refuseException(String ruleId) {
        if (RegistryVocabulary.kindOf(ruleId) == null) {
            throw new RegistryRefusal(HttpStatus.NOT_FOUND, "UNKNOWN_RULE", "The registry knows no such rule id.");
        }
        if (RegistryVocabulary.failClosedRule(ruleId)) {
            throw new RegistryRefusal(HttpStatus.CONFLICT, "FAIL_CLOSED_NO_EXCEPTION",
                "A fail-closed class or flow takes no exception (ADR-010, PC-5).");
        }
        throw new RegistryRefusal(HttpStatus.CONFLICT, "EXCEPTION_NOT_APPLICABLE",
            "A platform row names vendor endpoints; exceptions apply to class and tenant rules.");
    }

    /**
     * The simulation stub: re-decides the stored events of the window that carry the rule's class, with the proposed
     * action for that class and the active baseline for the others, and counts the verdicts that would change. A
     * non-verdict or an aborted stream is not re-evaluated. Counts only; no event leaves the database.
     */
    public Simulation simulate(String ruleId, String proposedAction, Instant to) {
        if (!RegistryVocabulary.KIND_CLASS.equals(RegistryVocabulary.kindOf(ruleId))) {
            throw new RegistryRefusal(HttpStatus.BAD_REQUEST, "SIMULATION_NOT_SUPPORTED",
                "The simulation re-decides DLP class rules only.");
        }
        if (!RegistryVocabulary.ACTIONS.contains(proposedAction)) {
            throw invalid("The proposed action is ALLOW, WARN, REDACT or BLOCK.");
        }
        String dataClass = RegistryVocabulary.dataClassOf(ruleId);
        Map<String, String> current = new LinkedHashMap<>();
        for (PolicyRuleVersion v : database.policyRegistry().active()) {
            if (RegistryVocabulary.KIND_CLASS.equals(v.kind()) && "enforce".equals(v.mode())
                && "all".equals(v.rolloutStage())) {
                current.put(v.dataClass(), v.action());
            }
        }
        Instant end = to == null ? clock.instant() : to;
        Instant start = end.minus(config.simulationWindow());
        VerdictQueries.SimulationBase base = database.verdictQueries().classCombinations(start, end, dataClass);
        long withClass = 0;
        long changed = 0;
        long notReevaluated = 0;
        Map<String, Long> transitions = new LinkedHashMap<>();
        for (VerdictQueries.ClassCombination c : base.combinations()) {
            withClass += c.events();
            if (c.verdict().isNonVerdict() || c.verdict() == Verdict.STREAM_ABORTED) {
                notReevaluated += c.events();
                continue;
            }
            int strictest = -1;
            for (String cls : c.classes()) {
                String action = cls.equals(dataClass) ? proposedAction : current.getOrDefault(cls, "BLOCK");
                strictest = Math.max(strictest, RegistryVocabulary.ACTIONS.indexOf(action));
            }
            Verdict next = Verdict.valueOf(RegistryVocabulary.ACTIONS.get(Math.max(0, strictest)));
            if (next != c.verdict()) {
                changed += c.events();
                transitions.merge(c.verdict().name() + ">" + next.name(), c.events(), Long::sum);
            }
        }
        List<Transition> list = transitions.entrySet().stream().map(e -> {
            String[] fromTo = e.getKey().split(">", 2);
            return new Transition(Verdict.valueOf(fromTo[0]), Verdict.valueOf(fromTo[1]), e.getValue());
        }).toList();
        return new Simulation(ruleId, dataClass, current.get(dataClass), proposedAction, start, end,
            base.eventsInWindow(), withClass, changed, notReevaluated, list);
    }

    private String pseudonym(String loginName) {
        if (!keys.keyAvailable()) {
            throw new RegistryRefusal(HttpStatus.SERVICE_UNAVAILABLE, "PRIVACY_KEY_UNAVAILABLE",
                "Registry changes are recorded under the author's pseudonym and the privacy key is missing.");
        }
        return pseudonymiser.user(loginName);
    }

    private static List<String> lower(List<String> hosts) {
        return hosts.stream().map(h -> h == null ? "" : h.strip().toLowerCase(Locale.ROOT)).toList();
    }

    private static RegistryRefusal invalid(String message) {
        return new RegistryRefusal(HttpStatus.BAD_REQUEST, "INVALID_DRAFT", message);
    }

    private static RegistryRefusal conflict(RegistryConflict e) {
        HttpStatus status = "POLICY_VERSION_NOT_FOUND".equals(e.reason()) ? HttpStatus.NOT_FOUND : HttpStatus.CONFLICT;
        return new RegistryRefusal(status, e.reason(), e.getMessage());
    }
}
