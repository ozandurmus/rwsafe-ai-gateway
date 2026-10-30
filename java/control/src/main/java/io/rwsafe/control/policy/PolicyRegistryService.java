package io.rwsafe.control.policy;

import io.rwsafe.control.config.ControlProperties;
import io.rwsafe.control.identity.Roles;
import io.rwsafe.control.privacy.Masking;
import io.rwsafe.control.privacy.PrivacyKeys;
import io.rwsafe.control.privacy.IdentifierCheck;
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
import java.util.HashSet;
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
    /** The platform the data plane names when no platform row matches (the flow classifier's fallback). */
    public static final String UNKNOWN_PLATFORM = "unknown";
    private static final Set<String> APPROVER_ROLES = Set.of(Roles.SECURITY_ADMIN, Roles.PRIVACY_OFFICER);

    private final Database database;
    private final ControlProperties.Policy config;
    private final Pseudonymiser pseudonymiser;
    private final PrivacyKeys keys;
    private final SnapshotSigner signer;
    private final SnapshotCompiler compiler = new SnapshotCompiler();
    private final Masking masking;
    private final IdentifierCheck identifiers;
    private final Clock clock;

    public PolicyRegistryService(Database database, ControlProperties properties, Pseudonymiser pseudonymiser,
                                 PrivacyKeys keys, SnapshotSigner signer) {
        this.database = database;
        this.config = properties.policy();
        this.pseudonymiser = pseudonymiser;
        this.keys = keys;
        this.signer = signer;
        this.masking = new Masking(keys, pseudonymiser);
        this.identifiers = new IdentifierCheck(keys);
        this.clock = Clock.systemUTC();
    }

    /**
     * The body of a draft: the fields of the rule's kind, its mode, its scope and reason code. {@code rolloutStage} is
     * optional and, when present, {@code all} (PO decision Q-39 retired the percentage stages); a missing {@code scope}
     * is {@code ANY}.
     */
    public record DraftRequest(String action, Boolean enforceFailClosed, List<String> hostSuffixes,
                               List<String> apiHosts, List<String> loginHosts, String mode, String rolloutStage,
                               ScopeRequest scope, String reasonCode) {
    }

    /** {@code ANY} with no groups, or {@code GROUPS} with 1 to 32 directory group names (trimmed, distinct by case). */
    public record ScopeRequest(String kind, List<String> groups) {
    }

    /** The body of a platform retirement: the administrator's reason, 1 to 500 characters (Q-40). */
    public record RetireRequest(String reason) {
    }

    static final int MAX_RETIRE_REASON = 500;

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

    /**
     * The platform ids a verdict event or a traffic filter may name (SR-PRIV-4): every platform rule the registry holds,
     * in any version, and {@link #UNKNOWN_PLATFORM}. Nothing else is a platform.
     */
    public Set<String> platformIds() {
        Set<String> ids = new HashSet<>();
        ids.add(UNKNOWN_PLATFORM);
        for (PolicyRuleVersion v : versions()) {
            if (RegistryVocabulary.KIND_PLATFORM.equals(v.kind()) && v.platformId() != null) {
                ids.add(v.platformId());
            }
        }
        return ids;
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
        // A snapshot is issued and ledgered as signed only when it can be signed (PR 16 review D-06).
        if (!signer.available()) {
            throw new RegistryRefusal(HttpStatus.SERVICE_UNAVAILABLE, "SNAPSHOT_SIGNING_UNAVAILABLE",
                "The snapshot signing key is unavailable; no snapshot is issued.");
        }
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

    /**
     * Adds the next version of a rule as pending, authored by the signed-in {@code loginName} (as its pseudonym). Only a
     * security administrator drafts, never in a masked session (PR 21 review D-06: the service checks it as well as
     * SecurityConfig); a platform row or the flow is drafted in enforce mode only.
     */
    public PolicyRuleVersion draft(String ruleId, DraftRequest body, String loginName, Set<String> sessionRoles) {
        requireSecurityAdmin(sessionRoles, "DRAFT_ROLE_MISSING", "Only a security administrator drafts a version.");
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
            || !RegistryVocabulary.reasonCode(body.reasonCode())) {
            throw invalid("A draft needs mode (monitor, enforce) and an upper-case reasonCode.");
        }
        if (body.rolloutStage() != null && !RegistryVocabulary.STAGE_ALL.equals(body.rolloutStage())) {
            throw new RegistryRefusal(HttpStatus.BAD_REQUEST, "ROLLOUT_STAGE_RETIRED",
                "Percentage rollout stages are retired; choose a scope (everyone or directory groups) instead.");
        }
        if (!kind.equals(RegistryVocabulary.KIND_CLASS) && !"enforce".equals(body.mode())) {
            throw new RegistryRefusal(HttpStatus.BAD_REQUEST, "ENFORCE_ONLY",
                "A platform row or the flow is drafted in enforce mode only; a monitor version of it is never sent.");
        }
        Scope scope = scope(kind, body.scope());
        // PR 16 review D-05: the reason code and a platform id are free values too; neither may name the estate.
        if (namesEstate(body.reasonCode()) || (kind.equals(RegistryVocabulary.KIND_PLATFORM)
            && namesEstate(ruleId.substring("platform.".length())))) {
            throw estateRefused();
        }
        // A platform id becomes ingestion vocabulary and a reason code is shown to every role (the masked one through
        // the text masker): no identifier shape and no long digit run (a number glued to letters escapes the detectors'
        // boundary rule).
        if (carriesIdentifier(body.reasonCode()) || (kind.equals(RegistryVocabulary.KIND_PLATFORM)
            && carriesIdentifier(ruleId.substring("platform.".length())))) {
            throw invalid("A platform id or reason code is vocabulary; it may not carry an identifier-shaped value.");
        }
        String author = pseudonym(loginName);
        Draft shape = switch (kind) {
            case RegistryVocabulary.KIND_CLASS -> classDraft(ruleId, body, author);
            case RegistryVocabulary.KIND_FLOW -> flowDraft(ruleId, body, author);
            default -> platformDraft(ruleId, body, author, all);
        };
        Draft draft = new Draft(shape.ruleId(), shape.kind(), shape.dataClass(), shape.action(), shape.platformId(),
            shape.hostSuffixes(), shape.apiHosts(), shape.loginHosts(), shape.enforceFailClosed(), shape.mode(),
            RegistryVocabulary.STAGE_ALL, shape.authorFingerprint(), shape.reasonCode(), scope.kind(), scope.groups());
        try {
            return database.policyRegistry().draft(draft, new AuditContext(author, "policy.draft", body.reasonCode(),
                UUID.randomUUID().toString()));
        } catch (RegistryConflict e) {
            throw conflict(e);
        }
    }

    /** A validated scope: {@code ANY}, or {@code GROUPS} with the trimmed names ordered as the snapshot carries them. */
    record Scope(String kind, List<String> groups) {
    }

    /**
     * Validates the requested scope. Only a DLP class rule takes a group scope (a format 2 scoped rule carries class
     * actions only). Group names are the operator's runtime data: they are never logged, never refused against the
     * estate dictionary (a directory group is an estate name by nature) and reach the masked role only as pseudonyms.
     */
    static Scope scope(String kind, ScopeRequest requested) {
        if (requested == null || ("ANY".equals(requested.kind())
            && (requested.groups() == null || requested.groups().isEmpty()))) {
            return new Scope(PolicyRuleVersion.SCOPE_ANY, List.of());
        }
        if (!PolicyRuleVersion.SCOPE_GROUPS.equals(requested.kind())) {
            throw new RegistryRefusal(HttpStatus.BAD_REQUEST, "INVALID_SCOPE",
                "The scope is ANY (everyone, no groups) or GROUPS with 1 to 32 group names.");
        }
        if (!RegistryVocabulary.KIND_CLASS.equals(kind)) {
            throw new RegistryRefusal(HttpStatus.BAD_REQUEST, "INVALID_SCOPE",
                "Only a DLP class rule takes a group scope; platform rows and the flow apply to everyone.");
        }
        List<String> groups = ScopeGroups.normalise(requested.groups());
        if (groups == null) {
            throw new RegistryRefusal(HttpStatus.BAD_REQUEST, "INVALID_SCOPE",
                "A group scope takes 1 to 32 short directory group names of 1 to 256 characters, without commas or "
                    + "control characters, each named once (compared after normalisation: case, Turkish i forms).");
        }
        // Directory group names are estate names by nature (no estate check; the masked role sees GRP- pseudonyms), but
        // never an identifier shape (PO decision on PR 24 confirmation review Q-1).
        if (groups.stream().anyMatch(IdentifierCheck::identifierShape)) {
            throw new RegistryRefusal(HttpStatus.BAD_REQUEST, "INVALID_SCOPE",
                "A group name may not carry an identifier-shaped value (a number, a card, an account or a secret).");
        }
        return new Scope(PolicyRuleVersion.SCOPE_GROUPS, groups);
    }

    private Draft classDraft(String ruleId, DraftRequest b, String author) {
        if (b.action() == null || b.enforceFailClosed() != null || b.hostSuffixes() != null || b.apiHosts() != null
            || b.loginHosts() != null || !RegistryVocabulary.ACTIONS.contains(b.action())) {
            throw invalid("A class rule takes an action (ALLOW, WARN, REDACT, BLOCK) and nothing else.");
        }
        String dataClass = RegistryVocabulary.dataClassOf(ruleId);
        if (RegistryVocabulary.failClosedClass(dataClass) && RegistryVocabulary.RELAXING_ACTIONS.contains(b.action())) {
            throw new RegistryRefusal(HttpStatus.CONFLICT, "FAIL_CLOSED_CLASS_NOT_RELAXABLE",
                "A fail-closed class is never ALLOW or WARN, in monitor or enforce mode, for everyone or for a group.");
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
        // Vendor-published endpoints only (PLATFORM_MATRIX §2): a host that names an estate term is refused, and so is
        // a host label carrying an identifier shape (PR 24 review D-04).
        if (rowNamesEstate(row)) {
            throw estateRefused();
        }
        for (List<String> hosts : List.of(row.hostSuffixes(), row.apiHosts(), row.loginHosts())) {
            if (hosts.stream().anyMatch(IdentifierCheck::identifierShape)) {
                throw invalid("A host name is vendor vocabulary; it may not carry an identifier-shaped value.");
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
                new AuditContext(approver, "policy.activate", "TWO_APPROVALS", correlation), this::checkActivation);
        } catch (RegistryConflict e) {
            throw conflict(e);
        }
    }

    /**
     * Runs inside the activating approval's transaction on the would-be active versions (PR 16 review D-04): they must
     * compile into a snapshot (every class and the flow, non-overlapping platform rows, approvals) and no platform row
     * may name the estate. A failure rolls the approval and the activation back.
     */
    void checkActivation(List<PolicyRuleVersion> active) {
        try {
            compiler.compile(active);
        } catch (RegistryRefusal e) {
            throw new RegistryRefusal(HttpStatus.CONFLICT, "ACTIVATION_WOULD_NOT_COMPILE",
                "This activation would leave a registry that does not compile (" + e.reason() + "); nothing changed.");
        }
        for (PolicyRuleVersion v : active) {
            // Every activating version's free values once more (N-02): the reason code, the platform row, the groups.
            if (namesEstate(v.reasonCode()) || carriesIdentifier(v.reasonCode())
                || (v.scopeGroups() != null && v.scopeGroups().stream().anyMatch(IdentifierCheck::identifierShape))) {
                throw invalid("An active version would carry an identifier or an estate name; nothing changed.");
            }
            if (RegistryVocabulary.KIND_PLATFORM.equals(v.kind()) && (namesEstate(v.platformId())
                || rowNamesEstate(new PlatformRow(v.platformId(), v.hostSuffixes(), v.apiHosts(), v.loginHosts())))) {
                throw estateRefused();
            }
        }
    }

    /**
     * Retires a platform row (PO decision Q-40): one {@code security_admin}'s action with a reason, no second approval.
     * The row is kept as {@code retired}, the ledger names the administrator and the reason, and the next snapshot no
     * longer carries the platform. A retirement that would leave no compilable snapshot (the last platform row) is
     * refused and rolled back.
     */
    public List<PolicyRuleVersion> retirePlatform(String ruleId, RetireRequest body, String loginName,
                                                  Set<String> sessionRoles) {
        requireSecurityAdmin(sessionRoles, "RETIRE_ROLE_MISSING", "Only a security administrator retires a platform row.");
        if (!RegistryVocabulary.KIND_PLATFORM.equals(RegistryVocabulary.kindOf(ruleId))) {
            throw new RegistryRefusal(HttpStatus.NOT_FOUND, "UNKNOWN_PLATFORM",
                "Only a platform row is retired; the registry knows no such platform.");
        }
        String reason = reasonText(body == null ? null : body.reason(), "INVALID_RETIREMENT", "retirement");
        String admin = pseudonym(loginName);
        try {
            return database.policyRegistry().retirePlatform(ruleId, admin, reason,
                new AuditContext(admin, "policy.platform_retire", reason, UUID.randomUUID().toString()),
                this::checkRetirement);
        } catch (RegistryConflict e) {
            throw conflict(e);
        }
    }

    /**
     * Requests the withdrawal of an active group-scoped class version (PR 21 Q-41): its groups fall back to the
     * {@code ANY} baseline once the request has the same two approvals as an activation (removing a stricter group rule
     * loosens policy). A security administrator requests it with a reason; the approvals use the normal approval route
     * on the request's version.
     */
    public PolicyRuleVersion requestWithdrawal(String ruleId, int version, RetireRequest body, String loginName,
                                               Set<String> sessionRoles) {
        requireSecurityAdmin(sessionRoles, "WITHDRAW_ROLE_MISSING",
            "Only a security administrator requests a withdrawal.");
        if (!RegistryVocabulary.KIND_CLASS.equals(RegistryVocabulary.kindOf(ruleId))) {
            throw new RegistryRefusal(HttpStatus.NOT_FOUND, "UNKNOWN_RULE",
                "Only a group-scoped DLP class version is withdrawn.");
        }
        String reason = reasonText(body == null ? null : body.reason(), "INVALID_WITHDRAWAL", "withdrawal");
        String author = pseudonym(loginName);
        try {
            return database.policyRegistry().requestWithdrawal(ruleId, version, reason, author,
                new AuditContext(author, "policy.withdraw_request", reason, UUID.randomUUID().toString()));
        } catch (RegistryConflict e) {
            throw conflict(e);
        }
    }

    private static void requireSecurityAdmin(Set<String> sessionRoles, String reason, String message) {
        if (!sessionRoles.contains(Roles.SECURITY_ADMIN) || sessionRoles.contains(Roles.REPLAY_VIEWER)) {
            throw new RegistryRefusal(HttpStatus.FORBIDDEN, reason, message);
        }
    }

    /**
     * A free-text reason (retirement, withdrawal): 1 to 500 characters on one line, and no identifier (PR 21 review
     * D-06): nothing a Tier-1 detector finds (secret shapes, TCKN, IBAN, payment cards), nothing the free-text masking
     * layers would change (e-mail and IP addresses, phone numbers, domain accounts, host names, numbers glued to letters,
     * a Turkish person's name) and no estate-dictionary term, because unmasked roles read it in full on the row and in
     * the ledger. A vendor endpoint of an approved platform row may be named: it is public, not estate data. The refusal
     * never echoes the text.
     */
    String reasonText(String raw, String invalidReason, String what) {
        String reason = raw == null ? "" : raw.strip();
        if (reason.isEmpty() || reason.length() > MAX_RETIRE_REASON || reason.chars().anyMatch(Character::isISOControl)) {
            throw new RegistryRefusal(HttpStatus.BAD_REQUEST, invalidReason,
                "A " + what + " needs a reason of 1 to 500 characters on one line.");
        }
        // PR 16 review D-05: a free value written to the registry never names the estate.
        if (namesEstate(reason)) {
            throw estateRefused();
        }
        if (!masking.available()) {
            throw new RegistryRefusal(HttpStatus.SERVICE_UNAVAILABLE, "MASKING_UNAVAILABLE",
                "The reason cannot be checked for identifiers without the masking key and dictionary; nothing changed.");
        }
        // A number glued to letters (a TCKN, a phone or a customer number as "ref<digits>") escapes the detectors'
        // boundary rule: six or more digits in a row are refused too (leak probe); the free-text layers find the rest
        // (a person's name, hosts other than vendor endpoints, domain accounts, IBAN shapes).
        if (IdentifierCheck.identifierShape(reason)
            || !masking.masker().maskFreeText(reason, vendorHosts()).equals(reason)) {
            throw new RegistryRefusal(HttpStatus.BAD_REQUEST, "REASON_HOLDS_IDENTIFIER",
                "The reason holds an identifier (an address, a number or a name the masking rules recognise); describe "
                    + "the reason without it.");
        }
        return reason;
    }

    /**
     * The public vendor endpoints of the registry's approved platform rows (active, superseded or retired; never a
     * draft nobody approved; PLATFORM_MATRIX §2): an API or login host as written, or a host equal to or under a host
     * suffix. Rows that name an estate term were refused when drafted.
     */
    private java.util.function.Predicate<String> vendorHosts() {
        Set<String> exact = new java.util.HashSet<>();
        List<String> suffixes = new ArrayList<>();
        for (PolicyRuleVersion v : database.policyRegistry().versions()) {
            if (RegistryVocabulary.KIND_PLATFORM.equals(v.kind())
                && Set.of("active", "superseded", "retired").contains(v.status())) {
                lower(v.apiHosts()).forEach(exact::add);
                lower(v.loginHosts()).forEach(exact::add);
                suffixes.addAll(lower(v.hostSuffixes()));
            }
        }
        return host -> exact.contains(host)
            || suffixes.stream().anyMatch(s -> host.equals(s) || host.endsWith("." + s));
    }

    /** The registry left by a retirement must still compile (every class, the flow, at least one platform row). */
    void checkRetirement(List<PolicyRuleVersion> active) {
        try {
            compiler.compile(active);
        } catch (RegistryRefusal e) {
            throw new RegistryRefusal(HttpStatus.CONFLICT, "RETIRE_WOULD_NOT_COMPILE",
                "This retirement would leave a registry that does not compile (" + e.reason() + "); nothing changed.");
        }
    }

    private boolean rowNamesEstate(PlatformRow row) {
        for (List<String> hosts : List.of(row.hostSuffixes(), row.apiHosts(), row.loginHosts())) {
            if (hosts.stream().anyMatch(this::namesEstate)) {
                return true;
            }
        }
        return false;
    }

    /**
     * True when {@code value} contains an estate-dictionary term, compared on Turkish-folded letters and digits only
     * (so {@code SYNTHETIC_ESTATE_X} matches the term {@code synthetic-estate}); the shared check (PR 24 review D-04).
     * Without the dictionary it refuses with 503 instead of passing the value.
     */
    boolean namesEstate(String value) {
        return identifiers.namesEstate(value);
    }

    static boolean carriesIdentifier(String value) {
        return IdentifierCheck.identifierShape(value);
    }

    private static RegistryRefusal estateRefused() {
        return new RegistryRefusal(HttpStatus.CONFLICT, "ESTATE_NAME_REFUSED",
            "Registry values name vendor endpoints and vocabulary only; a value matches the estate dictionary.");
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
                && "all".equals(v.rolloutStage()) && !v.scopedToGroups()) {
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
