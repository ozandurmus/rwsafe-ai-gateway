package io.rwsafe.persistence;

import static io.rwsafe.persistence.Schema.*;

import io.rwsafe.persistence.PolicyRuleVersion.Draft;
import io.rwsafe.persistence.PolicyRuleVersion.PolicyApproval;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;
import org.jooq.Condition;
import org.jooq.DSLContext;
import org.jooq.Field;
import org.jooq.Record;
import org.jooq.exception.DataAccessException;
import org.jooq.impl.DSL;

/**
 * The policy registry's versioned rules (AGENTS.md section 6). A registry version enters {@code pending} and becomes
 * {@code active} with the second of two approvals, one per role and by two different people; the database triggers
 * refuse every other path (V2). Changes to one rule are serialised by a transaction-scoped advisory lock, and every
 * mutation carries an {@link AuditContext} the ledger trigger records.
 */
public final class PolicyRegistryStore {

    public static final String ROLE_SECURITY_ADMIN = "security_admin";
    public static final String ROLE_PRIVACY_OFFICER = "privacy_officer";

    private final DSLContext dsl;

    PolicyRegistryStore(DSLContext dsl) {
        this.dsl = dsl;
    }

    public boolean empty() {
        return dsl.fetchCount(RULE_VERSION) == 0;
    }

    /**
     * Imports the committed fixture as version 1 of each rule, active. Runs once: when any version exists nothing is
     * written and false is returned.
     */
    public boolean seed(List<Draft> rules, AuditContext audit) {
        return dsl.transactionResult(cfg -> {
            DSLContext tx = DSL.using(cfg);
            tx.select(DSL.field("pg_advisory_xact_lock(hashtext('rwsafe.policy_registry.seed'))")).fetch();
            if (tx.fetchCount(RULE_VERSION) > 0) {
                return false;
            }
            audit.apply(tx);
            Instant now = Instant.now();
            for (Draft d : rules) {
                insert(tx, d, 1, "active", "seed", now);
            }
            return true;
        });
    }

    /** Every version of every rule, by rule id and newest version first, with its approvals. */
    public List<PolicyRuleVersion> versions() {
        return read(dsl, DSL.trueCondition());
    }

    /** The active versions (the snapshot compiles the active enforce baselines). */
    public List<PolicyRuleVersion> active() {
        return activeIn(dsl);
    }

    static List<PolicyRuleVersion> activeIn(DSLContext ctx) {
        return read(ctx, RV_STATUS.eq("active"));
    }

    public Optional<PolicyRuleVersion> version(String ruleId, int version) {
        return read(dsl, RV_RULE_ID.eq(ruleId).and(RV_VERSION.eq(version))).stream().findFirst();
    }

    /**
     * Adds the next version of {@code draft.ruleId()} as {@code pending}. A rule has at most one pending version per mode
     * and scope (drafts for different scopes run side by side): an earlier pending one of the same mode and
     * scope (with whatever approvals it gathered) is superseded, so an approval given to an older draft can never be
     * completed later by a single person (PR 16 review D-03).
     */
    public PolicyRuleVersion draft(Draft draft, AuditContext audit) {
        return refusalsAsConflicts(() -> dsl.transactionResult(cfg -> {
            DSLContext tx = DSL.using(cfg);
            lockRule(tx, draft.ruleId());
            int next = nextVersion(tx, draft.ruleId());
            audit.apply(tx);
            insert(tx, draft, next, "pending", "registry", null);
            supersedeOlderPending(tx, draft.ruleId(), next);
            return read(tx, RV_RULE_ID.eq(draft.ruleId()).and(RV_VERSION.eq(next))).get(0);
        }));
    }

    /**
     * Withdraws an active group-scoped class version (PO decision Q-41, 2026-10-31): one {@code security_admin}'s action
     * with a reason, no second approval, effective at once. The row stays (status {@code withdrawn}, with the time, the
     * administrator's pseudonym and the reason); it leaves the active set, so the next snapshot no longer carries it and
     * its groups fall back to the {@code ANY} baseline. It never becomes active again: the scope comes back only as a new
     * version under the two approvals. The ledger records the update with {@code audit}, whose actor must be
     * {@code administratorFingerprint} and whose reason must be {@code reason} (the V9 trigger checks both).
     *
     * @param withdrawCheck runs on the would-be active versions inside the same transaction; an exception it throws
     *                      rolls the withdrawal back
     * @throws RegistryConflict {@code POLICY_VERSION_NOT_FOUND} for an unknown version, {@code WITHDRAWAL_NOT_APPLICABLE}
     *                          when the version is not an active group-scoped class version
     */
    public PolicyRuleVersion withdrawScope(String ruleId, int version, String administratorFingerprint, String reason,
                                           AuditContext audit, Consumer<List<PolicyRuleVersion>> withdrawCheck) {
        return refusalsAsConflicts(() -> dsl.transactionResult(cfg -> {
            DSLContext tx = DSL.using(cfg);
            lockRule(tx, ruleId);
            PolicyRuleVersion target = read(tx, RV_RULE_ID.eq(ruleId).and(RV_VERSION.eq(version))).stream()
                .findFirst().orElseThrow(() -> new RegistryConflict("POLICY_VERSION_NOT_FOUND", "No such rule version."));
            if (!"active".equals(target.status()) || !target.scopedToGroups() || target.withdrawalRequest()
                || !"class_action".equals(target.kind())) {
                throw new RegistryConflict("WITHDRAWAL_NOT_APPLICABLE",
                    "Only an active group-scoped class version is withdrawn.");
            }
            audit.apply(tx);
            // The transaction's time: the guard lets this withdrawal (and no older one) supersede the scope's drafts.
            Field<Instant> now = DSL.field("now()", RV_WITHDRAWN_AT.getDataType());
            tx.update(RULE_VERSION).set(RV_STATUS, "withdrawn").set(RV_WITHDRAWN_AT, now)
                .set(RV_WITHDRAWN_BY, administratorFingerprint).set(RV_WITHDRAWAL_REASON, reason)
                .where(RV_RULE_ID.eq(ruleId).and(RV_VERSION.eq(version))).execute();
            // PR 30 review D-01 (as PR 21 D-01 for retirement): a pending draft of the withdrawn rule, mode and scope
            // (and any approval it holds) stops counting, so one approver can never bring the scope back by completing
            // a draft started before the withdrawal. Drafts of other scopes and modes keep waiting.
            tx.update(RULE_VERSION).set(RV_STATUS, "superseded").set(RV_SUPERSEDED_AT, now)
                .where(RV_RULE_ID.eq(ruleId).and(RV_STATUS.eq("pending")).and(RV_MODE.eq(target.mode()))
                    .and(RV_SCOPE_KEY.eq(tx.select(RV_SCOPE_KEY).from(RULE_VERSION)
                        .where(RV_RULE_ID.eq(ruleId).and(RV_VERSION.eq(version))).fetchOne(RV_SCOPE_KEY))))
                .execute();
            withdrawCheck.accept(activeIn(tx));
            return read(tx, RV_RULE_ID.eq(ruleId).and(RV_VERSION.eq(version))).get(0);
        }));
    }

    private static int nextVersion(DSLContext tx, String ruleId) {
        Integer max = tx.select(DSL.max(RV_VERSION)).from(RULE_VERSION).where(RV_RULE_ID.eq(ruleId))
            .fetchOne(0, Integer.class);
        return max == null ? 1 : max + 1;
    }

    /** Supersedes the older pending versions of the new version's rule, mode and scope. */
    private static void supersedeOlderPending(DSLContext tx, String ruleId, int version) {
        Record created = tx.select(RV_MODE, RV_SCOPE_KEY).from(RULE_VERSION)
            .where(RV_RULE_ID.eq(ruleId).and(RV_VERSION.eq(version))).fetchOne();
        tx.update(RULE_VERSION).set(RV_STATUS, "superseded").set(RV_SUPERSEDED_AT, Instant.now())
            .where(RV_RULE_ID.eq(ruleId).and(RV_STATUS.eq("pending")).and(RV_VERSION.lt(version))
                .and(RV_MODE.eq(created.get(RV_MODE))).and(RV_SCOPE_KEY.eq(created.get(RV_SCOPE_KEY))))
            .execute();
    }

    /**
     * Records one approval of a pending version; with the second (the other role, another person) the version becomes
     * active and supersedes what it replaces: every active version of its rule, mode and scope (a new version is stage
     * {@code all}; a legacy staged row of the same scope is replaced with the baseline). Versions of other scopes keep
     * applying: an {@code ANY} version and a group-scoped version of one rule are active side by side.
     *
     * @param approverFingerprint the approver's {@code USR-} pseudonym
     * @param activation          the ledger context of the activation, applied after the approval's
     * @param activationCheck     runs on the would-be active versions inside the same transaction when this approval
     *                            activates the version; an exception it throws rolls the approval and the activation
     *                            back (PR 16 review D-04: an activation that would not compile is refused)
     * @throws RegistryConflict when the version is not pending, a newer version of the rule is active, the role is
     *                          already filled, or the approver already approved this version
     */
    public PolicyRuleVersion approve(String ruleId, int version, String role, String approverFingerprint,
                                     AuditContext audit, AuditContext activation,
                                     Consumer<List<PolicyRuleVersion>> activationCheck) {
        return refusalsAsConflicts(() -> dsl.transactionResult(cfg -> {
            DSLContext tx = DSL.using(cfg);
            lockRule(tx, ruleId);
            Record row = tx.select(RV_STATUS, RV_MODE, RV_STAGE, RV_SCOPE_KEY).from(RULE_VERSION)
                .where(RV_RULE_ID.eq(ruleId).and(RV_VERSION.eq(version))).forUpdate().fetchOne();
            if (row == null) {
                throw new RegistryConflict("POLICY_VERSION_NOT_FOUND", "No such rule version.");
            }
            if (!"pending".equals(row.get(RV_STATUS))) {
                throw new RegistryConflict("POLICY_NOT_PENDING", "Only a pending version takes approvals.");
            }
            String mode = row.get(RV_MODE);
            String scopeKey = row.get(RV_SCOPE_KEY);
            if (tx.fetchExists(RULE_VERSION, RV_RULE_ID.eq(ruleId).and(RV_MODE.eq(mode)).and(RV_SCOPE_KEY.eq(scopeKey))
                .and(RV_STATUS.eq("active")).and(RV_VERSION.gt(version)))) {
                throw new RegistryConflict("NEWER_VERSION_ACTIVE",
                    "A newer version of this rule is active; draft again from it.");
            }
            for (Record a : tx.select(AP_ROLE, AP_APPROVER).from(APPROVAL)
                .where(AP_RULE_ID.eq(ruleId).and(AP_VERSION.eq(version))).fetch()) {
                if (a.get(AP_APPROVER).equals(approverFingerprint)) {
                    throw new RegistryConflict("APPROVER_ALREADY_APPROVED",
                        "The two approvals must come from two different people.");
                }
                if (a.get(AP_ROLE).equals(role)) {
                    throw new RegistryConflict("APPROVAL_ROLE_TAKEN", "This role has already approved this version.");
                }
            }
            audit.apply(tx);
            tx.insertInto(APPROVAL, AP_RULE_ID, AP_VERSION, AP_ROLE, AP_APPROVER)
                .values(ruleId, version, role, approverFingerprint).execute();
            int roles = tx.fetchCount(tx.selectDistinct(AP_ROLE).from(APPROVAL)
                .where(AP_RULE_ID.eq(ruleId).and(AP_VERSION.eq(version))));
            if (roles == 2) {
                activation.apply(tx);
                Instant now = Instant.now();
                // The new version first, then what it replaces: the guard supersedes an active version only when a
                // newer active one exists (the one-active constraints are checked at commit).
                tx.update(RULE_VERSION).set(RV_STATUS, "active").set(RV_ACTIVATED_AT, now)
                    .where(RV_RULE_ID.eq(ruleId).and(RV_VERSION.eq(version))).execute();
                Condition replaced = RV_RULE_ID.eq(ruleId).and(RV_MODE.eq(mode)).and(RV_SCOPE_KEY.eq(scopeKey))
                    .and(RV_STATUS.eq("active")).and(RV_VERSION.lt(version));
                if (!"all".equals(row.get(RV_STAGE))) {
                    replaced = replaced.and(RV_STAGE.ne("all"));
                }
                tx.update(RULE_VERSION).set(RV_STATUS, "superseded").set(RV_SUPERSEDED_AT, now).where(replaced).execute();
                activationCheck.accept(activeIn(tx));
            }
            return read(tx, RV_RULE_ID.eq(ruleId).and(RV_VERSION.eq(version))).get(0);
        }));
    }

    /**
     * Retires every active version of a platform rule (PO decision Q-40): one {@code security_admin}'s action with a
     * reason, no second approval. The rows stay (status {@code retired}, with the time, the administrator's pseudonym
     * and the reason); the next snapshot no longer carries the platform. A retired version never becomes active again: a
     * platform comes back only as a new version under the two approvals. The ledger records the update with
     * {@code audit}, whose actor must be {@code administratorFingerprint} (the trigger checks it).
     *
     * @param retireCheck runs on the would-be active versions inside the same transaction; an exception it throws rolls
     *                    the retirement back (a retirement that would leave no compilable snapshot is refused)
     * @throws RegistryConflict {@code POLICY_VERSION_NOT_FOUND} when the rule has no active version
     */
    public List<PolicyRuleVersion> retirePlatform(String ruleId, String administratorFingerprint, String reason,
                                                  AuditContext audit, Consumer<List<PolicyRuleVersion>> retireCheck) {
        return refusalsAsConflicts(() -> dsl.transactionResult(cfg -> {
            DSLContext tx = DSL.using(cfg);
            lockRule(tx, ruleId);
            Condition activeRows = RV_RULE_ID.eq(ruleId).and(RV_KIND.eq("platform")).and(RV_STATUS.eq("active"));
            if (!tx.fetchExists(RULE_VERSION, activeRows)) {
                throw new RegistryConflict("POLICY_VERSION_NOT_FOUND", "The platform has no active version to retire.");
            }
            audit.apply(tx);
            List<Integer> versions = tx.select(RV_VERSION).from(RULE_VERSION).where(activeRows).forUpdate()
                .fetch(RV_VERSION);
            tx.update(RULE_VERSION).set(RV_STATUS, "retired").set(RV_RETIRED_AT, Instant.now())
                .set(RV_RETIRED_BY, administratorFingerprint).set(RV_RETIRED_REASON, reason)
                .where(RV_RULE_ID.eq(ruleId).and(RV_VERSION.in(versions))).execute();
            // PR 21 review D-01: a pending draft of the retired platform (and any approval it holds) stops counting, so
            // one approver can never bring the platform back by completing a draft started before the retirement.
            tx.update(RULE_VERSION).set(RV_STATUS, "superseded").set(RV_SUPERSEDED_AT, Instant.now())
                .where(RV_RULE_ID.eq(ruleId).and(RV_STATUS.eq("pending"))).execute();
            retireCheck.accept(activeIn(tx));
            return read(tx, RV_RULE_ID.eq(ruleId).and(RV_VERSION.in(versions)));
        }));
    }

    private static void lockRule(DSLContext tx, String ruleId) {
        tx.select(DSL.field("pg_advisory_xact_lock(hashtext({0}))", DSL.val("rwsafe.policy_rule:" + ruleId))).fetch();
    }

    private static void insert(DSLContext tx, Draft d, int version, String status, String source, Instant activatedAt) {
        tx.insertInto(RULE_VERSION)
            .set(RV_RULE_ID, d.ruleId())
            .set(RV_VERSION, version)
            .set(RV_KIND, d.kind())
            .set(RV_DATA_CLASS, d.dataClass())
            .set(RV_ACTION, d.action())
            .set(RV_PLATFORM, d.platformId())
            .set(RV_HOST_SUFFIXES, array(d.hostSuffixes()))
            .set(RV_API_HOSTS, array(d.apiHosts()))
            .set(RV_LOGIN_HOSTS, array(d.loginHosts()))
            .set(RV_ENFORCE_FAIL_CLOSED, d.enforceFailClosed())
            .set(RV_MODE, d.mode())
            .set(RV_STAGE, d.rolloutStage())
            .set(RV_SCOPE_KIND, d.scopeKind())
            .set(RV_SCOPE_GROUPS, d.scopeGroups().toArray(String[]::new))
            .set(RV_STATUS, status)
            .set(RV_SOURCE, source)
            .set(RV_AUTHOR, d.authorFingerprint())
            .set(RV_REASON, d.reasonCode())
            .set(RV_ACTIVATED_AT, activatedAt)
            .execute();
    }

    private static String[] array(List<String> values) {
        return values == null ? null : values.toArray(String[]::new);
    }

    private static List<String> list(String[] values) {
        return values == null ? null : List.of(values);
    }

    private static List<PolicyRuleVersion> read(DSLContext ctx, Condition where) {
        List<Field<?>> fields = List.of(RV_RULE_ID, RV_VERSION, RV_KIND, RV_DATA_CLASS, RV_ACTION, RV_PLATFORM,
            RV_HOST_SUFFIXES, RV_API_HOSTS, RV_LOGIN_HOSTS, RV_ENFORCE_FAIL_CLOSED, RV_MODE, RV_STAGE, RV_STATUS,
            RV_SOURCE, RV_AUTHOR, RV_REASON, RV_CREATED_AT, RV_ACTIVATED_AT, RV_SUPERSEDED_AT, RV_SCOPE_KIND,
            RV_SCOPE_GROUPS, RV_RETIRED_AT, RV_RETIRED_BY, RV_RETIRED_REASON, RV_WITHDRAWS, RV_WITHDRAWAL_REASON,
            RV_WITHDRAWN_AT, RV_WITHDRAWN_BY);
        List<Record> rows = ctx.select(fields).from(RULE_VERSION).where(where)
            .orderBy(RV_RULE_ID, RV_VERSION.desc()).fetch();
        Map<String, List<PolicyApproval>> approvals = new LinkedHashMap<>();
        if (!rows.isEmpty()) {
            Condition sameVersions = DSL.row(AP_RULE_ID, AP_VERSION).in(rows.stream()
                .map(r -> DSL.row(r.get(RV_RULE_ID), r.get(RV_VERSION))).toList());
            for (Record a : ctx.select(AP_RULE_ID, AP_VERSION, AP_ROLE, AP_APPROVER, AP_APPROVED_AT).from(APPROVAL)
                .where(sameVersions).orderBy(AP_APPROVED_AT).fetch()) {
                approvals.computeIfAbsent(a.get(AP_RULE_ID) + "@v" + a.get(AP_VERSION), k -> new ArrayList<>())
                    .add(new PolicyApproval(a.get(AP_ROLE), a.get(AP_APPROVER), a.get(AP_APPROVED_AT)));
            }
        }
        List<PolicyRuleVersion> out = new ArrayList<>(rows.size());
        for (Record r : rows) {
            out.add(new PolicyRuleVersion(r.get(RV_RULE_ID), r.get(RV_VERSION), r.get(RV_KIND), r.get(RV_DATA_CLASS),
                r.get(RV_ACTION), r.get(RV_PLATFORM), list(r.get(RV_HOST_SUFFIXES)), list(r.get(RV_API_HOSTS)),
                list(r.get(RV_LOGIN_HOSTS)), r.get(RV_ENFORCE_FAIL_CLOSED), r.get(RV_MODE), r.get(RV_STAGE),
                r.get(RV_STATUS), r.get(RV_SOURCE), r.get(RV_AUTHOR), r.get(RV_REASON), r.get(RV_CREATED_AT),
                r.get(RV_ACTIVATED_AT), r.get(RV_SUPERSEDED_AT),
                approvals.getOrDefault(r.get(RV_RULE_ID) + "@v" + r.get(RV_VERSION), List.of()), r.get(RV_SCOPE_KIND),
                list(r.get(RV_SCOPE_GROUPS)), r.get(RV_RETIRED_AT) == null ? null
                    : new PolicyRuleVersion.Retirement(r.get(RV_RETIRED_AT), r.get(RV_RETIRED_BY),
                        r.get(RV_RETIRED_REASON)),
                r.get(RV_WITHDRAWS), r.get(RV_WITHDRAWAL_REASON), r.get(RV_WITHDRAWN_AT), r.get(RV_WITHDRAWN_BY)));
        }
        return out;
    }

    /**
     * A constraint or trigger refusal (SQL state class 23, or a trigger's {@code CODE: sentence}) becomes a
     * {@link RegistryConflict} with the trigger's code, so the database is a backstop that names its reason.
     */
    static <T> T refusalsAsConflicts(java.util.function.Supplier<T> work) {
        try {
            return work.get();
        } catch (DataAccessException e) {
            String state = e.sqlState();
            if (state != null && (state.startsWith("23") || state.equals("42501"))) {
                throw new RegistryConflict(triggerCode(e.getMessage()), "The registry refused this change.");
            }
            throw e;
        }
    }

    /** {@code POLICY_LIFECYCLE} from {@code ... ERROR: POLICY_LIFECYCLE: active -> pending ...}; a generic code else. */
    static String triggerCode(String message) {
        if (message != null) {
            int at = message.indexOf("ERROR: ");
            if (at >= 0) {
                int start = at + "ERROR: ".length();
                int end = start;
                while (end < message.length() && (Character.isUpperCase(message.charAt(end)) || message.charAt(end) == '_')) {
                    end++;
                }
                if (end > start + 2 && end < message.length() && message.charAt(end) == ':') {
                    return message.substring(start, end);
                }
            }
        }
        return "POLICY_CONSTRAINT_REFUSED";
    }
}
