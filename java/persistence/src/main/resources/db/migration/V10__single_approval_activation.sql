-- V10: the pilot-only single-approval activation (PO decision Q-47, decision 2, 2026-11-02,
-- docs/design/PO_DECISION_RECORD_2026_11_02_Q47_ADMIN_SECTION.md). While the control plane's switch
-- RWSAFE_POLICY_SINGLE_APPROVAL is on (the pilot overlay only), one security_admin's approval with a reason activates a
-- pending version alone. It amends the two-approval rule of V2/V3/V9 for that path only; every other activation still
-- needs two approvals, one per role, by two different people.
--
-- 1. The activation is recorded on the version itself: the administrator's pseudonym (single_approval_by) and the reason
--    (single_approval_reason), written once, by the pending -> active transition only, never on insert. The snapshot
--    compiler accepts a version with one approval only when it carries both, and the one approval is that
--    administrator's security_admin approval.
-- 2. The guard accepts such an activation only when the transaction declares the switch on (app.single_approval = 'on',
--    set by the store only when the control plane's switch is on), the version holds exactly one approval, the
--    security_admin approval of single_approval_by, and the ledger row of the activation names that administrator, the
--    action policy.activate_single_approval and the stored reason.
-- The V9 invariants stay as they were.

ALTER TABLE policy_rule_version
    ADD COLUMN single_approval_by     text CHECK (single_approval_by ~ '^USR-[0-9a-f]{10}$'),
    ADD COLUMN single_approval_reason text CHECK (rwsafe_reason_text_ok(single_approval_reason)),
    ADD CONSTRAINT policy_rule_version_single_approval_shape CHECK (
        (single_approval_by IS NULL) = (single_approval_reason IS NULL)
        AND (single_approval_by IS NULL OR (source = 'registry' AND status <> 'pending' AND activated_at IS NOT NULL
                                            AND withdraws_version IS NULL)));

-- The V9 guard with the single-approval activation.
CREATE OR REPLACE FUNCTION rwsafe_policy_rule_version_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    approvals integer;
    roles     integer;
    people    integer;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status IN ('retired', 'withdrawn') OR NEW.retired_at IS NOT NULL OR NEW.withdrawn_at IS NOT NULL
                OR NEW.withdrawn_by IS NOT NULL THEN
            RAISE EXCEPTION 'POLICY_LIFECYCLE: a version is retired or withdrawn only from active'
                USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.single_approval_by IS NOT NULL OR NEW.single_approval_reason IS NOT NULL THEN
            RAISE EXCEPTION 'POLICY_SINGLE_APPROVAL_REFUSED: a single-approval activation is written by the activation only'
                USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.withdraws_version IS NOT NULL OR NEW.withdrawal_reason IS NOT NULL THEN
            RAISE EXCEPTION 'POLICY_WITHDRAWAL_REQUEST_RETIRED: a group scope is withdrawn on its version, by one administrator'
                USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.source = 'registry' AND NEW.status <> 'pending' THEN
            RAISE EXCEPTION 'POLICY_APPROVAL_REQUIRED: a registry version starts pending'
                USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.source = 'seed' AND (NEW.status <> 'active' OR NEW.version <> 1 OR NEW.mode <> 'enforce'
                OR NEW.rollout_stage <> 'all' OR NEW.scope_kind <> 'ANY'
                OR NEW.author_fingerprint <> 'system:seed-fixture' OR NEW.reason_code <> 'SEED_FIXTURE') THEN
            RAISE EXCEPTION 'POLICY_SEED_SHAPE: a seed version is version 1, active, enforce, stage all, scope ANY, by the fixture'
                USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.source = 'seed' AND EXISTS (SELECT 1 FROM policy_rule_version WHERE source = 'registry') THEN
            RAISE EXCEPTION 'POLICY_SEED_CLOSED: the seed is imported into an empty registry only'
                USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.rollout_stage <> 'all' THEN
            RAISE EXCEPTION 'POLICY_STAGE_RETIRED: a new version is stage all; scope by group instead'
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;
    -- D-05: every lifecycle time is written once, by the transition it records.
    IF NEW.activated_at IS DISTINCT FROM OLD.activated_at AND NOT (OLD.status = 'pending' AND NEW.status = 'active') THEN
        RAISE EXCEPTION 'POLICY_LIFECYCLE: the activation time is written by the activation only'
            USING ERRCODE = 'check_violation';
    END IF;
    -- Q-47: the single-approval fields are written once, by the activation they record.
    IF (NEW.single_approval_by IS DISTINCT FROM OLD.single_approval_by
            OR NEW.single_approval_reason IS DISTINCT FROM OLD.single_approval_reason)
            AND NOT (OLD.status = 'pending' AND NEW.status = 'active') THEN
        RAISE EXCEPTION 'POLICY_SINGLE_APPROVAL_FINAL: the single-approval fields are written by the activation only'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.superseded_at IS DISTINCT FROM OLD.superseded_at
            AND NOT (OLD.status <> 'superseded' AND NEW.status = 'superseded') THEN
        RAISE EXCEPTION 'POLICY_LIFECYCLE: the supersede time is written by the supersede only'
            USING ERRCODE = 'check_violation';
    END IF;
    IF (NEW.retired_at IS DISTINCT FROM OLD.retired_at OR NEW.retired_by IS DISTINCT FROM OLD.retired_by
            OR NEW.retired_reason IS DISTINCT FROM OLD.retired_reason)
            AND NOT (OLD.status <> 'retired' AND NEW.status = 'retired') THEN
        RAISE EXCEPTION 'POLICY_RETIRED_FINAL: the retirement fields are written by the retirement only'
            USING ERRCODE = 'check_violation';
    END IF;
    IF (NEW.withdrawn_at IS DISTINCT FROM OLD.withdrawn_at OR NEW.withdrawn_by IS DISTINCT FROM OLD.withdrawn_by
            OR NEW.withdrawal_reason IS DISTINCT FROM OLD.withdrawal_reason)
            AND NOT (OLD.status <> 'withdrawn' AND NEW.status = 'withdrawn') THEN
        RAISE EXCEPTION 'POLICY_WITHDRAWN_FINAL: the withdrawal fields are written by the withdrawal only'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.status = 'retired' AND OLD.status <> 'retired' THEN
        IF OLD.status <> 'active' OR OLD.kind <> 'platform' THEN
            RAISE EXCEPTION 'POLICY_RETIRE_REFUSED: only an active platform row is retired'
                USING ERRCODE = 'check_violation';
        END IF;
        -- The ledger row of this update names the same administrator and carries the same reason.
        IF NEW.retired_by IS NULL OR current_setting('app.actor_fingerprint', true) IS DISTINCT FROM NEW.retired_by
                OR current_setting('app.reason_code', true) IS DISTINCT FROM NEW.retired_reason THEN
            RAISE EXCEPTION 'POLICY_RETIRE_REFUSED: the ledger names the retiring administrator and the reason'
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    -- Q-41 (2026-10-31): one administrator withdraws an active group-scoped class version with a reason.
    IF NEW.status = 'withdrawn' AND OLD.status <> 'withdrawn' THEN
        IF OLD.status <> 'active' OR OLD.kind <> 'class_action' OR OLD.scope_kind <> 'GROUPS'
                OR OLD.withdraws_version IS NOT NULL THEN
            RAISE EXCEPTION 'POLICY_WITHDRAWAL_REFUSED: only an active group-scoped class version is withdrawn'
                USING ERRCODE = 'check_violation';
        END IF;
        -- The ledger row of this update names the same administrator and carries the same reason.
        IF NEW.withdrawn_by IS NULL OR NEW.withdrawal_reason IS NULL
                OR current_setting('app.actor_fingerprint', true) IS DISTINCT FROM NEW.withdrawn_by
                OR current_setting('app.reason_code', true) IS DISTINCT FROM NEW.withdrawal_reason THEN
            RAISE EXCEPTION 'POLICY_WITHDRAWAL_REFUSED: the ledger names the withdrawing administrator and the reason'
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    -- A V3 withdrawal request still pending is never activated (it would take effect under the retired two-approval
    -- path); it may only be superseded.
    IF OLD.status = 'pending' AND NEW.status = 'active' AND OLD.withdraws_version IS NOT NULL THEN
        RAISE EXCEPTION 'POLICY_WITHDRAWAL_REQUEST_RETIRED: a withdrawal request is never activated'
            USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.status = 'active' AND NEW.status = 'superseded' AND NOT EXISTS (
            SELECT 1 FROM policy_rule_version r
             WHERE r.rule_id = OLD.rule_id AND r.mode = OLD.mode AND r.status = 'active' AND r.version > OLD.version
               AND r.withdraws_version IS NULL
               AND rwsafe_scope_key(r.scope_kind, r.scope_groups) = rwsafe_scope_key(OLD.scope_kind, OLD.scope_groups)
               AND (OLD.rollout_stage <> 'all' OR r.rollout_stage = 'all')) THEN
        RAISE EXCEPTION 'POLICY_NO_REPLACEMENT: an active version is superseded only by a newer active one of its scope'
            USING ERRCODE = 'check_violation';
    END IF;
    -- A pending version is superseded by a newer draft of its own mode and scope, with the withdrawal of its mode and
    -- scope in the same transaction (PR 30 review D-01; the withdrawal time is the transaction's), with its platform's
    -- retirement (PR 21 D-01), or, for a V3 withdrawal request, at any time (it never takes effect).
    IF OLD.status = 'pending' AND NEW.status = 'superseded' AND OLD.withdraws_version IS NULL AND NOT EXISTS (
            SELECT 1 FROM policy_rule_version r
             WHERE r.rule_id = OLD.rule_id
               AND ((r.mode = OLD.mode
                     AND rwsafe_scope_key(r.scope_kind, r.scope_groups) = rwsafe_scope_key(OLD.scope_kind, OLD.scope_groups)
                     AND (r.version > OLD.version OR (r.status = 'withdrawn' AND r.withdrawn_at = now())))
                    OR r.status = 'retired')) THEN
        RAISE EXCEPTION 'POLICY_NO_REPLACEMENT: a pending version is superseded only by a newer draft of its scope, a withdrawal of its scope or a retirement'
            USING ERRCODE = 'check_violation';
    END IF;
    -- Generated keys are computed after BEFORE triggers, so they are left out of the comparison (they follow the key).
    IF (to_jsonb(NEW) - 'status' - 'activated_at' - 'superseded_at' - 'retired_at' - 'retired_by' - 'retired_reason'
            - 'withdrawn_at' - 'withdrawn_by' - 'withdrawal_reason' - 'single_approval_by' - 'single_approval_reason'
            - 'version_key' - 'scope_key')
        IS DISTINCT FROM (to_jsonb(OLD) - 'status' - 'activated_at' - 'superseded_at' - 'retired_at' - 'retired_by'
            - 'retired_reason' - 'withdrawn_at' - 'withdrawn_by' - 'withdrawal_reason' - 'single_approval_by'
            - 'single_approval_reason' - 'version_key' - 'scope_key') THEN
        RAISE EXCEPTION 'POLICY_VERSION_IMMUTABLE: a rule version never changes; draft a new one'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NOT ((OLD.status = 'pending' AND NEW.status IN ('active', 'superseded'))
            OR (OLD.status = 'active' AND NEW.status IN ('superseded', 'retired', 'withdrawn'))
            OR OLD.status = NEW.status) THEN
        RAISE EXCEPTION 'POLICY_LIFECYCLE: % -> % is refused', OLD.status, NEW.status
            USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.status = 'pending' AND NEW.status = 'active' THEN
        SELECT count(*), count(DISTINCT approver_role), count(DISTINCT approver_fingerprint)
          INTO approvals, roles, people
          FROM policy_approval WHERE rule_id = NEW.rule_id AND version = NEW.version;
        IF NEW.single_approval_by IS NOT NULL THEN
            -- Q-47: the switch is on for this transaction, the one approval is the named administrator's as
            -- security_admin, and the ledger row of the activation names that administrator, the action and the reason.
            IF current_setting('app.single_approval', true) IS DISTINCT FROM 'on' OR approvals <> 1
                    OR NOT EXISTS (SELECT 1 FROM policy_approval a
                                    WHERE a.rule_id = NEW.rule_id AND a.version = NEW.version
                                      AND a.approver_role = 'security_admin'
                                      AND a.approver_fingerprint = NEW.single_approval_by)
                    OR current_setting('app.actor_fingerprint', true) IS DISTINCT FROM NEW.single_approval_by
                    OR current_setting('app.action_id', true) IS DISTINCT FROM 'policy.activate_single_approval'
                    OR current_setting('app.reason_code', true) IS DISTINCT FROM NEW.single_approval_reason THEN
                RAISE EXCEPTION 'POLICY_SINGLE_APPROVAL_REFUSED: %@v% is not a single-approval activation by its one security administrator', NEW.rule_id, NEW.version
                    USING ERRCODE = 'check_violation';
            END IF;
        ELSIF roles < 2 OR people < 2 THEN
            RAISE EXCEPTION 'POLICY_APPROVAL_REQUIRED: %@v% has % of 2 approvals', NEW.rule_id, NEW.version, approvals
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
