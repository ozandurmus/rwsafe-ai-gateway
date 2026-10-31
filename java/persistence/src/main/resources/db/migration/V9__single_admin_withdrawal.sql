-- V9: a group-scoped class version is withdrawn by one security_admin with a reason (PO decision Q-41, 2026-10-31,
-- docs/design/PO_DECISION_RECORD_2026_10_31_Q41_Q42_Q44.md). It supersedes the V3 withdrawal request, which took the two
-- approvals of an activation.
--
-- 1. The withdrawal is one update of the active group-scoped version itself: status 'withdrawn', with the time, the
--    administrator's pseudonym (withdrawn_by) and the reason (withdrawal_reason). The guard requires that the ledger's
--    actor is that administrator and that the ledger's reason is the stored reason, as for a platform retirement. The row
--    is never deleted and never becomes active again; its groups fall back to the ANY baseline.
-- 2. No new withdrawal request is accepted (withdraws_version stays NULL on every new row). Rows a V3 database already
--    holds keep their history: an active request stays the marker of the scope it withdrew, a withdrawn target keeps its
--    time; a pending request is superseded below and can never be activated.
-- The V2 and V3 invariants stay as they were.

ALTER TABLE policy_rule_version
    ADD COLUMN withdrawn_by text CHECK (withdrawn_by ~ '^USR-[0-9a-f]{10}$');

ALTER TABLE policy_rule_version DROP CONSTRAINT policy_rule_version_withdrawal_shape;
ALTER TABLE policy_rule_version ADD CONSTRAINT policy_rule_version_withdrawal_shape CHECK (
    -- A V3 withdrawal request: names an older version of its own group scope and carries its reason.
    (withdraws_version IS NULL OR (withdrawal_reason IS NOT NULL AND withdrawn_by IS NULL AND kind = 'class_action'
                                   AND scope_kind = 'GROUPS' AND withdraws_version < version))
    AND (status = 'withdrawn') = (withdrawn_at IS NOT NULL)
    AND (status <> 'withdrawn' OR (kind = 'class_action' AND scope_kind = 'GROUPS' AND withdraws_version IS NULL
                                   AND activated_at IS NOT NULL))
    -- A Q-41 withdrawal names its administrator and its reason together; a reason without either is a V3 request.
    AND (withdrawn_by IS NULL OR (status = 'withdrawn' AND withdrawal_reason IS NOT NULL))
    AND (withdrawal_reason IS NULL OR withdraws_version IS NOT NULL OR withdrawn_by IS NOT NULL));

-- The V3 guard with the single-administrator withdrawal.
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
    -- A pending version is superseded by a newer draft, with its platform's retirement (D-01), or, for a V3 withdrawal
    -- request, at any time (it never takes effect).
    IF OLD.status = 'pending' AND NEW.status = 'superseded' AND OLD.withdraws_version IS NULL AND NOT EXISTS (
            SELECT 1 FROM policy_rule_version r
             WHERE r.rule_id = OLD.rule_id AND (r.version > OLD.version OR r.status = 'retired')) THEN
        RAISE EXCEPTION 'POLICY_NO_REPLACEMENT: a pending version is superseded only by a newer draft or a retirement'
            USING ERRCODE = 'check_violation';
    END IF;
    -- Generated keys are computed after BEFORE triggers, so they are left out of the comparison (they follow the key).
    IF (to_jsonb(NEW) - 'status' - 'activated_at' - 'superseded_at' - 'retired_at' - 'retired_by' - 'retired_reason'
            - 'withdrawn_at' - 'withdrawn_by' - 'withdrawal_reason' - 'version_key' - 'scope_key')
        IS DISTINCT FROM (to_jsonb(OLD) - 'status' - 'activated_at' - 'superseded_at' - 'retired_at' - 'retired_by'
            - 'retired_reason' - 'withdrawn_at' - 'withdrawn_by' - 'withdrawal_reason' - 'version_key' - 'scope_key') THEN
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
        IF roles < 2 OR people < 2 THEN
            RAISE EXCEPTION 'POLICY_APPROVAL_REQUIRED: %@v% has % of 2 approvals', NEW.rule_id, NEW.version, approvals
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

-- A V3 withdrawal request still pending stops counting (its approvals with it), ledgered as the migration's own change.
-- The settings are local to the migration's transaction.
SELECT set_config('app.actor_fingerprint', 'system:migration', true),
       set_config('app.action_id', 'policy.withdraw_request_retired', true),
       set_config('app.reason_code', 'Q41_SINGLE_ADMIN_WITHDRAWAL', true);
UPDATE policy_rule_version SET status = 'superseded', superseded_at = now()
 WHERE status = 'pending' AND withdraws_version IS NOT NULL;
SELECT set_config('app.actor_fingerprint', '', true),
       set_config('app.action_id', '', true),
       set_config('app.reason_code', '', true);
