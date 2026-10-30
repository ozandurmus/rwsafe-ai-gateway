-- V3: scoped rule versions, platform retirement and scope withdrawal (PO_DECISION_RECORD_2026_10_30_POLICY_SCOPE_AND_
-- PLATFORM_RETIREMENT, POLICY_SNAPSHOT_CONTRACT "Format 2: scoped rules", PR 21 review D-01..D-06 and Q-41).
--
-- 1. Every rule version has a source scope: ANY (everyone) or GROUPS (1 to 32 short directory group names, each 1 to 256
--    characters, stored in the shared normal form of java/policy GroupNames, distinct). Only a DLP class rule takes a
--    group scope (a format 2 scoped rule carries class actions only); platform and flow rows are enforce only.
--    Directory group names are runtime data the operator types; no committed file holds one.
-- 2. One active version and one pending version per rule, mode and scope key ('any', or the sorted, lower-cased group
--    list). The percentage rollout stages are retired: a new version is stage 'all'; existing rows keep theirs.
-- 3. A platform row may be retired by one security_admin with a non-empty reason (no second approval). A retired row is
--    never deleted and never becomes active again; its pending drafts are superseded with it (D-01); a platform comes
--    back only as a new version under two approvals. The guard requires that the ledger's actor is the retiring
--    administrator and that the ledger's reason is the reason stored on the row.
-- 4. Q-41: an active group-scoped class version is withdrawn (its groups fall back to ANY) through a withdrawal request: a
--    pending version of the same rule, mode and scope that names the withdrawn version and a reason, and takes the same
--    two approvals as an activation. Its activation turns the target 'withdrawn' (terminal, history kept); the request
--    row stays active as the scope's marker and is never compiled.
-- 5. A verdict event may name the scoped-rule ids that applied (or, as monitor rules, would have applied).
-- The V2 invariants stay: two approvals by two people for activation, fail-closed classes never ALLOW or WARN (in any
-- scope: the V2 check applies to every class row whatever its scope), append-only approvals, snapshots and ledger. Every
-- lifecycle time is written once, by its own transition (D-05).

-- The uniqueness key of a scope: 'any', or the JSON array of the lower-cased, trimmed group names in byte order.
CREATE FUNCTION rwsafe_scope_key(kind text, groups text[]) RETURNS text LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE WHEN kind = 'ANY' THEN 'any'
        ELSE 'groups:' || coalesce((SELECT jsonb_agg(g ORDER BY g COLLATE "C")::text
                                      FROM (SELECT DISTINCT lower(btrim(x)) AS g FROM unnest(groups) AS x) AS s), '[]')
    END
$$;

-- A group list as stored: every name already in the normal form java/policy GroupNames writes and the data plane
-- compares (strip, NFC, the four Turkish and Latin i forms folded to 'i', lower case, a combining dot above after an i
-- removed, NFC): trimmed, NFC, lower case, none of U+0130, 'I', U+0131 or 'i' + U+0307 left, 1 to 256 characters, no
-- comma, no control character, distinct ignoring case (PR 21 review D-05).
CREATE FUNCTION rwsafe_scope_groups_ok(groups text[]) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
    SELECT coalesce(bool_and(g = btrim(g) AND g IS NFC NORMALIZED AND g = lower(g) AND length(g) BETWEEN 1 AND 256
                             AND g !~ '[\x01-\x1f\x7f,]' AND strpos(g, 'I') = 0 AND strpos(g, U&'\0130') = 0
                             AND strpos(g, U&'\0131') = 0 AND strpos(g, U&'i\0307') = 0), true)
        AND (SELECT count(DISTINCT lower(g)) FROM unnest(groups) AS g) = coalesce(cardinality(groups), 0)
    FROM unnest(groups) AS g
$$;

-- A free-text reason (retirement, withdrawal): trimmed, 1 to 500 characters, one line.
CREATE FUNCTION rwsafe_reason_text_ok(reason text) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
    SELECT reason = btrim(reason) AND length(reason) BETWEEN 1 AND 500 AND reason !~ '[[:cntrl:]]'
$$;

ALTER TABLE policy_rule_version
    ADD COLUMN scope_kind        text        NOT NULL DEFAULT 'ANY' CHECK (scope_kind IN ('ANY', 'GROUPS')),
    ADD COLUMN scope_groups      text[]      NOT NULL DEFAULT '{}' CHECK (rwsafe_scope_groups_ok(scope_groups)),
    ADD COLUMN scope_key         text        GENERATED ALWAYS AS (rwsafe_scope_key(scope_kind, scope_groups)) STORED,
    ADD COLUMN retired_at        timestamptz,
    ADD COLUMN retired_by        text        CHECK (retired_by ~ '^USR-[0-9a-f]{10}$'),
    ADD COLUMN retired_reason    text        CHECK (rwsafe_reason_text_ok(retired_reason)),
    ADD COLUMN withdraws_version integer     CHECK (withdraws_version > 0),
    ADD COLUMN withdrawal_reason text        CHECK (rwsafe_reason_text_ok(withdrawal_reason)),
    ADD COLUMN withdrawn_at      timestamptz,
    ADD CONSTRAINT policy_rule_version_scope_shape CHECK (CASE scope_kind
        WHEN 'ANY' THEN cardinality(scope_groups) = 0
        ELSE kind = 'class_action' AND cardinality(scope_groups) BETWEEN 1 AND 32
    END),
    -- PR 21 review D-06: a platform row or the flow is enforced or not at all (a monitor platform row is never sent).
    ADD CONSTRAINT policy_rule_version_enforce_only CHECK (kind = 'class_action' OR mode = 'enforce'),
    ADD CONSTRAINT policy_rule_version_retired_shape CHECK (
        (status = 'retired') = (retired_at IS NOT NULL)
        AND (status = 'retired') = (retired_by IS NOT NULL)
        AND (status = 'retired') = (retired_reason IS NOT NULL)
        AND (status <> 'retired' OR (kind = 'platform' AND activated_at IS NOT NULL))),
    ADD CONSTRAINT policy_rule_version_withdrawal_shape CHECK (
        (withdraws_version IS NULL) = (withdrawal_reason IS NULL)
        AND (withdraws_version IS NULL OR (kind = 'class_action' AND scope_kind = 'GROUPS'
                                           AND withdraws_version < version))
        AND (status = 'withdrawn') = (withdrawn_at IS NOT NULL)
        AND (status <> 'withdrawn' OR (kind = 'class_action' AND scope_kind = 'GROUPS' AND withdraws_version IS NULL
                                       AND activated_at IS NOT NULL)));

ALTER TABLE policy_rule_version DROP CONSTRAINT policy_rule_version_status_check;
ALTER TABLE policy_rule_version ADD CONSTRAINT policy_rule_version_status_check
    CHECK (status IN ('pending', 'active', 'superseded', 'retired', 'withdrawn'));

-- One active version per rule, mode and scope (the stage-'all' baseline); legacy staged rows keep the V2 staged
-- exclusion. One pending version per rule, mode and scope (Q-41: drafts for different scopes run side by side). Deferred,
-- as in V2, so an activation or a draft can write the new version before it replaces the old one.
ALTER TABLE policy_rule_version DROP CONSTRAINT policy_rule_version_one_baseline;
ALTER TABLE policy_rule_version ADD CONSTRAINT policy_rule_version_one_active_per_scope
    EXCLUDE USING btree (rule_id WITH =, mode WITH =, scope_key WITH =)
    WHERE (status = 'active' AND rollout_stage = 'all') DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE policy_rule_version DROP CONSTRAINT policy_rule_version_one_pending;
ALTER TABLE policy_rule_version ADD CONSTRAINT policy_rule_version_one_pending_per_scope
    EXCLUDE USING btree (rule_id WITH =, mode WITH =, scope_key WITH =)
    WHERE (status = 'pending') DEFERRABLE INITIALLY DEFERRED;

-- The V2 guard with scopes, retirement and withdrawal.
CREATE OR REPLACE FUNCTION rwsafe_policy_rule_version_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    approvals integer;
    roles     integer;
    people    integer;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status IN ('retired', 'withdrawn') OR NEW.retired_at IS NOT NULL OR NEW.withdrawn_at IS NOT NULL THEN
            RAISE EXCEPTION 'POLICY_LIFECYCLE: a version is retired or withdrawn only from active'
                USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.source = 'registry' AND NEW.status <> 'pending' THEN
            RAISE EXCEPTION 'POLICY_APPROVAL_REQUIRED: a registry version starts pending'
                USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.source = 'seed' AND (NEW.status <> 'active' OR NEW.version <> 1 OR NEW.mode <> 'enforce'
                OR NEW.rollout_stage <> 'all' OR NEW.scope_kind <> 'ANY' OR NEW.withdraws_version IS NOT NULL
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
        IF NEW.withdraws_version IS NOT NULL THEN
            IF NOT EXISTS (SELECT 1 FROM policy_rule_version t
                            WHERE t.rule_id = NEW.rule_id AND t.version = NEW.withdraws_version AND t.status = 'active'
                              AND t.withdraws_version IS NULL AND t.mode = NEW.mode AND t.scope_kind = 'GROUPS'
                              AND t.data_class = NEW.data_class AND t.action = NEW.action
                              AND rwsafe_scope_key(t.scope_kind, t.scope_groups)
                                  = rwsafe_scope_key(NEW.scope_kind, NEW.scope_groups)) THEN
                RAISE EXCEPTION 'POLICY_WITHDRAWAL_REFUSED: a withdrawal names an active group-scoped version of its scope'
                    USING ERRCODE = 'check_violation';
            END IF;
            IF current_setting('app.reason_code', true) IS DISTINCT FROM NEW.withdrawal_reason THEN
                RAISE EXCEPTION 'POLICY_WITHDRAWAL_REFUSED: the ledger carries the withdrawal reason'
                    USING ERRCODE = 'check_violation';
            END IF;
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
    IF NEW.withdrawn_at IS DISTINCT FROM OLD.withdrawn_at
            AND NOT (OLD.status <> 'withdrawn' AND NEW.status = 'withdrawn') THEN
        RAISE EXCEPTION 'POLICY_LIFECYCLE: the withdrawal time is written by the withdrawal only'
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
    -- Q-41: a group-scoped version is withdrawn only by its withdrawal request, active with its two approvals.
    IF NEW.status = 'withdrawn' AND OLD.status <> 'withdrawn' AND NOT EXISTS (
            SELECT 1 FROM policy_rule_version r
             WHERE r.rule_id = OLD.rule_id AND r.withdraws_version = OLD.version AND r.status = 'active'
               AND r.mode = OLD.mode) THEN
        RAISE EXCEPTION 'POLICY_WITHDRAWAL_REFUSED: a version is withdrawn only by its approved withdrawal request'
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
    -- A pending version is superseded by a newer draft, or with its platform's retirement (D-01).
    IF OLD.status = 'pending' AND NEW.status = 'superseded' AND NOT EXISTS (
            SELECT 1 FROM policy_rule_version r
             WHERE r.rule_id = OLD.rule_id AND (r.version > OLD.version OR r.status = 'retired')) THEN
        RAISE EXCEPTION 'POLICY_NO_REPLACEMENT: a pending version is superseded only by a newer draft or a retirement'
            USING ERRCODE = 'check_violation';
    END IF;
    -- Generated keys are computed after BEFORE triggers, so they are left out of the comparison (they follow the key).
    IF (to_jsonb(NEW) - 'status' - 'activated_at' - 'superseded_at' - 'retired_at' - 'retired_by' - 'retired_reason'
            - 'withdrawn_at' - 'version_key' - 'scope_key')
        IS DISTINCT FROM (to_jsonb(OLD) - 'status' - 'activated_at' - 'superseded_at' - 'retired_at' - 'retired_by'
            - 'retired_reason' - 'withdrawn_at' - 'version_key' - 'scope_key') THEN
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

-- The scoped-rule ids a verdict event names (POLICY_SNAPSHOT_CONTRACT format 2, "appliedRuleIds"; the monitor rules
-- that matched and would have changed the verdict, "monitorRuleIds"): at most 16 each, each a DLP class rule and version
-- (`class.<CLASS>@<version>`, a known class), none twice (PR 21 review D-04). Never a group name, never a value.
CREATE FUNCTION rwsafe_rule_id_list_ok(ids text[]) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
    SELECT coalesce(cardinality(ids), 0) <= 16
        AND coalesce(bool_and(i ~ '^class\.(SECRET|TCKN|TR_IBAN|PAYMENT_CARD)@[1-9][0-9]{0,9}$'), true)
        AND (SELECT count(DISTINCT x) FROM unnest(ids) AS x) = coalesce(cardinality(ids), 0)
    FROM unnest(ids) AS i
$$;

ALTER TABLE verdict_event
    ADD COLUMN applied_rule_ids text[] NOT NULL DEFAULT '{}' CHECK (rwsafe_rule_id_list_ok(applied_rule_ids)),
    ADD COLUMN monitor_rule_ids text[] NOT NULL DEFAULT '{}' CHECK (rwsafe_rule_id_list_ok(monitor_rule_ids));
