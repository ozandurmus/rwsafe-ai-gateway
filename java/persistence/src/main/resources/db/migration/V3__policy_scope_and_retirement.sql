-- V3: scoped rule versions and platform retirement (PO_DECISION_RECORD_2026_10_30_POLICY_SCOPE_AND_PLATFORM_RETIREMENT,
-- POLICY_SNAPSHOT_CONTRACT "Format 2: scoped rules").
--
-- 1. Every rule version has a source scope: ANY (everyone) or GROUPS (1 to 32 short directory group names, each 1 to 256
--    characters, stored in normal form, distinct). Only a DLP class rule takes a group scope (a format 2 scoped
--    rule carries class actions only). Directory group names are runtime data the operator types; no committed file holds
--    one.
-- 2. One active version per rule, mode and scope key ('any', or the sorted, lower-cased group list). The percentage
--    rollout stages are retired: a new version is stage 'all'; existing rows keep theirs as history.
-- 3. A platform row may be retired by one security_admin with a non-empty reason (no second approval). A retired row is
--    never deleted and never becomes active again; a platform comes back only as a new version under two approvals.
--    The retire is ledgered by the existing audit trigger; the guard requires that the ledger's actor is the retiring
--    administrator and that the ledger's reason is the reason stored on the row.
-- 4. A verdict event may name the scoped-rule ids that applied (or, as monitor rules, would have applied).
-- The V2 invariants stay: two approvals by two people for activation, fail-closed classes never ALLOW or WARN (in any
-- scope: the V2 check applies to every class row whatever its scope), append-only approvals, snapshots and ledger.

-- The uniqueness key of a scope: 'any', or the JSON array of the lower-cased, trimmed group names in byte order.
CREATE FUNCTION rwsafe_scope_key(kind text, groups text[]) RETURNS text LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE WHEN kind = 'ANY' THEN 'any'
        ELSE 'groups:' || coalesce((SELECT jsonb_agg(g ORDER BY g COLLATE "C")::text
                                      FROM (SELECT DISTINCT lower(btrim(x)) AS g FROM unnest(groups) AS x) AS s), '[]')
    END
$$;

-- A group list as stored: every name already in the normal form the control plane writes and the data plane compares
-- (strip, NFC, the four Turkish and Latin i forms folded to 'i', lower case, no combining dot above; the control plane's
-- GroupNames): trimmed, NFC, none of U+0130, 'I', U+0131 or U+0307 left, 1 to 256 characters, no comma, no control
-- character, distinct. The full lower-case mapping is the control plane's (Locale.ROOT); the database checks the shape.
CREATE FUNCTION rwsafe_scope_groups_ok(groups text[]) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
    SELECT coalesce(bool_and(g = btrim(g) AND g IS NFC NORMALIZED AND length(g) BETWEEN 1 AND 256
                             AND g !~ '[[:cntrl:],]' AND strpos(g, 'I') = 0 AND strpos(g, U&'\0130') = 0
                             AND strpos(g, U&'\0131') = 0 AND strpos(g, U&'\0307') = 0), true)
        AND (SELECT count(DISTINCT g) FROM unnest(groups) AS g) = coalesce(cardinality(groups), 0)
    FROM unnest(groups) AS g
$$;

ALTER TABLE policy_rule_version
    ADD COLUMN scope_kind     text        NOT NULL DEFAULT 'ANY' CHECK (scope_kind IN ('ANY', 'GROUPS')),
    ADD COLUMN scope_groups   text[]      NOT NULL DEFAULT '{}' CHECK (rwsafe_scope_groups_ok(scope_groups)),
    ADD COLUMN scope_key      text        GENERATED ALWAYS AS (rwsafe_scope_key(scope_kind, scope_groups)) STORED,
    ADD COLUMN retired_at     timestamptz,
    ADD COLUMN retired_by     text        CHECK (retired_by ~ '^USR-[0-9a-f]{10}$'),
    ADD COLUMN retired_reason text        CHECK (retired_reason = btrim(retired_reason)
                                                 AND length(retired_reason) BETWEEN 1 AND 500
                                                 AND retired_reason !~ '[[:cntrl:]]'),
    ADD CONSTRAINT policy_rule_version_scope_shape CHECK (CASE scope_kind
        WHEN 'ANY' THEN cardinality(scope_groups) = 0
        ELSE kind = 'class_action' AND cardinality(scope_groups) BETWEEN 1 AND 32
    END),
    ADD CONSTRAINT policy_rule_version_retired_shape CHECK (
        (status = 'retired') = (retired_at IS NOT NULL)
        AND (status = 'retired') = (retired_by IS NOT NULL)
        AND (status = 'retired') = (retired_reason IS NOT NULL)
        AND (status <> 'retired' OR (kind = 'platform' AND activated_at IS NOT NULL)));

ALTER TABLE policy_rule_version DROP CONSTRAINT policy_rule_version_status_check;
ALTER TABLE policy_rule_version ADD CONSTRAINT policy_rule_version_status_check
    CHECK (status IN ('pending', 'active', 'superseded', 'retired'));

-- One active version per rule, mode and scope (the stage-'all' baseline); legacy staged rows keep the V2 staged
-- exclusion. Deferred, as in V2, so an activation can write the new version before it supersedes the old one.
ALTER TABLE policy_rule_version DROP CONSTRAINT policy_rule_version_one_baseline;
ALTER TABLE policy_rule_version ADD CONSTRAINT policy_rule_version_one_active_per_scope
    EXCLUDE USING btree (rule_id WITH =, mode WITH =, scope_key WITH =)
    WHERE (status = 'active' AND rollout_stage = 'all') DEFERRABLE INITIALLY DEFERRED;

-- The V2 guard with scopes and retirement. Changes from V2: a new version is stage 'all' (POLICY_STAGE_RETIRED); an
-- active version is superseded only by a newer active version of the same rule, mode and scope; active -> retired is
-- the platform-only, one-administrator transition with a reason; retired is terminal.
CREATE OR REPLACE FUNCTION rwsafe_policy_rule_version_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    approvals integer;
    roles     integer;
    people    integer;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status = 'retired' OR NEW.retired_at IS NOT NULL THEN
            RAISE EXCEPTION 'POLICY_LIFECYCLE: a version is retired only from active'
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
    IF OLD.status = 'retired' AND (NEW.status <> 'retired' OR NEW.retired_at IS DISTINCT FROM OLD.retired_at
            OR NEW.retired_by IS DISTINCT FROM OLD.retired_by
            OR NEW.retired_reason IS DISTINCT FROM OLD.retired_reason) THEN
        RAISE EXCEPTION 'POLICY_RETIRED_FINAL: a retired version never changes; draft a new version'
            USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.status = NEW.status AND (NEW.activated_at IS DISTINCT FROM OLD.activated_at
            OR NEW.superseded_at IS DISTINCT FROM OLD.superseded_at
            OR NEW.retired_at IS DISTINCT FROM OLD.retired_at OR NEW.retired_by IS DISTINCT FROM OLD.retired_by
            OR NEW.retired_reason IS DISTINCT FROM OLD.retired_reason) THEN
        RAISE EXCEPTION 'POLICY_LIFECYCLE: the lifecycle fields change only with the status'
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
    IF OLD.status = 'active' AND NEW.status = 'superseded' AND NOT EXISTS (
            SELECT 1 FROM policy_rule_version r
             WHERE r.rule_id = OLD.rule_id AND r.mode = OLD.mode AND r.status = 'active' AND r.version > OLD.version
               AND rwsafe_scope_key(r.scope_kind, r.scope_groups) = rwsafe_scope_key(OLD.scope_kind, OLD.scope_groups)
               AND (OLD.rollout_stage <> 'all' OR r.rollout_stage = 'all')) THEN
        RAISE EXCEPTION 'POLICY_NO_REPLACEMENT: an active version is superseded only by a newer active one of its scope'
            USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.status = 'pending' AND NEW.status = 'superseded' AND NOT EXISTS (
            SELECT 1 FROM policy_rule_version r WHERE r.rule_id = OLD.rule_id AND r.version > OLD.version) THEN
        RAISE EXCEPTION 'POLICY_NO_REPLACEMENT: a pending version is superseded only by a newer draft'
            USING ERRCODE = 'check_violation';
    END IF;
    -- Generated keys are computed after BEFORE triggers, so they are left out of the comparison (they follow the key).
    IF (to_jsonb(NEW) - 'status' - 'activated_at' - 'superseded_at' - 'retired_at' - 'retired_by' - 'retired_reason'
            - 'version_key' - 'scope_key')
        IS DISTINCT FROM (to_jsonb(OLD) - 'status' - 'activated_at' - 'superseded_at' - 'retired_at' - 'retired_by'
            - 'retired_reason' - 'version_key' - 'scope_key') THEN
        RAISE EXCEPTION 'POLICY_VERSION_IMMUTABLE: a rule version never changes; draft a new one'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NOT ((OLD.status = 'pending' AND NEW.status IN ('active', 'superseded'))
            OR (OLD.status = 'active' AND NEW.status IN ('superseded', 'retired')) OR OLD.status = NEW.status) THEN
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
-- that matched and would have changed the verdict, "monitorRuleIds"): at most 16 each, each a registry rule id and
-- version of at most 128 characters. Never a group name.
CREATE FUNCTION rwsafe_rule_id_list_ok(ids text[]) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
    SELECT coalesce(cardinality(ids), 0) <= 16
        AND coalesce(bool_and(length(i) <= 128
                              AND i ~ '^(class|platform|flow)\.[A-Za-z0-9_-]{1,64}@[1-9][0-9]{0,9}$'), true)
    FROM unnest(ids) AS i
$$;

ALTER TABLE verdict_event
    ADD COLUMN applied_rule_ids text[] NOT NULL DEFAULT '{}' CHECK (rwsafe_rule_id_list_ok(applied_rule_ids)),
    ADD COLUMN monitor_rule_ids text[] NOT NULL DEFAULT '{}' CHECK (rwsafe_rule_id_list_ok(monitor_rule_ids));
