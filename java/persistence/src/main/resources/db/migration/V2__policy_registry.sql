-- V2: the policy registry (AGENTS.md section 6, ADR-008 §4, ADR-010) and the record of every issued policy snapshot
-- (docs/architecture/POLICY_SNAPSHOT_CONTRACT.md). Every rule is a versioned, exact entry; a version made through the
-- registry becomes active only with two approvals (security_admin and privacy_officer, two different people); the seed
-- versions come from the source-committed fixture under policy/, whose approval is its pull request. Every mutation is
-- ledgered by the C7 audit trigger; approvals and issued snapshots are append-only. No column holds a prompt, a response
-- or an estate name: a rule names a DLP class, an action or vendor-published host names (PLATFORM_MATRIX §2).

-- A host-name list as the snapshot carries it: lower-case DNS names with at least one dot, never an address literal.
CREATE FUNCTION rwsafe_host_list_ok(hosts text[]) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
    SELECT coalesce(bool_and(h ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
                             AND h !~ '^[0-9.]+$' AND length(h) <= 253), true)
    FROM unnest(hosts) AS h
$$;

CREATE TABLE policy_rule_version (
    rule_id              text        NOT NULL CHECK (rule_id ~ '^(class|platform|flow)\.[A-Za-z0-9_-]{1,64}$'),
    version              integer     NOT NULL CHECK (version > 0),
    -- The ledger's row key (the audit trigger names one column).
    version_key          text        GENERATED ALWAYS AS (rule_id || '@v' || version) STORED,
    kind                 text        NOT NULL CHECK (kind IN ('class_action', 'platform', 'flow')),
    data_class           text        CHECK (data_class IN ('SECRET', 'TCKN', 'TR_IBAN', 'PAYMENT_CARD')),
    action               text        CHECK (action IN ('ALLOW', 'WARN', 'REDACT', 'BLOCK')),
    platform_id          text        CHECK (platform_id ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
    host_suffixes        text[]      CHECK (rwsafe_host_list_ok(host_suffixes)),
    api_hosts            text[]      CHECK (rwsafe_host_list_ok(api_hosts)),
    login_hosts          text[]      CHECK (rwsafe_host_list_ok(login_hosts)),
    enforce_fail_closed  boolean,
    -- monitor: recorded and simulated next to the live verdict, never in a snapshot (for the fail-closed classes this is
    -- ADR-008's shadow evaluation: the seed baseline keeps enforcing).
    mode                 text        NOT NULL CHECK (mode IN ('monitor', 'enforce')),
    rollout_stage        text        NOT NULL CHECK (rollout_stage IN ('pilot', 'pct25', 'pct50', 'all')),
    status               text        NOT NULL CHECK (status IN ('pending', 'active', 'superseded')),
    source               text        NOT NULL CHECK (source IN ('seed', 'registry')),
    author_fingerprint   text        NOT NULL CHECK (author_fingerprint ~ '^(USR-[0-9a-f]{10}|system:[a-z_-]{1,32})$'),
    reason_code          text        NOT NULL CHECK (reason_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),
    created_at           timestamptz NOT NULL DEFAULT now(),
    activated_at         timestamptz,
    superseded_at        timestamptz,
    PRIMARY KEY (rule_id, version),
    CONSTRAINT policy_rule_version_shape CHECK (CASE kind
        WHEN 'class_action' THEN data_class IS NOT NULL AND action IS NOT NULL AND rule_id = 'class.' || data_class
            AND platform_id IS NULL AND host_suffixes IS NULL AND api_hosts IS NULL AND login_hosts IS NULL
            AND enforce_fail_closed IS NULL
        WHEN 'platform' THEN platform_id IS NOT NULL AND rule_id = 'platform.' || platform_id
            AND host_suffixes IS NOT NULL AND api_hosts IS NOT NULL AND login_hosts IS NOT NULL
            AND cardinality(host_suffixes) BETWEEN 1 AND 32 AND cardinality(api_hosts) <= 32
            AND cardinality(login_hosts) <= 32
            AND data_class IS NULL AND action IS NULL AND enforce_fail_closed IS NULL
        ELSE rule_id = 'flow.ai-category' AND enforce_fail_closed IS NOT NULL AND data_class IS NULL AND action IS NULL
            AND platform_id IS NULL AND host_suffixes IS NULL AND api_hosts IS NULL AND login_hosts IS NULL
    END),
    -- SR-DLP-1, ADR-010: every Tier-1 class is fail-closed, so an enforce version never allows or warns it, and the
    -- AI-category flow is never relaxed in enforce mode.
    CONSTRAINT policy_rule_version_fail_closed_class CHECK (
        NOT (kind = 'class_action' AND mode = 'enforce' AND action IN ('ALLOW', 'WARN'))),
    CONSTRAINT policy_rule_version_fail_closed_flow CHECK (
        NOT (kind = 'flow' AND mode = 'enforce' AND NOT enforce_fail_closed)),
    CONSTRAINT policy_rule_version_lifecycle CHECK ((status = 'pending') = (activated_at IS NULL)
        AND (status = 'superseded') = (superseded_at IS NOT NULL))
);

-- One active baseline (stage all) and one active staged version per rule and mode.
CREATE UNIQUE INDEX policy_rule_version_one_baseline ON policy_rule_version (rule_id, mode)
    WHERE status = 'active' AND rollout_stage = 'all';
CREATE UNIQUE INDEX policy_rule_version_one_staged ON policy_rule_version (rule_id, mode)
    WHERE status = 'active' AND rollout_stage <> 'all';

CREATE TABLE policy_approval (
    rule_id               text        NOT NULL,
    version               integer     NOT NULL,
    approver_role         text        NOT NULL CHECK (approver_role IN ('security_admin', 'privacy_officer')),
    -- A person's pseudonym only: an approval is never a system actor's.
    approver_fingerprint  text        NOT NULL CHECK (approver_fingerprint ~ '^USR-[0-9a-f]{10}$'),
    approved_at           timestamptz NOT NULL DEFAULT now(),
    approval_key          text        GENERATED ALWAYS AS (rule_id || '@v' || version || ':' || approver_role) STORED,
    PRIMARY KEY (rule_id, version, approver_role),
    -- Two approvals are two different people.
    UNIQUE (rule_id, version, approver_fingerprint),
    FOREIGN KEY (rule_id, version) REFERENCES policy_rule_version (rule_id, version)
);

-- A seed version enters active; a registry version enters pending. Afterwards only the lifecycle columns change, along
-- pending -> active -> superseded, and pending -> active needs both approvals by two different people.
CREATE FUNCTION rwsafe_policy_rule_version_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    approvals integer;
    roles     integer;
    people    integer;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.source = 'registry' AND NEW.status <> 'pending' THEN
            RAISE EXCEPTION 'POLICY_APPROVAL_REQUIRED: a registry version starts pending'
                USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.source = 'seed' AND NEW.status <> 'active' THEN
            RAISE EXCEPTION 'POLICY_SEED_SHAPE: a seed version starts active' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;
    -- The generated key is computed after BEFORE triggers, so it is left out of the comparison (it follows the key).
    IF (to_jsonb(NEW) - 'status' - 'activated_at' - 'superseded_at' - 'version_key')
        IS DISTINCT FROM (to_jsonb(OLD) - 'status' - 'activated_at' - 'superseded_at' - 'version_key') THEN
        RAISE EXCEPTION 'POLICY_VERSION_IMMUTABLE: a rule version never changes; draft a new one'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF NOT ((OLD.status = 'pending' AND NEW.status = 'active') OR (OLD.status = 'active' AND NEW.status = 'superseded')
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

CREATE TRIGGER policy_rule_version_guard BEFORE INSERT OR UPDATE ON policy_rule_version
    FOR EACH ROW EXECUTE FUNCTION rwsafe_policy_rule_version_guard();
CREATE TRIGGER policy_rule_version_no_delete BEFORE DELETE ON policy_rule_version
    FOR EACH ROW EXECUTE FUNCTION rwsafe_audit_append_only();
CREATE TRIGGER policy_rule_version_no_truncate BEFORE TRUNCATE ON policy_rule_version
    FOR EACH STATEMENT EXECUTE FUNCTION rwsafe_audit_append_only();
CREATE TRIGGER policy_rule_version_audit AFTER INSERT OR UPDATE ON policy_rule_version
    FOR EACH ROW EXECUTE FUNCTION rwsafe_audit_row('version_key');

-- An approval names a pending version.
CREATE FUNCTION rwsafe_policy_approval_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM policy_rule_version
                   WHERE rule_id = NEW.rule_id AND version = NEW.version AND status = 'pending') THEN
        RAISE EXCEPTION 'POLICY_NOT_PENDING: only a pending version takes approvals' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER policy_approval_guard BEFORE INSERT ON policy_approval
    FOR EACH ROW EXECUTE FUNCTION rwsafe_policy_approval_guard();
CREATE TRIGGER policy_approval_no_update_or_delete BEFORE UPDATE OR DELETE ON policy_approval
    FOR EACH ROW EXECUTE FUNCTION rwsafe_audit_append_only();
CREATE TRIGGER policy_approval_no_truncate BEFORE TRUNCATE ON policy_approval
    FOR EACH STATEMENT EXECUTE FUNCTION rwsafe_audit_append_only();
CREATE TRIGGER policy_approval_audit AFTER INSERT ON policy_approval
    FOR EACH ROW EXECUTE FUNCTION rwsafe_audit_row('approval_key');

-- Every snapshot the control plane issued (POLICY_SNAPSHOT_CONTRACT "Control plane behaviour"): the version, the id, the
-- exact signed document and its digest, the rule versions it compiled and their approvers. Versions only grow
-- (OFF2-11); rows are append-only and ledgered.
CREATE TABLE policy_snapshot (
    version          bigint      PRIMARY KEY CHECK (version > 0),
    snapshot_id      text        NOT NULL CHECK (snapshot_id ~ '^registry-[0-9a-f]{12}$'),
    issued_at        timestamptz NOT NULL,
    rules_digest     text        NOT NULL CHECK (rules_digest ~ '^[0-9a-f]{64}$'),
    document_sha256  text        NOT NULL CHECK (document_sha256 ~ '^[0-9a-f]{64}$'),
    document         text        NOT NULL CHECK (length(document) BETWEEN 2 AND 1048576),
    rule_versions    text[]      NOT NULL CHECK (cardinality(rule_versions) > 0),
    approvers        text[]      NOT NULL CHECK (cardinality(approvers) > 0),
    recorded_at      timestamptz NOT NULL DEFAULT now()
);

CREATE FUNCTION rwsafe_policy_snapshot_monotonic() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM policy_snapshot WHERE version >= NEW.version) THEN
        RAISE EXCEPTION 'SNAPSHOT_VERSION_NOT_MONOTONIC: % is not above every issued version', NEW.version
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER policy_snapshot_monotonic BEFORE INSERT ON policy_snapshot
    FOR EACH ROW EXECUTE FUNCTION rwsafe_policy_snapshot_monotonic();
CREATE TRIGGER policy_snapshot_no_update_or_delete BEFORE UPDATE OR DELETE ON policy_snapshot
    FOR EACH ROW EXECUTE FUNCTION rwsafe_audit_append_only();
CREATE TRIGGER policy_snapshot_no_truncate BEFORE TRUNCATE ON policy_snapshot
    FOR EACH STATEMENT EXECUTE FUNCTION rwsafe_audit_append_only();
CREATE TRIGGER policy_snapshot_audit AFTER INSERT ON policy_snapshot
    FOR EACH ROW EXECUTE FUNCTION rwsafe_audit_row('version');
