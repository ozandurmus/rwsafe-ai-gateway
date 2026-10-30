-- V1: verdict events (ADR-009 C1 metadata, C2 verdict, C6 findings), the trigger-enforced audit ledger (C7), the local
-- break-glass account table and the sign-in record. No column holds a prompt or response body, a raw identity claim or a
-- raw client address: the control plane pseudonymises and masks before the insert (ingestion contract,
-- MASKING_AND_PRIVACY B2/B3).

CREATE TABLE verdict_event (
    event_id          uuid        PRIMARY KEY,
    received_at       timestamptz NOT NULL,
    ingested_at       timestamptz NOT NULL DEFAULT now(),
    service           text        NOT NULL CHECK (service IN ('reqmod', 'respmod')),
    platform          text        NOT NULL CHECK (length(platform) BETWEEN 1 AND 64),
    surface           text        NOT NULL CHECK (length(surface) BETWEEN 1 AND 32),
    step              text        NOT NULL CHECK (length(step) BETWEEN 1 AND 32),
    verdict           text        NOT NULL CHECK (verdict IN ('ALLOW', 'WARN', 'REDACT', 'BLOCK', 'UNINSPECTABLE',
                                                              'MALFORMED', 'INSPECTION_FAILED', 'INSPECTION_TIMEOUT',
                                                              'UNKNOWN_FLOW', 'STREAM_ABORTED')),
    reason            text        CHECK (reason ~ '^[A-Za-z0-9_-]{1,64}$'),
    body_bytes        bigint      NOT NULL CHECK (body_bytes >= 0),
    decision_micros   bigint      NOT NULL CHECK (decision_micros >= 0),
    -- USR-<10 hex>: HMAC under rwsafe's own privacy key; the claim itself is never stored.
    user_pseudonym    text        CHECK (user_pseudonym ~ '^USR-[0-9a-f]{10}$'),
    -- Subnet-preserving mask in the synthetic 240/4 space (a /24 label), [REDACTED_IP] for IPv6 or [INVALID_ADDRESS];
    -- nothing else fits, so a raw address cannot be stored by mistake (PR 12 review D-06).
    client_subnet     text        CHECK (client_subnet ~ '^2(4[0-9]|5[0-5])\.([0-9]{1,3})\.([0-9]{1,3})\.0/24$'
                                         OR client_subnet IN ('[REDACTED_IP]', '[INVALID_ADDRESS]')),
    transport         text        NOT NULL CHECK (transport IN ('plain_allowlisted', 'mtls_verified')),
    snapshot_version  bigint      NOT NULL CHECK (snapshot_version >= 0),
    correlation_id    text        NOT NULL CHECK (correlation_id ~ '^[A-Za-z0-9_-]{1,64}$'),
    pseudonym_key_id  text        NOT NULL CHECK (length(pseudonym_key_id) BETWEEN 1 AND 32)
);

CREATE INDEX verdict_event_received_at ON verdict_event (received_at DESC, event_id DESC);
CREATE INDEX verdict_event_platform_received_at ON verdict_event (platform, received_at DESC);
CREATE INDEX verdict_event_verdict_received_at ON verdict_event (verdict, received_at DESC);
CREATE INDEX verdict_event_user_received_at ON verdict_event (user_pseudonym, received_at DESC)
    WHERE user_pseudonym IS NOT NULL;

-- C6: class and count per event; the digest of the matched span arrives with the data plane's digest key (ADR-009 §2)
-- and stays NULL until then. Never a value.
CREATE TABLE verdict_finding (
    event_id    uuid    NOT NULL REFERENCES verdict_event (event_id) ON DELETE CASCADE,
    data_class  text    NOT NULL CHECK (data_class ~ '^[A-Z][A-Z0-9_]{0,31}$'),
    hit_count   integer NOT NULL CHECK (hit_count > 0),
    digest      text    CHECK (digest ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (event_id, data_class)
);

-- C7 audit ledger (ARCHITECTURE.md §4.4): rows are written by the trigger below, never by the application, and are
-- append-only. The actor, action, reason and correlation come from the transaction's audit context (`app.*` settings).
CREATE TABLE audit_event (
    audit_id           bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at        timestamptz NOT NULL DEFAULT now(),
    actor_fingerprint  text        NOT NULL,
    action_id          text        NOT NULL,
    reason_code        text        NOT NULL,
    correlation_id     text,
    table_name         text        NOT NULL,
    operation          text        NOT NULL,
    row_key            text        NOT NULL
);

CREATE FUNCTION rwsafe_audit_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'AUDIT_APPEND_ONLY: % on audit_event is refused', TG_OP USING ERRCODE = 'insufficient_privilege';
END;
$$;

-- Only the audit trigger writes the ledger: a direct insert (trigger depth 1, the ledger's own trigger) is refused, so
-- the application cannot forge a row (PR 12 review D-07).
CREATE FUNCTION rwsafe_audit_insert_only_by_trigger() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF pg_trigger_depth() < 2 THEN
        RAISE EXCEPTION 'AUDIT_DIRECT_INSERT: audit_event rows are written by the audit trigger only'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER audit_event_insert_by_trigger_only BEFORE INSERT ON audit_event
    FOR EACH ROW EXECUTE FUNCTION rwsafe_audit_insert_only_by_trigger();
CREATE TRIGGER audit_event_no_update_or_delete BEFORE UPDATE OR DELETE ON audit_event
    FOR EACH ROW EXECUTE FUNCTION rwsafe_audit_append_only();
CREATE TRIGGER audit_event_no_truncate BEFORE TRUNCATE ON audit_event
    FOR EACH STATEMENT EXECUTE FUNCTION rwsafe_audit_append_only();

-- Attached to every audited table; TG_ARGV[0] names the column that identifies the row. A mutation without an audit
-- context is refused (fail closed): no admin change exists that the ledger does not name.
CREATE FUNCTION rwsafe_audit_row() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    actor  text := nullif(btrim(current_setting('app.actor_fingerprint', true)), '');
    action text := nullif(btrim(current_setting('app.action_id', true)), '');
    reason text := nullif(btrim(current_setting('app.reason_code', true)), '');
    corr   text := nullif(btrim(current_setting('app.correlation_id', true)), '');
    rec    jsonb;
BEGIN
    -- The actor is a pseudonym or a system actor, never a raw name (ARCHITECTURE.md §4.4).
    IF actor IS NULL OR action IS NULL OR reason IS NULL
        OR actor !~ '^(USR-[0-9a-f]{10}|system:[a-z_-]{1,32})$' THEN
        RAISE EXCEPTION 'AUDIT_CONTEXT_MISSING: % on % has no audit context', TG_OP, TG_TABLE_NAME
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    rec := CASE WHEN TG_OP = 'DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;
    INSERT INTO audit_event (actor_fingerprint, action_id, reason_code, correlation_id, table_name, operation, row_key)
    VALUES (actor, action, reason, corr, TG_TABLE_NAME, TG_OP, coalesce(rec ->> TG_ARGV[0], ''));
    RETURN NULL;
END;
$$;

-- Local break-glass accounts (ARCHITECTURE.md §3.2 identity). The password is stored as a BCrypt hash only; the initial
-- password is generated at first start and written to a file outside the repository (LOCAL_RUN.md).
CREATE TABLE local_account (
    account_name   text        PRIMARY KEY CHECK (account_name ~ '^[a-z][a-z0-9_-]{2,31}$'),
    password_hash  text        NOT NULL CHECK (password_hash LIKE '$2%'),
    -- The masked role is an exclusive session mode (MASKING_AND_PRIVACY B1): never combined with another role.
    roles          text[]      NOT NULL CHECK (cardinality(roles) > 0
                                   AND roles <@ ARRAY['security_admin', 'viewer', 'replay_viewer']::text[]
                                   AND (NOT 'replay_viewer' = ANY (roles) OR cardinality(roles) = 1)),
    enabled        boolean     NOT NULL DEFAULT true,
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER local_account_audit AFTER INSERT OR UPDATE OR DELETE ON local_account
    FOR EACH ROW EXECUTE FUNCTION rwsafe_audit_row('account_name');
-- A truncate bypasses row triggers, so it is refused outright (PR 12 review D-07).
CREATE TRIGGER local_account_no_truncate BEFORE TRUNCATE ON local_account
    FOR EACH STATEMENT EXECUTE FUNCTION rwsafe_audit_append_only();

-- Every accepted sign-in, ledgered by the audit trigger (ARCHITECTURE.md §4.4; PR 12 review D-02, D-09): the actor's
-- pseudonym, the authentication source and whether the session is the masked mode. Append-only.
CREATE TABLE login_record (
    login_id           bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    logged_in_at       timestamptz NOT NULL DEFAULT now(),
    -- The login name's pseudonym; only a break-glass sign-in made while the privacy key is missing is recorded under the
    -- system actor, since no pseudonym can be computed then.
    actor_fingerprint  text        NOT NULL CHECK (actor_fingerprint ~ '^USR-[0-9a-f]{10}$'
                                                   OR actor_fingerprint = 'system:break-glass'),
    source             text        NOT NULL CHECK (source IN ('ldap', 'local')),
    masked             boolean     NOT NULL
);

CREATE TRIGGER login_record_audit AFTER INSERT ON login_record
    FOR EACH ROW EXECUTE FUNCTION rwsafe_audit_row('login_id');
CREATE TRIGGER login_record_no_update_or_delete BEFORE UPDATE OR DELETE ON login_record
    FOR EACH ROW EXECUTE FUNCTION rwsafe_audit_append_only();
CREATE TRIGGER login_record_no_truncate BEFORE TRUNCATE ON login_record
    FOR EACH STATEMENT EXECUTE FUNCTION rwsafe_audit_append_only();
