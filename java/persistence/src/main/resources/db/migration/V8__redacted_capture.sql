-- V8: redacted capture (ADR-009 C3 and §2-§5; PO decisions Q-3, Q-4 b, Q-5; SR-PRIV-10, SR-PRIV-11, SR-HOST-2;
-- AGENTS.md 4.13). ADR-009 rejects bodies in PostgreSQL: the redacted text lives in the capture store, a directory on
-- its own volume (RWSAFE_CAPTURE_STORE_DIR), as content-defined chunks (8-64 KiB), each encrypted with AES-256-GCM under
-- a data key of its own. PostgreSQL holds only metadata: the record, its manifest (record -> ordered chunk list), each
-- chunk's keyed content address, its wrapped data key and reference count, the store's byte counter, the read ledger,
-- the deletion receipts and the key events. No column holds plaintext or ciphertext; the database never sees a key.
-- Deletions, holds, re-wraps, reads, receipts and key events are ledgered by the audit trigger, which the SIEM export
-- reads (ADR-009 §4: a deletion reaches the SIEM as a ledger row). (V4 is reserved by an open branch.)

-- One chunk of the store. Its address (chunk_digest) is HMAC-SHA256 of the chunk's plaintext under a key derived from
-- the capture key (keyed, so the column is no "does this text exist" oracle) and unique, so a repeated chunk is stored
-- once (ADR-009 §3). The file is named by chunk_id, never by content. The reference count is kept by the manifest
-- triggers.
CREATE TABLE capture_chunk (
    chunk_id      uuid        PRIMARY KEY,
    chunk_digest  text        NOT NULL UNIQUE CHECK (chunk_digest ~ '^[0-9a-f]{64}$'),
    key_id        text        NOT NULL CHECK (key_id ~ '^[A-Za-z0-9_-]{1,32}$'),
    -- nonce (12) || AES-GCM(capture key, chunk data key (32)) || tag (16)
    wrapped_key   bytea       NOT NULL CHECK (octet_length(wrapped_key) = 60),
    -- nonce (12) + ciphertext + tag (16) on disk; a chunk is at most 64 KiB of plaintext
    stored_bytes  integer     NOT NULL CHECK (stored_bytes BETWEEN 29 AND 65564),
    ref_count     integer     NOT NULL DEFAULT 0 CHECK (ref_count >= 0),
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX capture_chunk_key_id ON capture_chunk (key_id);
CREATE INDEX capture_chunk_unreferenced ON capture_chunk (chunk_id) WHERE ref_count = 0;

-- One captured record: who it is for (SR-PRIV-10), when it expires (at most 90 days, Q-5), whether a hold keeps it, and
-- a record key (wrapped) whose HMAC binds every column below and the ordered chunk addresses (manifest_mac), so a
-- changed expiry, user, rule set or chunk list does not open.
CREATE TABLE capture_record (
    event_id        uuid        PRIMARY KEY REFERENCES verdict_event (event_id) ON DELETE CASCADE,
    captured_at     timestamptz NOT NULL,
    expires_at      timestamptz NOT NULL,
    user_pseudonym  text        NOT NULL CHECK (user_pseudonym ~ '^USR-[0-9a-f]{10}$'),
    key_id          text        NOT NULL CHECK (key_id ~ '^[A-Za-z0-9_-]{1,32}$'),
    wrapped_key     bytea       NOT NULL CHECK (octet_length(wrapped_key) = 60),
    manifest_mac    bytea       NOT NULL CHECK (octet_length(manifest_mac) = 32),
    plain_bytes     integer     NOT NULL CHECK (plain_bytes BETWEEN 1 AND 262144),
    truncated       boolean     NOT NULL,
    -- The masking rule set applied at persistence (ADR-009 §2: layers run at persistence as well as at view).
    mask_rule_set   text        NOT NULL CHECK (mask_rule_set ~ '^[a-z0-9.-]{1,32}$'),
    legal_hold      boolean     NOT NULL DEFAULT false,
    CHECK (expires_at > captured_at - interval '30 days' AND expires_at <= captured_at + interval '90 days')
);

CREATE INDEX capture_record_expires_at ON capture_record (expires_at) WHERE NOT legal_hold;
CREATE INDEX capture_record_captured_at ON capture_record (captured_at) WHERE NOT legal_hold;
CREATE INDEX capture_record_key_id ON capture_record (key_id);

CREATE TABLE capture_manifest (
    event_id  uuid     NOT NULL REFERENCES capture_record (event_id) ON DELETE CASCADE,
    seq       smallint NOT NULL CHECK (seq BETWEEN 0 AND 63),
    chunk_id  uuid     NOT NULL REFERENCES capture_chunk (chunk_id),
    PRIMARY KEY (event_id, seq)
);

CREATE INDEX capture_manifest_chunk ON capture_manifest (chunk_id);

-- The store's byte counter (ADR-009 §3): the bytes of every chunk on disk, kept by the chunk triggers.
CREATE TABLE capture_store_usage (
    id            smallint PRIMARY KEY CHECK (id = 1),
    stored_bytes  bigint   NOT NULL CHECK (stored_bytes >= 0)
);
INSERT INTO capture_store_usage (id, stored_bytes) VALUES (1, 0);

CREATE FUNCTION rwsafe_capture_refs() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE capture_chunk SET ref_count = ref_count + 1 WHERE chunk_id = NEW.chunk_id;
    ELSE
        UPDATE capture_chunk SET ref_count = ref_count - 1 WHERE chunk_id = OLD.chunk_id;
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER capture_manifest_refs AFTER INSERT OR DELETE ON capture_manifest
    FOR EACH ROW EXECUTE FUNCTION rwsafe_capture_refs();
CREATE TRIGGER capture_manifest_no_update BEFORE UPDATE ON capture_manifest
    FOR EACH ROW EXECUTE FUNCTION rwsafe_audit_append_only();

CREATE FUNCTION rwsafe_capture_usage() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE capture_store_usage SET stored_bytes = stored_bytes + NEW.stored_bytes WHERE id = 1;
    ELSE
        UPDATE capture_store_usage SET stored_bytes = stored_bytes - OLD.stored_bytes WHERE id = 1;
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER capture_chunk_usage AFTER INSERT OR DELETE ON capture_chunk
    FOR EACH ROW EXECUTE FUNCTION rwsafe_capture_usage();

-- A chunk changes only its reference count (manifest triggers) and, in a planned key rotation, its wrapping; a record
-- only its legal hold and its wrapping (ADR-009 §4, PO decision on PR 25 Q-3).
CREATE FUNCTION rwsafe_capture_chunk_mutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (to_jsonb(NEW) - 'ref_count' - 'key_id' - 'wrapped_key')
        IS DISTINCT FROM (to_jsonb(OLD) - 'ref_count' - 'key_id' - 'wrapped_key') THEN
        RAISE EXCEPTION 'CAPTURE_IMMUTABLE: only the references and the wrapping of a chunk may change'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION rwsafe_capture_record_mutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (to_jsonb(NEW) - 'legal_hold' - 'key_id' - 'wrapped_key')
        IS DISTINCT FROM (to_jsonb(OLD) - 'legal_hold' - 'key_id' - 'wrapped_key') THEN
        RAISE EXCEPTION 'CAPTURE_IMMUTABLE: only the legal hold and the wrapping of a capture may change'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER capture_chunk_mutable BEFORE UPDATE ON capture_chunk
    FOR EACH ROW EXECUTE FUNCTION rwsafe_capture_chunk_mutable();
-- A re-wrap and a delete are ledgered; reference counting is not (it is the manifest's own bookkeeping).
CREATE TRIGGER capture_chunk_audit_rewrap AFTER UPDATE OF key_id, wrapped_key ON capture_chunk
    FOR EACH ROW EXECUTE FUNCTION rwsafe_audit_row('chunk_id');
CREATE TRIGGER capture_chunk_audit_delete AFTER DELETE ON capture_chunk
    FOR EACH ROW EXECUTE FUNCTION rwsafe_audit_row('chunk_id');
CREATE TRIGGER capture_chunk_no_truncate BEFORE TRUNCATE ON capture_chunk
    FOR EACH STATEMENT EXECUTE FUNCTION rwsafe_audit_append_only();

CREATE TRIGGER capture_record_mutable BEFORE UPDATE ON capture_record
    FOR EACH ROW EXECUTE FUNCTION rwsafe_capture_record_mutable();
CREATE TRIGGER capture_record_audit AFTER UPDATE OR DELETE ON capture_record
    FOR EACH ROW EXECUTE FUNCTION rwsafe_audit_row('event_id');
CREATE TRIGGER capture_record_no_truncate BEFORE TRUNCATE ON capture_record
    FOR EACH STATEMENT EXECUTE FUNCTION rwsafe_audit_append_only();
CREATE TRIGGER capture_manifest_no_truncate BEFORE TRUNCATE ON capture_manifest
    FOR EACH STATEMENT EXECUTE FUNCTION rwsafe_audit_append_only();
CREATE TRIGGER capture_store_usage_no_truncate BEFORE TRUNCATE ON capture_store_usage
    FOR EACH STATEMENT EXECUTE FUNCTION rwsafe_audit_append_only();

-- Every request to read a capture (AGENTS.md 4.13, RAW_CONTENT_ACCESS §4): actor pseudonym, reason code, case id and the
-- outcome, a refused one included. SERVED is written only after the record opened. No foreign key: the ledger outlives
-- the record. Append-only.
CREATE TABLE capture_read (
    read_id            bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    read_at            timestamptz NOT NULL DEFAULT now(),
    event_id           uuid        NOT NULL,
    actor_fingerprint  text        NOT NULL CHECK (actor_fingerprint ~ '^USR-[0-9a-f]{10}$'),
    reason_code        text        NOT NULL CHECK (reason_code IN ('INCIDENT_INVESTIGATION', 'DSAR', 'LEGAL_HOLD_REVIEW',
                                                                   'FALSE_POSITIVE_REVIEW', 'REGULATOR_REQUEST', 'NONE')),
    case_id            text        CHECK (case_id ~ '^[A-Za-z0-9_-]{3,64}$'),
    outcome            text        NOT NULL CHECK (outcome IN ('SERVED', 'REFUSED_NO_REASON', 'REFUSED_ROLE',
                                                               'NOT_FOUND', 'KEY_UNAVAILABLE', 'INTEGRITY_FAILED')),
    CHECK (outcome <> 'SERVED' OR (reason_code <> 'NONE' AND case_id IS NOT NULL))
);

CREATE INDEX capture_read_event ON capture_read (event_id);

CREATE TRIGGER capture_read_audit AFTER INSERT ON capture_read
    FOR EACH ROW EXECUTE FUNCTION rwsafe_audit_row('read_id');
CREATE TRIGGER capture_read_no_update_or_delete BEFORE UPDATE OR DELETE ON capture_read
    FOR EACH ROW EXECUTE FUNCTION rwsafe_audit_append_only();
CREATE TRIGGER capture_read_no_truncate BEFORE TRUNCATE ON capture_read
    FOR EACH STATEMENT EXECUTE FUNCTION rwsafe_audit_append_only();

-- Deletion receipts (DATA_CLASSES_AND_RETENTION §2): which records left, how many chunks were shredded, when and why.
CREATE TABLE capture_deletion_receipt (
    receipt_id   bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    deleted_at   timestamptz NOT NULL DEFAULT now(),
    reason       text        NOT NULL CHECK (reason IN ('RETENTION_EXPIRED', 'STORE_CAP_EVICTED', 'KEY_SHREDDED')),
    key_id       text        CHECK (key_id ~ '^[A-Za-z0-9_-]{1,32}$'),
    event_ids    uuid[]      NOT NULL CHECK (cardinality(event_ids) BETWEEN 0 AND 1000),
    chunk_count  integer     NOT NULL CHECK (chunk_count >= 0),
    CHECK (cardinality(event_ids) > 0 OR chunk_count > 0)
);

CREATE TRIGGER capture_deletion_receipt_audit AFTER INSERT ON capture_deletion_receipt
    FOR EACH ROW EXECUTE FUNCTION rwsafe_audit_row('receipt_id');
CREATE TRIGGER capture_deletion_receipt_no_update_or_delete BEFORE UPDATE OR DELETE ON capture_deletion_receipt
    FOR EACH ROW EXECUTE FUNCTION rwsafe_audit_append_only();
CREATE TRIGGER capture_deletion_receipt_no_truncate BEFORE TRUNCATE ON capture_deletion_receipt
    FOR EACH STATEMENT EXECUTE FUNCTION rwsafe_audit_append_only();

-- Key events (PO decision on PR 25 Q-3): a planned rotation's re-wrap, and an emergency crypto-shred (a key removed
-- without re-wrap and named in the Secret's `shredded` list). Append-only and ledgered.
CREATE TABLE capture_key_event (
    key_event_id  bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at   timestamptz NOT NULL DEFAULT now(),
    operation     text        NOT NULL CHECK (operation IN ('REWRAP', 'EMERGENCY_SHRED')),
    from_key_id   text        CHECK (from_key_id ~ '^[A-Za-z0-9_-]{1,32}$'),
    to_key_id     text        CHECK (to_key_id ~ '^[A-Za-z0-9_-]{1,32}$'),
    records       integer     NOT NULL CHECK (records >= 0),
    chunks        integer     NOT NULL CHECK (chunks >= 0),
    CHECK ((operation = 'REWRAP') = (to_key_id IS NOT NULL))
);

CREATE TRIGGER capture_key_event_audit AFTER INSERT ON capture_key_event
    FOR EACH ROW EXECUTE FUNCTION rwsafe_audit_row('key_event_id');
CREATE TRIGGER capture_key_event_no_update_or_delete BEFORE UPDATE OR DELETE ON capture_key_event
    FOR EACH ROW EXECUTE FUNCTION rwsafe_audit_append_only();
CREATE TRIGGER capture_key_event_no_truncate BEFORE TRUNCATE ON capture_key_event
    FOR EACH STATEMENT EXECUTE FUNCTION rwsafe_audit_append_only();
