-- V6: redacted capture (ADR-009 C3; PO decisions Q-3, Q-4 b, Q-5; SR-PRIV-10, SR-PRIV-11, SR-HOST-2; AGENTS.md 4.13).
-- The redacted text of a REDACT verdict is stored only as ciphertext: AES-256-GCM under a data key of its own, the data
-- key wrapped by the capture key (a mounted Secret of its own, never the privacy HMAC key) named by key_id. No column
-- holds plaintext; the database never sees a key. Retention is at most 90 days (Q-5); a retired capture key shreds every
-- record under it. Deletions, legal-hold changes, reads and receipts are ledgered by the audit trigger.
-- (V4 is reserved by an open branch.)

CREATE TABLE redacted_capture (
    event_id        uuid        PRIMARY KEY REFERENCES verdict_event (event_id) ON DELETE CASCADE,
    captured_at     timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    -- The user the notice acknowledgement gate opened capture for (SR-PRIV-10); a pseudonym, never a claim.
    user_pseudonym  text        NOT NULL CHECK (user_pseudonym ~ '^USR-[0-9a-f]{10}$'),
    key_id          text        NOT NULL CHECK (key_id ~ '^[A-Za-z0-9_-]{1,32}$'),
    -- nonce (12) || AES-GCM(capture key, data key (32)) || tag (16)
    wrapped_key     bytea       NOT NULL CHECK (octet_length(wrapped_key) = 60),
    nonce           bytea       NOT NULL CHECK (octet_length(nonce) = 12),
    ciphertext      bytea       NOT NULL CHECK (octet_length(ciphertext) BETWEEN 16 AND 1048576),
    plain_bytes     integer     NOT NULL CHECK (plain_bytes BETWEEN 0 AND 262144),
    truncated       boolean     NOT NULL,
    -- The masking rule set applied at persistence (ADR-009 §2: layers run at persistence as well as at view).
    mask_rule_set   text        NOT NULL CHECK (mask_rule_set ~ '^[a-z0-9.-]{1,32}$'),
    legal_hold      boolean     NOT NULL DEFAULT false,
    CHECK (expires_at > captured_at AND expires_at <= captured_at + interval '90 days')
);

CREATE INDEX redacted_capture_expires_at ON redacted_capture (expires_at) WHERE NOT legal_hold;
CREATE INDEX redacted_capture_key_id ON redacted_capture (key_id);

-- A capture is immutable; only its legal hold may change (ADR-009 §4), and that change is ledgered.
CREATE FUNCTION rwsafe_capture_hold_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (to_jsonb(NEW) - 'legal_hold') IS DISTINCT FROM (to_jsonb(OLD) - 'legal_hold') THEN
        RAISE EXCEPTION 'CAPTURE_IMMUTABLE: only the legal hold of a capture may change'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER redacted_capture_hold_only BEFORE UPDATE ON redacted_capture
    FOR EACH ROW EXECUTE FUNCTION rwsafe_capture_hold_only();
CREATE TRIGGER redacted_capture_audit AFTER UPDATE OR DELETE ON redacted_capture
    FOR EACH ROW EXECUTE FUNCTION rwsafe_audit_row('event_id');
CREATE TRIGGER redacted_capture_no_truncate BEFORE TRUNCATE ON redacted_capture
    FOR EACH STATEMENT EXECUTE FUNCTION rwsafe_audit_append_only();

-- Every request to read a capture (AGENTS.md 4.13, RAW_CONTENT_ACCESS §4): actor pseudonym, reason code, case id and the
-- outcome, a refused one included. No foreign key: the ledger outlives the record. Append-only.
CREATE TABLE capture_read (
    read_id            bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    read_at            timestamptz NOT NULL DEFAULT now(),
    event_id           uuid        NOT NULL,
    actor_fingerprint  text        NOT NULL CHECK (actor_fingerprint ~ '^USR-[0-9a-f]{10}$'),
    reason_code        text        NOT NULL CHECK (reason_code IN ('INCIDENT_INVESTIGATION', 'DSAR', 'LEGAL_HOLD_REVIEW',
                                                                   'FALSE_POSITIVE_REVIEW', 'REGULATOR_REQUEST', 'NONE')),
    case_id            text        CHECK (case_id ~ '^[A-Za-z0-9_-]{3,64}$'),
    outcome            text        NOT NULL CHECK (outcome IN ('SERVED', 'REFUSED_NO_REASON', 'NOT_FOUND',
                                                               'KEY_UNAVAILABLE')),
    CHECK (outcome <> 'SERVED' OR (reason_code <> 'NONE' AND case_id IS NOT NULL))
);

CREATE INDEX capture_read_event ON capture_read (event_id);

CREATE TRIGGER capture_read_audit AFTER INSERT ON capture_read
    FOR EACH ROW EXECUTE FUNCTION rwsafe_audit_row('read_id');
CREATE TRIGGER capture_read_no_update_or_delete BEFORE UPDATE OR DELETE ON capture_read
    FOR EACH ROW EXECUTE FUNCTION rwsafe_audit_append_only();
CREATE TRIGGER capture_read_no_truncate BEFORE TRUNCATE ON capture_read
    FOR EACH STATEMENT EXECUTE FUNCTION rwsafe_audit_append_only();

-- Deletion receipts (DATA_CLASSES_AND_RETENTION §2): which records left, when and why. Append-only and ledgered.
CREATE TABLE capture_deletion_receipt (
    receipt_id  bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    deleted_at  timestamptz NOT NULL DEFAULT now(),
    reason      text        NOT NULL CHECK (reason IN ('RETENTION_EXPIRED', 'KEY_SHREDDED')),
    key_id      text        CHECK (key_id ~ '^[A-Za-z0-9_-]{1,32}$'),
    event_ids   uuid[]      NOT NULL CHECK (cardinality(event_ids) BETWEEN 1 AND 1000)
);

CREATE TRIGGER capture_deletion_receipt_audit AFTER INSERT ON capture_deletion_receipt
    FOR EACH ROW EXECUTE FUNCTION rwsafe_audit_row('receipt_id');
CREATE TRIGGER capture_deletion_receipt_no_update_or_delete BEFORE UPDATE OR DELETE ON capture_deletion_receipt
    FOR EACH ROW EXECUTE FUNCTION rwsafe_audit_append_only();
CREATE TRIGGER capture_deletion_receipt_no_truncate BEFORE TRUNCATE ON capture_deletion_receipt
    FOR EACH STATEMENT EXECUTE FUNCTION rwsafe_audit_append_only();
