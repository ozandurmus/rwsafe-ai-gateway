-- V5: the notice acknowledgement (ADR-009 C12; KVKK article 10; PC-2, PC-3; PO decisions Q-32 and Q-35). Proof that
-- the duty to inform was met, never consent: one row per user, notice version and source. The user is the USR-
-- pseudonym under rwsafe's own key; the identity claim is never stored. Rows are ledgered by the audit trigger, never
-- updated, and deleted only by retention (scope + 400 days) or an erasure, which the ledger records as well.
-- (V3 and V4 are reserved by open branches.)

CREATE TABLE notice_acknowledgement (
    acknowledgement_id  bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_pseudonym      text        NOT NULL CHECK (user_pseudonym ~ '^USR-[0-9a-f]{10}$'),
    -- <language>-<catalogue version>-<8 hex of the rendered notice> (docs/i18n/README.md, PC-1).
    notice_version      text        NOT NULL CHECK (notice_version ~ '^[a-z]{2}-[0-9]{1,4}-[0-9a-f]{8}$'),
    acknowledged_at     timestamptz NOT NULL,
    source              text        NOT NULL CHECK (source IN ('banner', 'ide_first_run', 'directory_attribute',
                                                               'gateway_credential_issue')),
    recorded_at         timestamptz NOT NULL DEFAULT now(),
    pseudonym_key_id    text        NOT NULL CHECK (length(pseudonym_key_id) BETWEEN 1 AND 32),
    UNIQUE (user_pseudonym, notice_version, source)
);

CREATE INDEX notice_acknowledgement_user ON notice_acknowledgement (user_pseudonym, notice_version);

CREATE TRIGGER notice_acknowledgement_audit AFTER INSERT OR DELETE ON notice_acknowledgement
    FOR EACH ROW EXECUTE FUNCTION rwsafe_audit_row('acknowledgement_id');
CREATE TRIGGER notice_acknowledgement_no_update BEFORE UPDATE ON notice_acknowledgement
    FOR EACH ROW EXECUTE FUNCTION rwsafe_audit_append_only();
CREATE TRIGGER notice_acknowledgement_no_truncate BEFORE TRUNCATE ON notice_acknowledgement
    FOR EACH STATEMENT EXECUTE FUNCTION rwsafe_audit_append_only();
