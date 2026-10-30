-- V7: SIEM export (ARCHITECTURE.md §3.2 `audit`, ADR-002 "SIEM watermarks", ADR-009 C8). Commit-safe export order for
-- the two exported tables and one watermark row per destination.
--
-- Why a transaction id and not a timestamp or a sequence (PR 23 review D-1): `ingested_at`/`occurred_at` (now(), the
-- transaction start) and `audit_id` (an identity) are taken before commit, so a row can become visible after a newer
-- row that a watermark already passed, and would then be skipped for ever. Every exported row now records the id of the
-- transaction that wrote it (`tx_id`, xid8, assigned no later than the insert). The exporter reads only rows with
-- `tx_id < pg_snapshot_xmin(pg_current_snapshot())`: every transaction below the snapshot's xmin has ended, so all of its
-- rows are either visible now or never will be (aborted), and any transaction still running or not yet started has an
-- id at or above that xmin. The watermark is (tx_id, row id) of the last acknowledged row, always below the xmin of the
-- read that returned it, and xmin never moves backwards for later snapshots; so no row can ever appear behind the
-- watermark. A long transaction holds the xmin back: export pauses (visible as backlog), it never skips.
--
-- Existing rows take the migration's own transaction id (the default is evaluated inside the migration's transaction).

ALTER TABLE verdict_event ADD COLUMN tx_id xid8 NOT NULL DEFAULT pg_current_xact_id();
ALTER TABLE audit_event ADD COLUMN tx_id xid8 NOT NULL DEFAULT pg_current_xact_id();

CREATE INDEX verdict_event_tx_id_event_id ON verdict_event (tx_id, event_id);
CREATE INDEX audit_event_tx_id_audit_id ON audit_event (tx_id, audit_id);

-- One row per destination: the position of the last verdict event and the last ledger row the destination acknowledged.
-- Positions only: no exported field, no body, no identity. The row's creation is ledgered (who started the export, from
-- where, and how many verdict events a `latest` start skipped: PR 23 review D-6); the moves after each delivered batch are
-- system bookkeeping and are not ledgered, since a ledger row per batch would itself be exported and move the watermark.
CREATE TABLE siem_watermark (
    destination        text        PRIMARY KEY CHECK (destination IN ('syslog', 'hec')),
    verdict_tx_id      xid8,
    verdict_event_id   uuid,
    audit_tx_id        xid8,
    audit_id           bigint      CHECK (audit_id > 0),
    -- `latest` applies to verdict events only; ledger rows always export from the first one (PO decision Q-SIEM-1).
    start_from         text        NOT NULL CHECK (start_from IN ('earliest', 'latest')),
    skipped_at_start   bigint      NOT NULL DEFAULT 0 CHECK (skipped_at_start >= 0),
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CHECK ((verdict_tx_id IS NULL) = (verdict_event_id IS NULL)),
    CHECK ((audit_tx_id IS NULL) = (audit_id IS NULL)),
    CHECK (start_from = 'latest' OR skipped_at_start = 0)
);

CREATE TRIGGER siem_watermark_audit AFTER INSERT ON siem_watermark
    FOR EACH ROW EXECUTE FUNCTION rwsafe_audit_row('destination');
