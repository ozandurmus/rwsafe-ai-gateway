-- V4: the SIEM export watermark (ARCHITECTURE.md §3.2 `audit`, ADR-002 "SIEM watermarks"). One row per destination
-- holds the position of the last verdict event and the last audit-ledger row the destination acknowledged, so the
-- exporter resumes after a restart without losing an event (at least once; the event id travels in every exported line
-- for SIEM-side deduplication). Positions only: no exported field, no body, no identity.
--
-- Not ledgered by the audit trigger: the row moves with every delivered batch (system bookkeeping, not an admin action),
-- and a ledger row per batch would itself be exported and move the watermark again.

CREATE TABLE siem_watermark (
    destination          text        PRIMARY KEY CHECK (destination IN ('syslog', 'hec')),
    -- Verdict events are read in (ingested_at, event_id) order; both NULL before the first delivered verdict event.
    verdict_ingested_at  timestamptz,
    verdict_event_id     uuid,
    -- Audit-ledger rows are read in audit_id order; 0 before the first delivered row.
    audit_id             bigint      NOT NULL DEFAULT 0 CHECK (audit_id >= 0),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    CHECK ((verdict_ingested_at IS NULL) = (verdict_event_id IS NULL))
);

-- The exporter's keyset read over verdict events.
CREATE INDEX verdict_event_ingested_at_event_id ON verdict_event (ingested_at, event_id);
