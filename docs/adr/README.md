# Architecture decision records

One file per decision, `ADR-NNN-<slug>.md`, in the format below. Status values: `PROPOSED` (the architect's draft),
`ACCEPTED` (by a RATIFIED PO decision record or a recorded PO chat decision the ADR quotes), `SUPERSEDED` (by a later
ADR, named), `REJECTED`. A PROPOSED ADR authorises no implementation.

```
# ADR-NNN: <title>
Status: PROPOSED | ACCEPTED (<record>) | SUPERSEDED by ADR-MMM | REJECTED
Date: YYYY-MM-DD
Answers: <brief clause>, <council IDs>
## Context
## Decision
## Alternatives considered
## Consequences
## Evidence and UNVERIFIED facts
## Open questions (OPEN_QUESTIONS ids)
```

| ADR | Title |
|---|---|
| ADR-001 | Hosting on HOST-A and namespace isolation |
| ADR-002 | Separate PostgreSQL instance |
| ADR-003 | Reverse proxy and host-based routing, including the exact neXus change |
| ADR-004 | ICAP versus chained proxy versus agent, per traffic type |
| ADR-005 | WebSocket and streaming strategy |
| ADR-006 | Edge SWG and off-net agent strategy |
| ADR-007 | Tenant restriction per vendor |
| ADR-008 | Guardrail engine: build versus integrate |
| ADR-009 | Data model, retention and privacy |
| ADR-010 | Fail-open and fail-closed |
| ADR-011 | Shared tooling with neXus and the corporate build standard |

All eleven ADRs are **ACCEPTED** by `docs/design/PO_DECISION_RECORD_2026_10_30_DESIGN_FREEZE.md` (2026-10-30); a change to an accepted ADR
needs a new decision record or a superseding ADR that quotes one.
