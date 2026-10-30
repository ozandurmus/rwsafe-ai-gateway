# PO decision record 2026-10-30: design freeze

**Status:** RATIFIED — Product Owner, 2026-10-30 (chat): "Donmayı onaylıyorum" (I ratify the freeze), given after the
draft of this record and the Q-30 to Q-36 decisions were presented in chat. Frozen at the main commit that merges pull
request 2 of the public repository.

## Context
The architecture design phase produced the brief's section 9 and 10.5 deliverables: eleven ADRs, the architecture and
ICAP/streaming specification, ports and resources, capacity and SLO model, hardening exceptions, deploy and shared-host
runbook, threat model, security requirements, masking and privacy, data classes and retention, raw content access,
privacy impact assessment, regulatory mapping, bypass catalogue, penetration test plan, platform matrix, out of scope,
competitive reference and roadmap. The design-freeze council (2026-10-30, three seats) returned ACCEPT WITH CORRECTIONS;
every correction is applied and answered by ID in `docs/reviews/COUNCIL_RESPONSE.md` section 7. The seven council
questions are decided in `PO_DECISION_RECORD_2026_10_30_FREEZE_COUNCIL_QUESTIONS_Q30_Q36.md`. The repository privacy gate
passes. No product code exists; HOST-A, neXus and ProxySG are unchanged.

## Decision
1. The design documents listed under "Consequences" are **FROZEN** at the main commit that merges this record; a frozen
   document changes only through a PO decision record or an ADR that quotes one.
2. ADR-001 to ADR-011 move from PROPOSED to **ACCEPTED** by this record.
3. Open questions Q-1 to Q-29 stay open. The architect's recommendation in each is the planning assumption for phase 0
   only; no MVP deliverable that depends on an open question is built before that question is decided (ROADMAP MVP
   preconditions).
4. The design phase ends and the implementation phase starts with ROADMAP phase 0 (discovery and measurement, no production
   change). The orchestrating tier is the one `docs/reference/MODEL_TIER_MAP.md` names for implementation and operations.
5. Council outputs stay evidence (Q-36); the brief's sections 1 to 10 stay binding until superseded clause by clause.

## Consequences
- Status line → FROZEN: `docs/architecture/ARCHITECTURE.md`, `docs/architecture/ICAP_AND_STREAMING_PROTOCOL_SPEC.md`,
  `docs/operations/PORTS_AND_RESOURCES.md`, `docs/operations/CAPACITY_AND_SLO_MODEL.md`,
  `docs/operations/HARDENING_EXCEPTIONS.md`, `docs/operations/DEPLOY_AND_SHARED_HOST_RUNBOOK.md`,
  `docs/security/THREAT_MODEL.md`, `docs/security/SECURITY_REQUIREMENTS.md`, `docs/security/MASKING_AND_PRIVACY.md`,
  `docs/security/DATA_CLASSES_AND_RETENTION.md`, `docs/security/RAW_CONTENT_ACCESS.md`,
  `docs/security/PRIVACY_IMPACT_ASSESSMENT.md`, `docs/compliance/REGULATORY_MAPPING.md`,
  `docs/security/BYPASS_CATALOGUE.md`, `docs/security/PENETRATION_TEST_PLAN.md`, `docs/product/PLATFORM_MATRIX.md`,
  `docs/product/OUT_OF_SCOPE.md`, `docs/product/COMPETITIVE_REFERENCE.md`, `docs/product/ROADMAP.md`.
  `docs/product/OPEN_QUESTIONS.md` stays LIVE.
- ADR-001..ADR-011: `Status: ACCEPTED (PO_DECISION_RECORD_2026_10_30_DESIGN_FREEZE)`.
- `CURRENT_STATE.md` and `AI_HANDOVER.md`: phase becomes "implementation, phase 0".
- Residual risk: Q-29 is not signed by this record; the pilot cannot start before it is.

## Open items
Q-1 to Q-29 (`docs/product/OPEN_QUESTIONS.md`); the Git-authority decision record and the `AGENTS.md` amendments (PO's
hand); every UNVERIFIED mark, to be measured in phase 0.
