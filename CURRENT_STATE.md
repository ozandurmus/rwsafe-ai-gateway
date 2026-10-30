# rwsafe-ai-gateway: current state

Checkpoint 2026-10-30. Phase: **architecture design**; no product code; nothing deployed; HOST-A, neXus and ProxySG unchanged.

## Done in this phase

Repository skeleton; governance (AGENTS.md, CLAUDE.md, roles/, decision-record template, model tier map, SSDF mapping,
ship pipeline plan, delivery manifest, privacy gate with Turkish identifiers, gitleaks config, empty security baseline,
hook installer); read-only masked HOST-A inventory (non-root and the PO's root-only pass); eleven ADRs (PROPOSED);
ARCHITECTURE, ICAP and streaming spec, ports and resources, capacity and SLO model, hardening exceptions, deploy and
shared-host runbook; threat model, security requirements, masking and privacy, data classes and retention, raw content
access, PIA, regulatory mapping, bypass catalogue, penetration test plan; platform matrix, out of scope, competitive
reference, roadmap, open questions (Q-1..Q-29); council response (every P0 by ID); Turkish end-user texts; review scripts
with the content guard; corporate stack reference.

## Not done

The design-freeze council run through `tools/review/` (needs the PO's go); PO decisions on Q-1..Q-29; phase 0
measurements (every UNVERIFIED mark); the GitHub repository (created by the PO) and the first push; vendoring of the
neXus delivery scripts (`tools/delivery/VENDORED_FROM_NEXUS.md` describes the plan).

## Next

1. PO reads OPEN_QUESTIONS and COUNCIL_RESPONSE; decides or asks.
2. Council run (three seats) on the frozen set; architect answers; PO accepts the freeze by decision record.
3. Hand-over to the implementation phase (Opus and subagents) with ROADMAP phase 0 as the first movement.
