# rwsafe-ai-gateway: current state

Checkpoint 2026-10-30. Phase: **architecture design**; no product code; nothing deployed; HOST-A, neXus and ProxySG unchanged.

## Done in this phase

Repository skeleton; governance (AGENTS.md, CLAUDE.md, roles/, decision-record template, model tier map, SSDF mapping,
ship pipeline plan, delivery manifest, privacy gate with Turkish identifiers, gitleaks config, empty security baseline,
hook installer); read-only masked HOST-A inventory (non-root and the PO's root-only pass); eleven ADRs (PROPOSED);
ARCHITECTURE, ICAP and streaming spec, ports and resources, capacity and SLO model, hardening exceptions, deploy and
shared-host runbook; threat model, security requirements, masking and privacy, data classes and retention, raw content
access, PIA, regulatory mapping, bypass catalogue, penetration test plan; platform matrix, out of scope, competitive
reference, roadmap, open questions (Q-1..Q-36); council response (every P0 by ID, plus section 7 for the freeze council);
Turkish end-user texts; review scripts with the content guard; corporate stack reference. **Design-freeze council run**
(three seats, all ACCEPT WITH CORRECTIONS) and both correction rounds applied; repository public on GitHub (main = baseline).

## Not done

PO decisions on Q-1..Q-36; the freeze ratification decision record; PO-only edits to AGENTS.md (section 1 item 4, section 9)
and .claude/settings.json; phase 0 measurements (every UNVERIFIED mark); vendoring of the neXus delivery scripts
(`tools/delivery/VENDORED_FROM_NEXUS.md` describes the plan).

## Next

1. Merge branch `design/freeze-council-corrections` into main (PR).
2. PO reads COUNCIL_RESPONSE section 7 and OPEN_QUESTIONS Q-30..Q-36; decides; ratifies the freeze by decision record.
3. Hand-over to the implementation phase (Opus and subagents) with ROADMAP phase 0 as the first movement.
