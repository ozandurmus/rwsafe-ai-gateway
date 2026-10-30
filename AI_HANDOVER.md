# AI handover (non-authoritative pointer)

Snapshot (2026-10-30, mid-afternoon): design set complete; design-freeze council run (three seats, all ACCEPT WITH
CORRECTIONS, outputs in docs/reviews/FREEZE_2026_10_30_*). Corrections applied so far: ICAP spec (rewritten), ADR-010
(rewritten), ADR-001/003/004/005/007/008/009/011, PORTS, CAPACITY, DEPLOY runbook, HARDENING, SHIP plan, k3s overlay
manifests. Public GitHub repository exists; baseline pushed by the PO; branch protection on.

Exact next action (in order):
1. Branch `design/freeze-council-corrections` holds the council run and both correction rounds (commits c61c9a6, a53dc0e);
   privacy gate PASS. Push it, open the PR against main, merge (PO-authorised, AGENTS.md section 9). If the harness refuses
   the push, hand the three commands to the PO.
2. PO-only edits (the harness refuses agent edits that widen the agent's own authority): write .claude/settings.json from the
   rules given in chat; AGENTS.md section 1 item 4 demotes docs/reviews/ to evidence (Q-36); section 9 gains the standing
   push/PR authorisation sentence; the Git-authority decision record under docs/design/.
3. PO decides Q-30..Q-36 and ratifies the freeze by decision record; then the architect says "Opus ok" and hands over with
   CURRENT_STATE.md and ROADMAP phase 0.
If anything here looks stale, CURRENT_STATE.md wins.
