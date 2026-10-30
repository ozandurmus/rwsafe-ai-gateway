# AI handover (non-authoritative pointer)

Snapshot (2026-10-30, mid-afternoon): design set complete; design-freeze council run (three seats, all ACCEPT WITH
CORRECTIONS, outputs in docs/reviews/FREEZE_2026_10_30_*). Corrections applied so far: ICAP spec (rewritten), ADR-010
(rewritten), ADR-001/003/004/005/007/008/009/011, PORTS, CAPACITY, DEPLOY runbook, HARDENING, SHIP plan, k3s overlay
manifests. Public GitHub repository exists; baseline pushed by the PO; branch protection on.

Exact next action (in order):
1. Apply the remaining council corrections: DATA_CLASSES (PC-2 acknowledgement, PC-6 C6 split, PC-13 C10 location, PC-14 C15,
   OFF2-8 metadata), RAW_CONTENT_ACCESS (PC-8 break-glass), PIA (PC-4, PC-7 residual, PC-11, PC-12 BDDK row), REGULATORY_MAPPING
   (PC-2 consent excluded, PC-4 art. 9 instrument, PC-12), MASKING (PC-2, PC-10 viewer/auditor, PC-11), i18n notice (PC-1
   controller, transfers, automated collection, objection; block page hides exception link for fail-closed classes, PC-5),
   SECURITY_REQUIREMENTS (SR-DLP-1, SR-DP-2/8 additions, SR-GW-1 reword OFF2-14, SR-PRIV-10 two sources, SR-PRIV-14, SR-ADM-9),
   THREAT_MODEL (agent tooling section OFF2-15, build pods OFF2-16, estate digests OFF2-9, metadata hostile input OFF2-8),
   BYPASS_CATALOGUE (BY-ENC-8 to MVP, OFF2-1/OFF2-6 fixtures), PENETRATION_TEST_PLAN (OFF2-17), PLATFORM_MATRIX §3 and
   OUT_OF_SCOPE (OFF2-13 storage-integrated and embedded AI), ROADMAP (Secure ICAP before the fail-open window, Q-E),
   OPEN_QUESTIONS (Q-12 Türkiye, Q-28 recommendation (b), Q-29 additions, new Q-30..Q-36), COUNCIL_RESPONSE new section 7.
2. AGENTS.md section 1 item 4: demote docs/reviews/ to evidence (OFF2-15, Q-F) and section 9 standing-authorisation sentence:
   both need the PO's hand (the harness refuses agent edits that widen the agent's own authority); the PO also writes
   .claude/settings.json from the rules given in chat.
3. Privacy gate, commit on branch design/freeze-council-corrections, push, PR, merge (PO-authorised).
4. Then say "Opus ok" to the PO and hand over with CURRENT_STATE.md and ROADMAP phase 0.
If anything here looks stale, CURRENT_STATE.md wins.
