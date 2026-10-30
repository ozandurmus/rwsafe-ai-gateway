# PO decision record 2026-10-30: freeze-council questions Q-30 to Q-36

**Status:** RATIFIED — Product Owner, 2026-10-30 (chat, one question at a time with the architect's recommendation shown;
the PO's exact answers): Q-30 "Tüm kategorisiz alanlar (Önerilen)" (all uncategorised domains), Q-31 "Pilotta izle,
sonra zorla (Önerilen)" (monitor in the pilot, then enforce), Q-32 "Dışla (Önerilen)" (exclude), Q-33 "Hayır,
fail-closed (Önerilen)" (no, fail-closed), Q-34 "Evet, lab tenant'ları (Önerilen)" (yes, lab tenants), Q-35 "Evet, sürüm
ve tarihle (Önerilen)" (yes, with version and date), Q-36 "Yalnızca kanıt (Önerilen)" (evidence only).

## Context
The design-freeze council of 2026-10-30 (three seats, `docs/reviews/FREEZE_2026_10_30_SEAT_*.md`, answered in
`docs/reviews/COUNCIL_RESPONSE.md` section 7) raised seven decisions the architect could not take alone: OFF2-5, OFF2-7,
OFF2-15 and OFF2-17 from the offensive seat, PC-2, PC-3 and PC-4 from the privacy seat. They were recorded as Q-30 to
Q-36 in `docs/product/OPEN_QUESTIONS.md` with recommendations. No production data was involved; the inputs are the
council texts and the design documents.

## Decision
1. **Q-30, header-only metadata mode.** ProxySG sends requests to all uncategorised domains, and to broad categories the
   phase-0 bypass audit names, to REQMOD with headers only: no body capture, C1 metadata only, 30-day retention. The
   alternative, the AI category alone, was not chosen because relays and new AI hosts would be invisible by construction.
2. **Q-31, response-side and tool-result prompt injection.** Monitor-only during the pilot; after the pilot,
   high-confidence deterministic injection patterns are enforced (blocked) on agentic surfaces (CLI, IDE, MCP). Alert-only
   forever was not chosen.
3. **Q-32, explicit consent excluded.** Explicit consent is not a legal basis for any data class of this product; the notice
   acknowledgement (C12) is proof that the duty to inform was met, never a switch that enables processing. Keeping consent
   as a fallback basis was not chosen.
4. **Q-33, art. 9 instrument precondition.** No vendor receives traffic of any class, "public" prompts included, until its
   KVKK article 9 transfer instrument is recorded in the policy registry; the vendor row is fail-closed until then.
   Allowing public data before the instrument was not chosen.
5. **Q-34, lab tenants.** Lab tenants are procured for the three header vendors (Microsoft Entra / M365, Google Workspace,
   OpenAI ChatGPT Enterprise) and, where available, Anthropic, for the penetration test and the ICAP e2e tenant fixtures.
   Testing on production tenants with pilot users was not chosen.
6. **Q-35, directory acknowledgement as C12.** For IDE, CLI and API users the HR policy acknowledgement imported from the
   directory counts as the C12 record when it carries the notice version and date. Banner-only was not chosen.
7. **Q-36, council outputs are evidence.** The outputs under `docs/reviews/` are evidence, not authority; only a PO
   decision record that quotes a council item makes that item binding. Keeping them binding for the design phase was not
   chosen.

## Consequences
- AMENDS `AGENTS.md` section 1 item 4: the kickoff brief sections 1 to 10 stay at item 4; `docs/reviews/` moves to item 6
  (evidence and record). This edit is made by the PO (the harness refuses agent edits to the agent's own authority file).
- Confirms as design (no text change needed): ADR-004 and ADR-010 §2 header-only metadata mode (Q-30); ADR-005 §3a and
  ADR-008 §2 monitor-then-enforce for injection on agentic surfaces (Q-31); `docs/compliance/REGULATORY_MAPPING.md`
  art. 5 row and `DATA_CLASSES_AND_RETENTION.md` legal-basis column (Q-32); ADR-007 §3a and `PLATFORM_MATRIX.md` §5
  vendor fail-closed until the instrument is recorded (Q-33); `PENETRATION_TEST_PLAN.md` and ROADMAP MVP preconditions
  (Q-34); `DATA_CLASSES_AND_RETENTION.md` C12 sources and SR-PRIV-10 (Q-35); `THREAT_MODEL.md` §8a (Q-36).
- Phase 0 tasks gained: measure request volume to uncategorised domains before enabling header-only mode (Q-30; the
  capacity model assumes headers-only flows cost well under one body inspection each, to be measured); collect each
  vendor's article 9 instrument under the "corporate contract facts" task (Q-33); procure lab tenants (Q-34, owner: PO);
  agree the directory attribute that carries the HR acknowledgement with HR and IT (Q-35; the attribute name is runtime
  configuration, never committed).
- Policy registry: vendor rows carry an "article 9 instrument recorded" flag that defaults to false (Q-33); injection
  detectors on agentic surfaces are registry entries with the monitor → enforce transition after the pilot (Q-31).
- No new residual risk accepted. Q-29 (residual risk acceptance) stays open.

## Open items
Q-1 to Q-29 stay in `docs/product/OPEN_QUESTIONS.md`. The design-freeze ratification is a separate record
(`PO_DECISION_RECORD_2026_10_30_DESIGN_FREEZE.md`). The Git-authority record and the `AGENTS.md` section 9 sentence are
written by the PO.
