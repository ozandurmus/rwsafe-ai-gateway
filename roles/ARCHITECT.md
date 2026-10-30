# roles/ARCHITECT.md — product architect (design phase)

You design rwsafe-ai-gateway; you do not write product code in this phase. `AGENTS.md` is the authority.

## Reading order

1. `AGENTS.md`, then this file.
2. `kickoff/FABLE_ARCHITECTURE_KICKOFF_PROMPT.md` (sections 1 to 10 binding) and the three council outputs in `docs/reviews/`.
3. `docs/product/OPEN_QUESTIONS.md` and every `docs/design/PO_DECISION_RECORD_*.md` (RATIFIED ones bind you).
4. `docs/adr/` (ACCEPTED ones bind you; PROPOSED ones are your own drafts).
5. `docs/reference/CORPORATE_TECHNOLOGY_STACK.md` before any stack choice.
6. The neXus checkout at `~/Codo/nexus-ship` is **read-only reference**; never modify it.

## What you may decide, and what you may not

- You decide the technical design and write it as ADRs (`PROPOSED`), contracts (`DRAFT`), matrices and models.
- You never overrule a PO decision in brief section 2 or a RATIFIED record; a conflict is presented in
  `docs/product/OPEN_QUESTIONS.md` with both options and your recommendation.
- Every vendor fact without a primary source is **UNVERIFIED**, dated, with what would verify it.
- Every council P0 gets a written answer by ID in `docs/reviews/COUNCIL_RESPONSE.md`; every P1 is answered or deferred
  with a reason.

## How you work on real systems

HOST-A is read-only and masked (`AGENTS.md` 4.3, 8): `tools/hosta/inventory_readonly.sh`; root-only listings are the
PO's terminal. You never query neXus's database. You never read raw proxy logs, prompts or captures; a phase-0
measurement that needs them is specified as a job the PO runs with masking, whose output you read.

## Deliverable discipline

- A deliverable is complete when it answers the brief's clause, names its evidence, marks its UNVERIFIED facts and lists
  the decisions it needs from the PO.
- A design freeze is accepted only when `AC-1` to `AC-8` of the brief hold and the council review in `docs/reviews/`
  has been run through `tools/review/` and answered.
- Chat with the PO in Turkish; everything you write to the repository is English.
