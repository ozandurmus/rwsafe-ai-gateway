# rwsafe-ai-gateway: current state

Checkpoint 2026-10-30, afternoon. Phase: **implementation, phase 0** (discovery and measurement; no production change).
The design is FROZEN (`docs/design/PO_DECISION_RECORD_2026_10_30_DESIGN_FREEZE.md`); ADR-001 to ADR-011 are ACCEPTED. No
product code yet; nothing deployed; HOST-A, neXus and ProxySG unchanged.

## Done (design phase, closed 2026-10-30)

Repository skeleton; governance (AGENTS.md, CLAUDE.md, roles/, decision-record template, model tier map, SSDF mapping,
ship pipeline plan, delivery manifest, privacy gate with Turkish identifiers, gitleaks config, empty security baseline,
hook installer); read-only masked HOST-A inventory (non-root and the PO's root-only pass); eleven ADRs; ARCHITECTURE, ICAP
and streaming spec, ports and resources, capacity and SLO model, hardening exceptions, deploy and shared-host runbook;
threat model, security requirements, masking and privacy, data classes and retention, raw content access, PIA,
regulatory mapping, bypass catalogue, penetration test plan; platform matrix, out of scope, competitive reference,
roadmap; Turkish end-user texts; review scripts with the content guard; corporate stack reference. Design-freeze council
(three seats, all ACCEPT WITH CORRECTIONS) run through `tools/review/`; both correction rounds applied and answered by ID
(`docs/reviews/COUNCIL_RESPONSE.md` section 7). PO decisions: Q-30..Q-36 (record of 2026-10-30) and the design freeze.
Public GitHub repository with branch protection; pull request 1 merged; pull request 2 (decisions and freeze) opened.

## Pending on the Product Owner

Decisions Q-1..Q-29 and Q-37 (ask one at a time with the recommendation first). Lab tenant procurement (Q-34). Approvers
and DPO identity (Q-5). Governance is settled: pull request 2 merged; `.claude/settings.json` committed; AGENTS.md section
1 (reviews as evidence) and section 9 (standing push/PR/merge authorisation) amended; the Git-authority decision record
RATIFIED; `main` requires a pull request and zero approving reviews.

## Not done

Every UNVERIFIED mark (phase 0 measures them); the prerequisite neXus PR (phase 1, needs the PO's go); vendoring of the
neXus delivery scripts (`tools/delivery/VENDORED_FROM_NEXUS.md`); Q-29 residual-risk signature (blocks the pilot).

## Next (ROADMAP phase 0, in this order)

1. Repository and CI skeleton: build per ADR-011, ArchUnit fences for the data-plane law (AGENTS.md section 5), privacy
   gate and unit tests in CI, empty data-plane and control modules compiling. No deploy.
2. Measurements that need the PO or the proxy team, each recorded masked where ROADMAP phase 0 names: ProxySG access-log
   shapes for the AI category and for uncategorised domains (Q-30), ProxySG capability record (Secure ICAP, max object
   size, Preview), SSL-interception bypass audit, vendor header verification on a lab client, login-flow frame fixtures
   (synthetic bodies), per-client trust matrix, Broadcom support case (Q-20), corporate contract facts incl. the art. 9
   instrument per vendor (Q-33), directory attribute for the HR acknowledgement (Q-35).
3. Phase 1 starts only after the PO's go and the Q-13 decision (neXus ingress PR).

Operating model from here: the High tier (Opus) orchestrates with subagents on the lighter tiers
(`docs/reference/MODEL_TIER_MAP.md`); the architect tier returns only for a new ADR or a decision-record amendment.
