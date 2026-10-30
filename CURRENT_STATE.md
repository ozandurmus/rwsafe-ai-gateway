# rwsafe-ai-gateway: current state

Checkpoint 2026-10-30, evening. Phase: **implementation, phase 0** (discovery and measurement; no production change).
The design is FROZEN (`docs/design/PO_DECISION_RECORD_2026_10_30_DESIGN_FREEZE.md`); ADR-001 to ADR-011 are ACCEPTED.
Phase 0 movement 1 (repository and CI skeleton) is done on `feature/phase0-repo-ci-skeleton` (pull request 4); no
product behaviour yet; nothing deployed; HOST-A, neXus and ProxySG unchanged.

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
Public GitHub repository with branch protection; pull requests 1, 2 (decisions and freeze) and 3 (Git authority) merged.

## Done (phase 0, movement 1: repository and CI)

- Gradle build under `java/` per ADR-011 §4 (Gradle 8.14.3 wrapper, Java 21 toolchain, `-Xlint:all -Werror`), modules
  per ARCHITECTURE §9: `platform-core`, `detect`, `policy`, `dataplane`, `persistence`, `control`, `worker`, `cli`,
  `architecture-tests`, `integration-tests`; all empty but compiling. Lockfiles for every configuration and
  `gradle/verification-metadata.xml` (sha256). Entry points `unitTest` and `architectureTest` (neXus task names).
- ArchUnit fences (`java/architecture-tests`, `Fences.java`), each proved on fixtures by `FenceSelfTest`; calls and
  method references count alike: no `java.util.regex`, `Scanner` or regex `String` shortcuts on the inline path
  (`platform`, `dataplane`, `detect`, `policy`; RE2/J only, SR-DP-1); no database API, servlet stack or control-plane
  module there (SR-DP-6); on request threads (the same packages except `dataplane.boot` and `dataplane.controlplane`) no
  blocking network, DNS or disk call and no sleep, wait, park, `Future.get` or `BlockingQueue.put/take`; a class that
  holds or reads content (`@BodyBearing`, `@BodyContent`) never logs, meters, traces or prints; a `@BodyContent` accessor
  lives on a `@BodyBearing` class, which is not a record and whose own `toString()` reads no content field; server
  modules never write to the standard streams (4.14). Every module emits a class (`-Xpkginfo:always`) and the product
  test fails if a module is invisible to the fences.
- Second independent review (AGENTS.md section 9): Argon, `docs/reviews/PR4_2026_10_30_ARGON_PHASE0_SKELETON.md`, MERGE
  WITH CORRECTIONS; answered by ID in `docs/reviews/PR4_2026_10_30_RESPONSE.md` (D-03..D-05 fixed, D-06/D-07 partly).
- CI `.github/workflows/validation.yml` on every pull request and on `main`: privacy gate, gitleaks (tree and history,
  checksum-verified binary), unit and ArchUnit tests; every job prints the commit it tested (the merge commit plus the
  PR head and base); actions pinned by commit digest; read-only token; no secrets.
- Hooks installed in this checkout (`tools/delivery/install_hooks.sh`; `core.hooksPath=.githooks` in the shared
  repository config, so every worktree needs its own install run).

## Pending on the Product Owner

Mark the three `validation` jobs (`privacy-gate`, `gitleaks`, `java-tests`) as required status checks on `main`
(none is required today). Decisions still open: Q-7, Q-8, Q-11, Q-12, Q-17..Q-29, Q-37 (ask one batch at a time with
the recommendation first); the twelve MVP-blocking questions are decided
(`docs/design/PO_DECISION_RECORD_2026_10_30_MVP_BLOCKING_QUESTIONS.md`). Lab tenant
procurement (Q-34). Approvers and DPO identity (Q-5). Governance is settled: pull request 2 merged;
`.claude/settings.json` committed; AGENTS.md section 1 (reviews as evidence) and section 9 (standing push/PR/merge
authorisation) amended; the Git-authority decision record RATIFIED; `main` requires a pull request and zero approving
reviews.

## Not done

Every UNVERIFIED mark (phase 0 measures them); the prerequisite neXus PR (phase 1, needs the PO's go); vendoring of the
neXus delivery scripts (`tools/delivery/VENDORED_FROM_NEXUS.md`); Q-29 residual-risk signature (blocks the pilot); the
Maven-portability smoke build that ADR-011 §4 names as the Gradle mitigation (generated `pom.xml` built in CI); Semgrep,
Trivy (lockfile and config scan, SR-SC-2) and the Jazzer corpus in CI; `frontend/`; privacy-gate hardening from the PR 4
review (D-01, D-02: no private-range exemption for fixtures, `.gitleaks.toml` allowlist dates, extensionless files, a
gate self-test in CI); an ArchUnit module-graph rule (D-06).

## Next (ROADMAP phase 0, in this order)

1. Measurements that need the PO or the proxy team, each recorded masked where ROADMAP phase 0 names: ProxySG access-log
   shapes for the AI category and for uncategorised domains (Q-30), ProxySG capability record (Secure ICAP, max object
   size, Preview), SSL-interception bypass audit, vendor header verification on a lab client, login-flow frame fixtures
   (synthetic bodies), per-client trust matrix, Broadcom support case (Q-20), corporate contract facts incl. the art. 9
   instrument per vendor (Q-33), directory attribute for the HR acknowledgement (Q-35).
2. Phase 1 starts only after the PO's go and the Q-13 decision (neXus ingress PR).

Operating model from here: the High tier (Opus) orchestrates with subagents on the lighter tiers
(`docs/reference/MODEL_TIER_MAP.md`); the architect tier returns only for a new ADR or a decision-record amendment.
