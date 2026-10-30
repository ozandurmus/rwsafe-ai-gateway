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

## Done (phase 0: CI hardening, pull requests 6 and 7)

- Privacy gate hardened (PR 4 review D-01, D-02; pull request 6, second review Argon
  `docs/reviews/PR6_2026_10_30_ARGON_PRIVACY_GATE.md`, answered by ID in `PR6_2026_10_30_RESPONSE.md`): no fixture
  exemption; candidates from `git ls-files` and build/cache content reported; extensionless files and the gate's own
  source scanned; value-level exemptions; IPv6, serial and account-name literals, LDAP DNs and domain accounts; owned,
  dated, anchored `.gitleaks.toml` allowlists with the defaults extended exactly. `tools/privacy/test_repository_privacy_check.py`
  (22 tests) runs in CI; CI also gates every commit a pull request adds (and its message) against the pull request's
  own allowlist, and a gitleaks self-test requires one planted canary per rwsafe rule to be reported.
- `security-scans` job: Trivy (filesystem, Gradle lockfiles, configuration; SR-SC-2; checksum-verified binary) and
  Semgrep (Java rules from `semgrep/semgrep-rules` pinned by commit, digest-pinned image, no network), judged by
  `tools/security/baseline_gate.py` against `security/baseline.yaml` (still empty): Trivy HIGH/CRITICAL and Semgrep
  ERROR/WARNING fail unless an exact, owned, unexpired acceptance names them; the gate has its own self-test.
- Jazzer harness (SR-DP-4): `jazzer-junit` in `dataplane` tests, a placeholder `@FuzzTest` with its committed synthetic
  corpus under `src/test/resources/.../PlaceholderParserFuzzTestInputs/`; `unitTest` replays the corpus and CI fuzzes
  for 60 s per target (`fuzzTest`, one JVM per target class, 5 s per input). The ICAP and HTTP decoder targets replace the placeholder when the decoders land.
- Maven-portability smoke build (ADR-011 §4): `generateMavenSmokeBuild` writes `java/build/maven-smoke/pom.xml` and one
  pom per product module (the module's standard source directories, the same dependency edges, every version pinned to
  the Gradle lock); the `maven-portability` job builds and tests the product with plain Maven.
- ArchUnit module-graph fence (PR 4 review D-06): each module depends only on the modules ARCHITECTURE §9 lists (the
  data plane never on persistence, control, worker or CLI; nothing on the data plane) and every class belongs to a
  module; proved on fixtures by `FenceSelfTest.moduleGraphFence`. The fences import every class the product modules
  compile, and a class must declare a package under its own module's root (`classesLiveUnderTheirModuleRoot`).
- Second independent review of pull request 7 (Argon, `docs/reviews/PR7_2026_10_30_ARGON_CI_HARDENING.md`) answered by
  ID in `PR7_2026_10_30_RESPONSE.md`: fail-closed severities and a policy floor, empty-scan refusal and a real-scanner
  canary step, per-resource misconfiguration acceptances with a 90-day cap, one JVM per fuzz class with a per-input
  timeout, and a Maven generator that refuses what it cannot translate. The privacy gate gains `LOCAL_HOME_PATH`, and
  the review scripts mask the workspace and home paths in their output.

## Pending on the Product Owner

Mark the five `validation` jobs (`privacy-gate`, `gitleaks`, `java-tests`, `maven-portability`, `security-scans`) as
required status checks on `main` (none is required today). Decisions still open: Q-7, Q-8, Q-11, Q-12, Q-17..Q-29, Q-37 (ask one batch at a time with
the recommendation first); the twelve MVP-blocking questions are decided
(`docs/design/PO_DECISION_RECORD_2026_10_30_MVP_BLOCKING_QUESTIONS.md`). Lab tenant
procurement (Q-34). Approvers and DPO identity (Q-5). Governance is settled: pull request 2 merged;
`.claude/settings.json` committed; AGENTS.md section 1 (reviews as evidence) and section 9 (standing push/PR/merge
authorisation) amended; the Git-authority decision record RATIFIED; `main` requires a pull request and zero approving
reviews.

## Not done

Every UNVERIFIED mark (phase 0 measures them); the prerequisite neXus PR (phase 1, needs the PO's go); vendoring of the
neXus delivery scripts (`tools/delivery/VENDORED_FROM_NEXUS.md`); Q-29 residual-risk signature (blocks the pilot);
`frontend/` (and with it Semgrep TypeScript); the real Jazzer targets for the ICAP and HTTP decoders (they arrive with
the decoders); Trivy image scanning and SBOM (with the first image, ship pipeline).

## Next (ROADMAP phase 0, in this order)

1. Measurements that need the PO or the proxy team, each recorded masked where ROADMAP phase 0 names: ProxySG access-log
   shapes for the AI category and for uncategorised domains (Q-30), ProxySG capability record (Secure ICAP, max object
   size, Preview), SSL-interception bypass audit, vendor header verification on a lab client, login-flow frame fixtures
   (synthetic bodies), per-client trust matrix, Broadcom support case (Q-20), corporate contract facts incl. the art. 9
   instrument per vendor (Q-33), directory attribute for the HR acknowledgement (Q-35).
2. Phase 1 starts only after the PO's go and the Q-13 decision (neXus ingress PR).

Operating model from here: the High tier (Opus) orchestrates with subagents on the lighter tiers
(`docs/reference/MODEL_TIER_MAP.md`); the architect tier returns only for a new ADR or a decision-record amendment.
