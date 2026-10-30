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

Mark the six `validation` jobs (`privacy-gate`, `gitleaks`, `java-tests`, `frontend`, `maven-portability`,
`security-scans`) as required status checks on `main` (none is required today). Every open question is decided except the information
requests Q-17, Q-23, Q-25 (`docs/design/PO_DECISION_RECORD_2026_10_30_*`). The PO is the proxy administrator and runs the
ProxySG and Broadcom steps from `docs/operations/PROXYSG_PHASE0_GUIDE.md` (Q-20, Q-21); the session asks the PO and records the answers
in `docs/operations/PHASE0_PROXYSG_RECORD.md` (first pass 2026-10-30: appliances, identity format, interception, QUIC,
tenant restrictions). Lab tenant
procurement (Q-34). Approvers and DPO identity (Q-5). Governance is settled: pull request 2 merged;
`.claude/settings.json` committed; AGENTS.md section 1 (reviews as evidence) and section 9 (standing push/PR/merge
authorisation) amended; the Git-authority decision record RATIFIED; `main` requires a pull request and zero approving
reviews.

## Done (MVP data plane, slice 1: ICAP engine)

`java/dataplane` serves ICAP/1.0 on Netty: OPTIONS, REQMOD and RESPMOD with Preview, `ieof`, `100 Continue` and the
RFC 3507 204 rule; strict head, `Encapsulated` and chunked parsing with the ICAP spec §3 limits; every JSON string leaf
normalised and scanned (OFF2-6); Tier-1 detectors in `java/detect` (secret shapes, TCKN and TR IBAN with checksums,
payment cards with Luhn; RE2/J only); REDACT rewrites JSON leaves in place with class tokens and recomputes
`Content-Length`; BLOCK answers a Turkish HTML page or a JSON error; oversize, malformed, encoded and slow bodies are
non-verdicts that block on the fail-closed AI flow; streamed RESPMOD is relayed with one window of delay and aborted
before a leaking window leaves. Verdict events (metadata only) go through a bounded queue to
`POST /internal/v1/verdict-events`. Policy is the built-in development snapshot (`java/policy`). Jazzer targets for the
ICAP head, the chunked decoder and the JSON scanner replace the placeholder. Local run and synthetic replay:
`docs/operations/LOCAL_RUN.md`.

## Done (MVP control plane and admin UI, slice 1)

- `java/persistence`: Flyway V1 and jOOQ (Q-16) over a hand-written schema that `SchemaMatchesMigrationsTest` proves
  against the migrations. Verdict events and findings are metadata only (ADR-009 C1/C2/C6: no body, no raw claim, no raw
  address column; findings are class + count, digest column reserved). Trigger-enforced audit ledger (C7): a mutation of
  an audited table without the `app.*` audit context is refused, the ledger is append-only (update, delete, truncate
  refused). Local break-glass accounts (BCrypt hash only). Tests on an embedded PostgreSQL 16 (no container runtime).
- `java/control` (Spring Boot 4.1.1 with Spring Framework 7.0.9 and Spring Security 7.1.1, PO decision record
  `PO_DECISION_RECORD_2026_10_30_SPRING_BOOT_4`; neXus is on 4.0.8; no Boot plugin; HTTP JSON on Jackson 2): `POST /internal/v1/verdict-events` on its own
  connector (8092; the admin port answers 404 for it and vice versa; 2 MiB cap checked before reading) with the exact
  contract (unknown or missing fields refuse the batch, values never echoed), idempotent on `eventId`; the identity claim
  becomes `USR-<10 hex>` and the client address a /24 label in 240/4 under rwsafe's own HMAC key before persistence, 503
  when the key is missing. Identity: LDAP/AD search-and-bind (Q-9) behind the `Authenticator` seam, a generated
  break-glass account (owner-only initial password file, ledgered), every sign-in ledgered under a pseudonym, login
  throttling per name and client, request bodies bounded as read, session + CSRF cookies, roles
  `security_admin`, `viewer`, `replay_viewer` (read-only, masked). The masking funnel (`ResponseBodyAdvice`) serves the
  masked role (exclusive, read-only) only `MaskedView` bodies through the `rwmask-v1-slice1` text layers, with
  `X-RWSAFE-Masked`, and 503
  `MASKING_UNAVAILABLE` without the key or the estate dictionary; `FunnelCoverageTest` proves every API route has a masked
  projection. Read API: overview, traffic (keyset pages, pseudonym-only user filter), event detail, platforms, health
  (stub). Synthetic sample events (dev profile) through the real ingestion path; `:control:runDev` starts everything
  locally with an embedded PostgreSQL and a synthetic LDAP directory.
- `frontend/` (React 18, TypeScript, MUI 5, Vite 7, Vitest 5): Overview, Traffic, Event detail, Health; errors show the
  server's reason class and sentence. CI job `frontend` (tsc, Vitest, build).
- Second review: Argon `docs/reviews/PR12_2026_10_30_ARGON_CONTROL_PLANE.md`, answered by ID in
  `PR12_2026_10_30_RESPONSE.md`.
- Verified end to end locally: the ICAP engine's replay scenarios reach the control plane and appear in the UI.
- Local run: `docs/operations/LOCAL_RUN.md` "Control plane and admin UI".

## Done (MVP control plane and admin UI, slice 2: merged in PR 16)

- Admin UI in Turkish and English (PO decision Q-38): one catalogue per language under `frontend/src/i18n` (keys in
  English), every UI string moved there; the Turkish catalogue is typed against the English key set and a Vitest test
  fails on a missing key, an empty text or a placeholder mismatch; tr-TR and en-GB numbers and dates (Europe/Istanbul);
  server reason codes stay English identifiers, mapped to labels (`reason.code_<CODE>`). The user menu holds the roles,
  the language switch and sign-out; the choice is remembered per user in the browser (no server-side user settings store
  exists yet).
- Policy registry (AGENTS.md section 6): Flyway V2 (`policy_rule_version`, `policy_approval`, `policy_snapshot`), seeded
  once from `policy/registry-seed.yaml` (equal to the built-in development snapshot, proved by `RegistrySeedTest`). A
  version has mode monitor or enforce and a rollout stage (pilot, 25 %, 50 %, all); a registry version becomes active only
  with a `security_admin` and a `privacy_officer` approval by two different people (service check and database trigger);
  a fail-closed class is never ALLOW or WARN in any version, monitor or enforce, and takes no exception; versions are
  immutable; approvals and snapshots are append-only; every change is ledgered. REST `/api/v1/policy`: list, draft,
  approve, simulation stub (counts how stored verdict events carrying a class would change), exception refusal. The
  `privacy_officer` role is new (directory group binding).
- Signed snapshot feed `GET /internal/v1/policy/snapshot` on its own connector (8091) per POLICY_SNAPSHOT_CONTRACT:
  format 1, monotonic version, Ed25519 via the JDK over the exact body bytes, `X-RWSAFE-Key-Id`, `ETag` and 304; 503
  with a reason without a signing key or a complete registry. Only active enforce versions at stage `all` are compiled
  (format 1 has no group targeting). The active policy is re-signed under the next version at least every 6 hours with no
  rule change (scheduled), and the compiler refuses a snapshot with a fail-closed class at ALLOW or WARN (contract changes
  of the data-plane review, PR 14). Every issued snapshot is recorded and ledgered.
- Screens: Policies (registry table with action, mode, rollout bar, version, status; versions, approval steps,
  simulation panel and a new-version form for a selected rule) and Platforms (platform rows). The masked role reads both
  through the funnel and changes nothing.
- Local run: `docs/operations/LOCAL_RUN.md` "Control plane and admin UI" (dev signing key and its public key for a local
  data plane, the snapshot feed with curl, the two-approval walk-through).

## Done (deploy manifests, branch `feature/deploy-manifests`)

Container builds `deploy/images/{dataplane,control}.Containerfile` (Gradle `imageDist`, UBI 9 OpenJDK 21, digest-pinned
bases, UID 185 group 0, read-only root); kustomize base for `rwsafe-dataplane`, `rwsafe-control` and `rwsafe-db` with
NetworkPolicies, PDB and Secret contracts (`deploy/rwsafe/contracts/runtime-contracts.json`); k3s overlay additions
(priority assignment, platform-peer NetworkPolicies, in-cluster image names with a placeholder digest). CI job
`manifests` runs `tools/deploy/manifest_check.py` (AGENTS.md section 8 rules, quota fit) and its fixture self-test.
Nothing applied; build and apply commands in `DEPLOY_AND_SHARED_HOST_RUNBOOK.md` §7 (apply is the PO's step).

## Not done

ICAP engine, later slices: decompression and base64 layers, the file pipeline, login-step tenant rules, flow shape
fingerprints, group claims on Secure ICAP (`docs/operations/LOCAL_RUN.md` lists them). Slice 2 of the data plane (pull
request 14) added the signed snapshot pull, Secure ICAP with a required client certificate, per-identity and pod-wide
admission, the body budget, the drain window, the verdict spool with backpressure and fixed-label metrics.
Every UNVERIFIED mark (phase 0 measures them); the prerequisite neXus PR (phase 1, needs the PO's go); vendoring of the
neXus delivery scripts (`tools/delivery/VENDORED_FROM_NEXUS.md`); Semgrep TypeScript rules for `frontend/`; control plane
later slices (mTLS on 8091 and 8092, SAML, policy exceptions with expiry for non-fail-closed rules and group targeting of
staged versions (both need a snapshot format with groups), a server-side user settings store for the UI language, the
ratified decision record that mirrors the seed fixture, C3 capture store, the Incidents, Identities and roles and
Administration screens, Playwright masked-role leak probe, the cluster PostgreSQL Job); the
Jazzer targets for the LLM-gateway HTTP decoder and the SSE parser (they arrive with them); Trivy image scanning and SBOM (with
the first image, ship pipeline).

## Next (ROADMAP phase 0, in this order)

1. Measurements that need the PO or the proxy team, each recorded masked where ROADMAP phase 0 names: ProxySG access-log
   shapes for the AI category and for uncategorised domains (Q-30), ProxySG capability record (Secure ICAP, max object
   size, Preview), SSL-interception bypass audit, vendor header verification on a lab client, login-flow frame fixtures
   (synthetic bodies), per-client trust matrix, Broadcom support case (Q-20), corporate contract facts incl. the art. 9
   instrument per vendor (Q-33), directory attribute for the HR acknowledgement (Q-35).
2. Phase 1 starts only after the PO's go and the Q-13 decision (neXus ingress PR).

Operating model from here: the High tier (Opus) orchestrates with subagents on the lighter tiers
(`docs/reference/MODEL_TIER_MAP.md`); the architect tier returns only for a new ADR or a decision-record amendment.
