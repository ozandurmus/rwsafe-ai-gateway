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
  masked role (exclusive, read-only) only `MaskedView` bodies through the text layers (now `rwmask-v1-slice2`), with
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
- Scoped policy control (PO decisions Q-39 and Q-40, branch `feature/scoped-policy-control`): migration V3 gives every
  rule version a scope (`ANY` or 1 to 32 directory groups; one active version per rule, mode and scope), retires the
  percentage stages for new versions, adds the platform `retired` status (one `security_admin` with a reason, ledgered,
  never deleted, back only through a new two-approval version) and stores the scoped-rule ids of verdict events. The
  compiler emits snapshot format 2 (`scopedRules`, always present); the data-plane side is a separate lane. The masked
  role sees group names only as `GRP-` pseudonyms. Policies shows a scope column and a scope picker instead of the
  rollout bar; Platforms has the retire action with a reason and a built-in confirmation step. After the second review
  (`docs/reviews/PR21_2026_10_30_RESPONSE.md`): group names use the shared `java/policy` `GroupNames` normal form
  everywhere (API, database check, compiler, masked pseudonyms, UI duplicate check); a retirement supersedes the
  platform's pending drafts; an active group-scoped version can be withdrawn (status `withdrawn`, its groups fall back
  to `ANY`; since PO decision Q-41 of 2026-10-31 one security administrator with a reason, see "Done (single-administrator
  withdrawal)"); drafts for different scopes wait side by side; verdict events
  carry only `class.<CLASS>@<version>` rule ids and the read paths return them; free-text reasons refuse identifiers.
- Screens: Policies (registry table with action, mode, scope, version, status; versions, approval steps,
  simulation panel and a new-version form for a selected rule) and Platforms (platform rows). The masked role reads both
  through the funnel and changes nothing.
- Local run: `docs/operations/LOCAL_RUN.md` "Control plane and admin UI" (dev signing key and its public key for a local
  data plane, the snapshot feed with curl, the two-approval walk-through).

## Done (scoped rules, data plane: branch `feature/scoped-policy-dataplane`, not yet merged)

- Snapshot format 2 (POLICY_SNAPSHOT_CONTRACT.md, PO decision Q-39) in `java/policy`: `SnapshotCodec` reads formats 1
  and 2 and refuses a scoped rule outside the contract (`SCOPE_FIELD`, `SCOPE_DUPLICATE_ID`, `SCOPE_GROUPS`,
  `SCOPE_MODE`, `SCOPE_TOO_MANY`, and `FAIL_CLOSED_WEAKENED` in any scope and mode); `PolicyEvaluator.resolve` applies the
  four evaluation steps (ANY baseline; trusted claim: matching enforce rules replace ANY, strictest wins; no trusted
  claim: strictest of ANY and every enforce rule; monitor rules reported, never applied).
- Data plane: `X-Authenticated-Groups` parsed per transaction (encoding configured as plain or base64, format
  UNVERIFIED; anything unreadable is no claim) and trusted only on the mutual-TLS listener; verdict events carry
  `appliedRuleIds` and
  `monitorRuleIds` (rule ids only, at most 16 each, written only when non-empty). Synthetic end-to-end tests cover plain
  and Secure ICAP; `docs/operations/LOCAL_RUN.md` "Scoped rules".
- Second review (Argon, `docs/reviews/PR20_2026_10_30_ARGON_SCOPED_POLICY_DATAPLANE.md`) answered in
  `docs/reviews/PR20_2026_10_30_RESPONSE.md`: the header encoding is configured, never guessed; one group-name
  normalisation (`GroupNames`, Turkish I folded) on both sides; exact snapshot field sets and strict UTF-8.
- ConfigMap contract for the deploy owner (not edited here): the data plane reads `RWSAFE_GROUP_CLAIM_ENCODING`, value
  `plain` or `base64`; absent or any other value disables group claims (strictest policy for everyone). It belongs in the
  data plane's uncommitted runtime ConfigMap once the proxy's format is verified with the PO.
- Open: the control plane's ingestion must accept the two new event fields before a scoped rule takes part in a verdict
  (it refuses unknown fields today); the control compiler must emit exactly the contract's fields, a non-empty class map
  per scoped rule, and group names without commas.

## Done (deploy manifests, merged in PR 18)

Container builds `deploy/images/{dataplane,control}.Containerfile` (Gradle `imageDist`, UBI 9 OpenJDK 21, digest-pinned
bases, UID 185 group 0, read-only root); kustomize base for `rwsafe-icap` (the `rwsafe-dataplane` image), `rwsafe-control` and
`rwsafe-db` (two roles, ADR-002) with NetworkPolicies, PDB and Secret contracts (`deploy/rwsafe/contracts/runtime-contracts.json`); k3s overlay additions
(priority assignment, platform-peer NetworkPolicies, in-cluster image names with a placeholder digest). CI job
`manifests` runs `tools/deploy/manifest_check.py` (AGENTS.md section 8 rules, quota fit) and its fixture self-test.
Nothing applied; build and apply commands in `DEPLOY_AND_SHARED_HOST_RUNBOOK.md` §7 (apply is the PO's step).

## Done (leak probe and log scanner, branch `feature/leak-probe`)

Both run in `:control:test`, so in `unitTest` and the CI `java-tests` job; no workflow change.

- Masked-role leak probe, API level (AGENTS.md 4.11, SR-PRIV-2, AC-5): `MaskedRoleLeakProbeTest` seeds the control plane
  through its real paths with a synthetic estate built at runtime (`support/Canaries`: TCKN and TR IBAN with valid
  checksums, TR mobile numbers, a Luhn card, a secret shape, Turkish names, directory logins, e-mail addresses, domain
  accounts, host and group names in the estate dictionary, RFC 5737 addresses, an operator signing key id naming an
  estate host): verdict events through the capture sink, Turkish-name directory users who sign in, draft and approve a
  policy version. The masked user walks every endpoint of `frontend/src/api.ts` and every `/api` route the server maps
  (all pages, filters, event details, simulations, refused mutations); the test fails when either side gains an endpoint
  the walk does not cover (`support/ApiInventory`). Response bodies and headers are compared token by token as HMAC
  digests under a per-run key (`support/LeakProbe`); a hit names the endpoint template, JSON path class and canary class,
  never the value. Every masked page must carry `X-RWSAFE-Masked` and the rule-set header. The same walk as a viewer is
  the positive control (it must see the classes a viewer sees in clear, and still no identity claim or address). No
  export exists yet; the inventory check fails as soon as one appears unprobed. Result: zero hits, no leak found.
- Fail closed (AGENTS.md 4.10, SR-PRIV-7): `FailClosedDictionaryMissingProbeTest` and `FailClosedKeyMissingProbeTest`
  refuse the masked sign-in (503) and answer every read of the inventory with 503 `MASKING_UNAVAILABLE` and every
  mutation with 403 for a request that already carries the masked role.
- Log scanner (AGENTS.md 4.14, SR-PRIV-6): `LogScannerEndToEndTest` runs the real data plane (ICAP engine, event
  shipper with its spool, metrics endpoint) against the control plane's capture sink in one JVM; synthetic bodies with
  random markers and identifier values pass allow, redact, block (JSON and page), malformed JSON, oversize, encoded,
  streamed relay and abort, a marked request URL and two ICAP framing errors, plus seven refused ingestion batches that
  carry markers. Logback (rwsafe loggers at TRACE, Netty at DEBUG), `java.util.logging`, uncaught exceptions, the
  console, the Prometheus text, block and error pages, control-plane answers and every stored row hold no marker, body
  fragment, identity claim or client address (the spool is checked for bodies only: its wire format carries the claim by
  design). The data plane runs on its own Netty line there (strict test constraint in `control/build.gradle.kts`).
- Closed gaps the probe exposed: ingestion refuses an event whose `platform` is not a platform id of the registry (any
  version, or `unknown`) or whose `surface` or `step` is not one of the flow classifier's fixed enumerations; the
  registry refuses a platform id that a Tier-1 detector recognises or that holds a run of six or more digits (a number
  glued to letters escapes the detectors), on top of the estate check. The traffic platform filter takes only a registry
  platform id (SR-PRIV-4; the user filter already took only a pseudonym). The probe seeds identifier-shaped values,
  estate names, a Turkish name and a letter-glued TCKN into those fields and asserts each batch is refused, nothing is
  stored and no role sees them; `theMaskedRolesTrafficFiltersTakeNoRawValue` asserts every raw guess is refused as a
  filter without being echoed.
- After the merge of PR 17, 18 and 21: the walk covers the withdrawal and retirement routes, and the seeding activates a
  group-scoped class version naming estate and Turkish-letter directory groups (the masked role sees only `GRP-`
  pseudonyms; the viewer, the positive control, sees the names), a withdrawal and a platform retirement. The probe found
  a leak and it is fixed: the free-text withdrawal and retirement reasons reached the masked role with a Turkish name and
  a number glued to letters, which the text masker cannot recognise (no name layer; the detectors need a word
  boundary). The masked projection now withholds both reasons (`[FREE_TEXT_WITHHELD]`); a reason with ten or more
  digits in a row is refused for every role, and a draft's `reasonCode` takes the platform-id identifier check. The log
  scanner runs the data plane with plain group claims (`X-Authenticated-Groups`, one well-formed and one repeated) and
  finds no group name in any log, metric, error page, stored row or the spool.
- After the merge of PR 22 (end-user notices): the probe configures the notice's runtime values as canaries
  (controller name, contact, policy link), seeds acknowledgements with the claimants' identity claims through the
  internal intake on the capture-sink port (and asserts the intake answers 404 on the admin port, signed in or not, and
  on the snapshot feed), and walks `GET /api/v1/notice` and `GET /api/v1/notice/acknowledgements` for every pseudonym
  the traffic screen shows. The masked notice carries no sections and no configured value; acknowledgements show
  `USR-` pseudonyms only; the viewer's positive control sees the configured values; the acknowledgements' user filter
  refuses every raw guess. No leak found.
- Second review (Argon, `docs/reviews/PR24_2026_10_31_ARGON_LEAK_PROBE.md`, DO NOT MERGE with one P0), answered by ID
  in `PR24_2026_10_31_RESPONSE.md`. One shared identifier check (`privacy/IdentifierCheck`: detectors, six or more
  digits in a row even glued to letters, estate terms on Turkish-folded letters, 503 without the dictionary) guards
  every free value the registry stores. Ingestion takes no free token: `reason` is the closed `ReasonCodes` set
  (platform-core; the data plane's end-to-end tests fail on a reason missing from it) and `correlationId` a canonical
  UUID. Retirement and withdrawal reasons stay withheld from the masked role permanently and refuse six or more digits
  (PO, Q-1 and Q-2). The probe compares in NFC and Turkish-folded form with the extra digit joins, and its positive control
  covers every canary class: a test-only fixture route shows the classes no real screen holds. The log scanner also runs
  with the capture sink down (the spool is written, scanned and replayed), sends the identity headers on every request,
  and finds two planted markers before it asserts no finding. Confirmation review
  (`PR24_2026_10_31_ARGON_LEAK_PROBE_RECHECK.md`, MERGE WITH CORRECTIONS) answered in the same response file: finding
  classes are known DLP classes only; the identifier check joins digit groups across a space, hyphen, dot or underscore
  and also applies to scope group names and at activation; the probe decodes percent escapes per sequence and emits every
  span of grouped digits.
- Not covered: a browser-level (Playwright) walk of the screens (needs a browser download; the UI reads only the API
  client the probe enumerates); layer 4 customer numbers (pending Q-23; the name dictionary arrived with masking
  layers 4 and 5 below); third-party loggers below their production levels.

## Done (SIEM export, branch `feature/siem-export`)

`java/control` package `siem` (ROADMAP MVP "SIEM out (CEF/LEEF/HEC)", SR-SIEM-1 to 3): verdict events and audit-ledger rows
leave as CEF or LEEF 1.0 lines over syslog with TLS (RFC 5425 octet framing) and as Splunk HEC JSON over HTTPS. A fixed
field set (`SiemField`; C1/C2/C6/C7 only, no body field, schema test). Every value must match its exact shape and hold no
estate term, or it leaves as `[WITHHELD]`. Ledger row keys leave as written only in an allow-listed table's key shape;
account keys become `USR-` pseudonyms and any other key a keyed `KEY-` pseudonym. Every string is stripped of control
characters and bounded ANSI sequences and length-capped. CEF escaping, LEEF tab, `=` and `\` safety are tested against an
independent parser. TLS only (CA bundle, host-name check, TLS 1.3/1.2), no UDP or plain-TCP path. Without the privacy key
or the estate dictionary nothing starts; an unsafe destination is not started; the Health screen's `siem` row says why.
Commit-safe order (PR 23 review D-1): Flyway V7 adds `tx_id` (the writing transaction) to `verdict_event` and
`audit_event`, and the exporter reads only rows below the snapshot's xmin in (tx_id, id) order, so a late commit is never
overtaken. Two threads per destination around a bounded queue, a page per stream per round: the reader defers when the
queue has no room (nothing dropped, ingestion untouched). The sender retries with exponential back-off and moves the
persisted watermark (`siem_watermark`) only after acknowledgement: at least once, restart from the watermark. Creating a
watermark is a ledger row. Ledger rows always export from the first one; `latest` skips only verdict events and records
the count (Q-SIEM-1). A delivered batch whose watermark save fails is kept and only the save is retried. Health and
fixed-label counters (`rwsafe_siem_*`) show the backlog (rows held behind an open transaction counted separately), a
stall after 3 minutes without progress, separate reader and sender failure states and possibly lost syslog batches.
Both application database roles abort a session idle in a transaction after 60 s (Q-SIEM-3). Audit durability relies on
HEC (Q-SIEM-2). Tests run a local TLS syslog receiver and a HEC stub with certificates generated at runtime, and two
concurrent transactions where the older commits last. Second review `docs/reviews/PR23_2026_10_31_ARGON_SIEM_EXPORT.md`
and confirmation review `PR23_2026_10_31_ARGON_SIEM_EXPORT_RECHECK.md`, answered in `PR23_2026_10_31_RESPONSE.md`.
Configuration and residuals: `docs/operations/LOCAL_RUN.md` "SIEM export". The runtime contract holds the ConfigMap
`rwsafe-siem-destination` and the Secret `rwsafe-siem-credentials`.

## Done (end-user notices, branch `feature/end-user-notices`)

- Turkish end-user catalogue (AGENTS.md section 3, council PRIV-2): first-use notice (aydınlatma metni: what is
  inspected, why, legal basis art. 5/2-ç and 5/2-f with explicit consent excluded (Q-32), transfers and the art. 9
  instrument (Q-33), retention, rights, personal accounts (Q-6), acknowledgement), the block page per reason kind
  (fail-closed class, uninspectable content, inspection unavailable, platform not allowed, personal account, other),
  the coaching (WARN) page, the stream-termination message and the class and reason labels. Product copy
  `java/platform-core/src/main/resources/io/rwsafe/platform/enduser/end-user-tr.properties`, review copies under
  `docs/i18n/tr` (a test fails when they differ). Configured values (controller name, data protection contact, policy
  link, retention days) come from `RWSAFE_ENDUSER_*` environment values, never committed. The seven legal review items
  LR-1..LR-7 are closed: the PO approved the texts on 2026-10-31
  (`PO_DECISION_RECORD_2026_10_31_END_USER_NOTICE_LEGAL_REVIEW.md`); the full-text tier text and the objection sentence
  are removed, `retention_raw` is gone from the configuration, catalogue `tr-3` (every employee acknowledges again). The
  data protection officer's confirmation is the PO's responsibility.
- `EndUserPages` (platform-core) renders self-contained UTF-8 pages: every text and value HTML-escaped, a
  Content-Security-Policy that loads nothing, no script, link or external resource, the reference id only. The notice
  version is `catalogue.version` plus 8 hex of the rendered notice, so a text or value change is a new version (PC-1);
  an incomplete notice has no version. The data plane's `BlockPages` renders from it (API JSON and SSE messages too);
  `IcapConnectionHandler` is unchanged.
- Notice acknowledgement (C12): Flyway `V5__notice_acknowledgement.sql` (V3 and V4 are reserved by open branches; merge
  them first or the database must be fresh), pseudonym only, idempotent per user, version and source, ledgered, never
  updated; `notice_version` records when each version was first issued, and an acknowledgement must name an issued
  version. Intake `POST /internal/v1/notice-acknowledgements` on the capture sink: refused while the notice is
  incomplete; the interactive sources (banner, IDE first run, gateway credential issue) record the current version
  only; the directory HR record (version and date, Q-35) may carry an earlier issued version as history; the date lies
  between the version's issue time and now (5 minutes of skew each way). `GET /api/v1/notice` and
  `GET /api/v1/notice/acknowledgements?user=USR-…` for every role, masked through the funnel (the masked notice omits the
  configured values). `NoticeAcknowledgementService.contentCaptureAllowed` is the SR-PRIV-10 gate for the C3 capture
  store (fails closed without the current version's record).
- Second review (Argon, `docs/reviews/PR22_2026_10_31_ARGON_END_USER_NOTICES.md`): D-01 to D-08 fixed and PO-Q1 to
  PO-Q3 taken as recommended (`PR22_2026_10_31_RESPONSE.md`); catalogue `tr-2` then, `tr-3` after the PO legal review.
- Open: the banner and IDE first-run surfaces that show the notice and post the acknowledgement, the directory import
  job, the `RWSAFE_ENDUSER_*` ConfigMap contract in `deploy/rwsafe/contracts`, a call site for the coaching page, and
  the data plane reasons `PLATFORM_NOT_ALLOWED`, `VENDOR_INSTRUMENT_MISSING` and `PERSONAL_ACCOUNT` (their pages exist).

## Done (redacted capture, branch `feature/redacted-capture`)

ROADMAP "Capture in redacted mode (Q-4 b)", acceptance SR-PRIV-10, SR-PRIV-11, SR-HOST-2. Off by default on both sides
(`RWSAFE_CAPTURE_MODE=redacted` turns it on); `docs/operations/LOCAL_RUN.md` "Redacted capture".

- Data plane: a REDACT verdict event (REQMOD and whole-body RESPMOD) carries the body the engine already rewrote
  (`CapturedText`: the redaction's array wrapped on the request thread, decoded and bounded to 32 KiB by default, at
  most 64 KiB, on the shipper thread); BLOCK, ALLOW, non-verdicts and stream aborts carry none. Same queue and spool;
  posted arrays are cut to 512 Ki characters (under the 2 MiB ingestion cap); the spool keeps the text only below the
  Q-3 redacted watermark of its filesystem, otherwise it spools metadata only and counts it (Prometheus
  `icap_capture_*`). The `capture` object is written only when present, so other events keep the earlier field set.
- Shared breaker `platform.capacity.WatermarkBreaker`: raw off at 75 %, redacted off at 85 %, resume 5 points lower
  (hysteresis is this lane's choice), no reading for 5 minutes trips it.
- Control plane `control.capture`: the sink stores content only for a REDACT verdict of a user with an acknowledgement
  of the current notice (`NoticeAcknowledgementService.contentCaptureAllowed`, PR 22), below the store volume's
  watermark (read every 30 s), when no Tier-1 detector hits the text (raw and normalised), after the masking layers ran
  at persistence; everything else is dropped with a counted reason while metadata and verdicts are stored.
- Storage per ADR-009 §2-§3 (PO decision on the PR 25 review, Q-1): content lives outside PostgreSQL in the capture
  store on its own volume (`RWSAFE_CAPTURE_STORE_DIR`), as content-defined chunks (8-64 KiB, Gear hash) addressed by a
  keyed HMAC and stored once (reference-counted); each chunk is AES-256-GCM under its own data key (per chunk, not per
  record, because a deduplicated chunk is shared); a per-record key's HMAC binds event id, user, capture and expiry
  times, truncation, rule set, size and the ordered chunk list. MAX_STORE_BYTES (80 GiB) evicts the oldest records
  without a hold, receipted. Expiry counts from the event's own time, at most 90 days.
- Keys (Q-3): the capture key is its own Secret (`<id>.key`, `active`, optional `shredded` list). A planned rotation
  re-wraps every live or held record key and chunk key under the active key (`REWRAP` key events, content never
  decrypted); emergency crypto-shredding is a listed key: its records are deleted with a `KEY_SHREDDED` receipt and an
  `EMERGENCY_SHRED` key event. Maintenance (retention, cap, re-wrap, shred, orphan-file sweep) runs in the protected
  windows. Health shows `capture` (bytes against the cap, records under older keys) and `capture-watermark`.
- Migration V8: `capture_record`, `capture_manifest`, `capture_chunk`, `capture_store_usage` (metadata, wrapped keys and
  references only; immutable except hold and wrapping; deletes and re-wraps ledgered), `capture_read`,
  `capture_deletion_receipt` and `capture_key_event` (append-only, ledgered; the SIEM export reads the ledger).
- Read route `POST /api/v1/captures/{eventId}/read`: MVP reader roles `security_admin` and `privacy_officer` (PO
  decision Q-2 on the PR 25 review), `DSAR` for `privacy_officer` only, reason code and case id; every request
  ledgered, refusals included, `SERVED` only after the record opened; expired records are never served; the text is
  framed inert (C0/C1, the full Bidi_Control set, U+2028/2029); the masked projection withholds it. The API-level
  leak probe (PR 24) walks the route with seeded captures as the masked role and the viewer (refused by the security chain and ledgered, nothing seen;
  an admin read is its positive control); a capture test proves no log line carries content. Deletions reach the SIEM
  as exported ledger rows (PR 23) keyed by the event id.
- Second review (Argon, `docs/reviews/PR25_2026_10_31_ARGON_REDACTED_CAPTURE.md`), answered by id in
  `docs/reviews/PR25_2026_10_31_RESPONSE.md`; the confirmation review (`PR25_2026_10_31_ARGON_REDACTED_CAPTURE_RECHECK.md`)
  closed everything and its D-08 (dedup decided again inside the insert) and D-09 (re-wrap from mounted keys only)
  are fixed. The migration is V8 (after V7).
- Open: ADR-009 gaps listed in the response (C5 special-category flag, legal
  hold and DSAR APIs, restore-time receipt replay, the worker module); deploy wiring (the capture PVC, the capture-key
  Secret, `RWSAFE_CAPTURE_*` in the ConfigMaps and contracts); the screen that opens a record; persisted skip
  counters.

- Open: ADR-009 gaps listed in the response (C5 special-category flag, masking layers 4 and 5 at persistence, legal
  hold and DSAR APIs, restore-time receipt replay, the worker module); the screen that opens a record; persisted skip
  counters. Deploy wiring: done in pull request 27 (below).

## Done (deploy wiring 2, pull request 27)

The features above are wired into `deploy/rwsafe/`, every one off by default; nothing applied (the PO's step,
`DEPLOY_AND_SHARED_HOST_RUNBOOK.md` §7.4, first-run steps §7.5).

- Data plane: `RWSAFE_CAPTURE_MODE` off, `RWSAFE_CAPTURE_MAX_BYTES` 32768, `RWSAFE_GROUP_CLAIM_ENCODING` unset (group
  claims disabled until the proxy's encoding is verified), `RWSAFE_ENDUSER_*` from the uncommitted ConfigMap
  `rwsafe-enduser` (optional).
- Control plane: `RWSAFE_SIEM_*` from `rwsafe-siem-destination` (CA bundle as a file) and the HEC token from
  `rwsafe-siem-credentials`; capture with the Secret `rwsafe-capture-key` mounted whole and the PVC
  `rwsafe-capture-store` (40Gi; application cap 32 GiB, below ADR-009's 80 GiB until the PO decides on HOST-A's disk,
  PR 27 review Q-2); the watermark paths; `RWSAFE_ENDUSER_*`; the metrics listener on 9400 (`GET /metrics` only, the
  SIEM exporter's Prometheus text, 404 for anything else before security; `/readyz` counts it).
- k3s overlay: egress `rwsafe-control-to-siem` with its own RFC 5737 placeholder; 9400 and 9401 admitted only from pods
  labelled `rwsafe.io/metrics-scraper=true` in a namespace with the same label.
- `tools/deploy/manifest_check.py`: claimed PVCs rendered; PVCs and claim templates within the LimitRange maximum;
  projected Secret and ConfigMap sources in the contract; an ipBlock without a valid cidr, an ingress rule without
  `from`, an empty peer or an empty selector in a peer fail; no placeholder shared by two policies; all requested
  storage within `HOST_FREE_STORAGE_BUDGET` (138Gi: PORTS_AND_RESOURCES §1 free space minus the kubelet's eviction
  reserve). Namespace `rwsafe` now requests 60Gi (database 20Gi, capture 40Gi).
- Second review: `docs/reviews/PR27_2026_10_31_ARGON_DEPLOY_WIRING_2.md`, answered in `PR27_2026_10_31_RESPONSE.md`.
- Residual (accepted, PR 27 review Q-1): 9401 also holds the ICAP preStop drain, so an admitted scraper pod could
  drain an ICAP pod; 9402 is the gateway's port in the frozen plan, so the drain gets no port of its own.
- Departures: the frozen runbook gained §7.5 and the two-placeholder estate patch in §7.4 (ratified with the rest of
  section 7 by PO decision Q-42, `docs/design/PO_DECISION_RECORD_2026_10_31_Q41_Q42_Q44.md`), and the frozen plan's capture
  claim (100Gi) is 40Gi for now, which still needs the PO's record. The quota ceilings of the three namespaces (150Gi, 20Gi,
  30Gi; 200Gi together) still exceed the host-free budget: the check bounds what is requested, not the quotas.

Product Owner inputs, before the first release or the feature named:

1. The SIEM receivers' CIDR (`siem-cidr`) and the ConfigMap `rwsafe-siem-destination`: §7.4 refuses a release without
   it. The HEC token Secret when HEC is used; confirm the receivers' ports (6514, 8088).
2. The five notice values in `rwsafe-enduser` (controller name, DPO contact, policy link, two retention figures).
3. The capture key Secret `rwsafe-capture-key`, and the go-ahead that sets `RWSAFE_CAPTURE_MODE: "redacted"` in both
   ConfigMaps (a pull request).
4. The proxy's encoding of `X-Authenticated-Groups` (`plain` or `base64`), then a pull request setting
   `RWSAFE_GROUP_CLAIM_ENCODING`.
5. The scraper: label its namespace and its pods `rwsafe.io/metrics-scraper=true`.
6. HOST-A's disk (80 % used): reclaim space or confirm the 32 GiB capture cap; raising it, the 40Gi claim or the
   138Gi budget needs a new measurement and the PO's decision.

## Done (masking layers 4 and 5, branch `feature/masking-layers-4-5`, pull request 26)

- Rule set `rwmask-v1-slice2` (`TextMasker.RULE_SET`, header `X-RWSAFE-Mask-Rules` on every masked page). One
  pipeline for every path (`mask`, `maskFreeText`, `maskVendorHost`): each layer claims spans of the original text, no
  layer touches a claimed span, the result is written once, so a token is never masked again and one value reads the
  same on screens, in the capture store and in the SIEM export. Order: tokens and UUIDs kept; Tier-1 detectors on the
  text and its folded lower- and upper-case forms; URL hosts with their userinfo, e-mail, user-directory paths,
  `DOMAIN\user`; IPv6 (with IPv4-mapped) then IPv4; IBAN shapes (any country, letters in the account part, glued);
  mobile numbers in every form (hyphen, dot, underscore, parentheses, `+90`, `90`, `0090`) and every digit run joined as
  `IdentifierCheck` joins it (TCKN, TEL, CARD, otherwise `NUM-` from six digits, glued, grouped or free-standing; only
  an exact calendar date is excepted); the estate dictionary, folded, every run of separators and spaces as one; names;
  host-shaped names. Free text adds lone names, the word after a keyword (host, user, kullanıcı, müşteri, hesap; TCKN
  and IBAN only before a word with a digit; from and to only before an identifier-shaped word; ordinary product and
  operational words never) and serial-like tokens (`SER-`). Every shape `IdentifierCheck` refuses is masked (tested on both paths). A text over the detectors' finding
  limit in any piece is withheld whole. An empty estate dictionary is unavailable (503), like a missing one.
- Layer 4: a committed Turkish name dictionary (`java/control/src/main/resources/io/rwsafe/control/privacy/names/`;
  source and licence in its README, PO decision Q-23). Folded matching (NFC, case, every i form, Turkish letters),
  whole words, apostrophes `' ’ ‘ ʼ ` ´`, simple and compound case endings without an apostrophe with the longest,
  non-everyday stem preferred and softened consonants restored (Mehmede, Burağa). A person (a given and a family name,
  or an initial and a name: `A. Yılmaz`, `Ayşe N. Yılmaz`, `a.yilmaz`; either order; any case mix; three lower-case
  words; a suffixed first word; a capitalised word hyphenated to a family name) is one `NAME-<WORD>` in every field,
  keyed by the sorted names. Privacy before readability (orchestrator, PR 26 confirmation review): in free text every
  capitalised name word is a name, alone, in capitals or with an ending; an everyday word that is also a name stays a
  word only in lower case and alone, and is a name next to another name word or by a title (Sayın, Dr., Bey, Beye,
  Hanıma). A given name followed by a lower-case everyday family name is taken as one person ("Mehmet yazıcı").
  Two- and three-letter stems with an ending count only next to another name word or capitalised. `<WORD>` (`Pseudonymiser.word`) is four consonant-vowel
  syllables keyed by rwsafe's HMAC, never itself a dictionary name, consonants only if every draw is refused.
- Applied: error messages, health details (masked role); captured text at persistence (`CaptureSink`, SR-PRIV-15);
  registry host columns keep public vendor endpoints (`maskVendorHost`). Retirement and withdrawal reasons stay withheld
  from the masked role (PR 24 Q-1) and are refused on write when `IdentifierCheck` or the free-text layers would change
  them, vendor endpoints of approved platform rows excepted. The SIEM export uses `IdentifierCheck` for vocabulary and
  its folded estate comparison, and sends a free-text ledger reason only through the free-text masker.
- Leak probe: free-text name, glued TCKN and domain-account canaries in the positive-control fixture; names in
  registry reasons are refused at write; the admin's capture read shows the person as a `NAME-<WORD>`.
- Second review (Argon, `docs/reviews/PR26_2026_10_31_ARGON_MASKING_LAYERS_4_5.md`, DO NOT MERGE) and its
  confirmation review (`PR26_2026_10_31_ARGON_MASKING_LAYERS_4_5_RECHECK.md`: D-02, D-03, D-05, D-07, D-08 closed;
  N-01 to N-04) answered by id in `docs/reviews/PR26_2026_10_31_RESPONSE.md`. Class-token widening was question Q-44:
  the PO chose the B3 pseudonym registry, token formats unchanged (`docs/design/PO_DECISION_RECORD_2026_10_31_Q41_Q42_Q44.md`).
- Remaining before `rwmask-v1` (MASKING_AND_PRIVACY B2, B3): the B3 `pseudonym_registry` (class tokens stay 4 hex;
  PO decision Q-44 builds the registry next, in its own lane with migration V10), MAC OUI-preserving masking (a MAC reads `[REDACTED_IP]` today),
  customer numbers `CUST-` by the PO's format rules (Q-23; only the word after müşteri, customer or hesap is `CUST-`
  now), project code names (they need an estate list of code names that does not exist yet).

## Done (admin UI slice 3, pull request 28)

Screens for the control-plane features merged on 2026-10-31; every new string in both catalogues (Turkish in plain words).

- Captured content reader (event screen, REDACT events only, since nothing else is captured): offered to
  `security_admin` and `privacy_officer` only, never to a masked session, a viewer or a session that also holds
  `replay_viewer`. Reason codes per role (PR 28 review Q-1, ADR-009 §5), enforced by `CaptureReadController` and
  mirrored in the UI: incident reasons (`INCIDENT_INVESTIGATION`, `FALSE_POSITIVE_REVIEW`, `LEGAL_HOLD_REVIEW`,
  `REGULATOR_REQUEST`) for `security_admin`, `DSAR` for `privacy_officer`, both sets for a person holding both roles;
  `CaptureReasonCodesUiTest` fails when `CAPTURE_REASON_CODES` or `CAPTURE_REASONS_BY_ROLE` in `frontend/src/api.ts`
  and the server's differ. A case id (Q-2, D-01) has at least one letter and passes the shared `IdentifierCheck` (no
  detector hit, no run of six or more digits even across a separator, no estate term); otherwise 400 `CASE_ID_REFUSED`,
  ledgered without the value and never repeated; the browser mirrors the shape rules and forgets a refused value. The
  form keeps nothing for the browser (autocomplete and spell check off, cleared on close; D-02). An in-page
  confirmation that the read is recorded; the text rendered as a text node only (never HTML) with the recorded-read
  notice and its ledger id, the truncation and expiry; refusals show the server's reason.
- Health: the SIEM export, capture and capture-watermark cards say in plain words what each state means and what to do,
  and show their counts by name per destination. The counts come from a structured `counts` object on every health
  component (D-03: fixed keys, numbers and 0/1 conditions only, no identifier; the masked projection carries it as it
  is), asserted in `SiemTransportTest` and `RedactedCaptureIntegrationTest` and read by `frontend/src/healthFacts.ts`,
  which drops any value that is not a non-negative safe integer; the server's detail is still shown beside them.
- Notice (new tab "Aydınlatma metni"): version, catalogue version, completeness, missing and refused settings, the
  acknowledged count, the sections as text for unmasked roles and the masked projection as served (no sections); an
  incomplete notice says so for every role (D-04); an acknowledgement lookup that sends only a well-formed `USR-`
  pseudonym.
- `frontend/src/api.ts` gained `readCapture`, `notice` and `noticeAcknowledgements`; the leak probe already walked those
  routes, so its inventory check passes unchanged. Vitest 61, `tsc` clean, `:control:test` 203 green on the tree merged with pull request 26.
- Second review `docs/reviews/PR28_2026_10_31_ARGON_ADMIN_UI_SLICE3.md` (MERGE WITH CORRECTIONS), answered in
  `PR28_2026_10_31_RESPONSE.md`.
- Open: ADR-009 §5 still names `security_analyst` for the incident read (the role does not exist yet; the PO's records
  give it to `security_admin`); the event list does not say which events hold captured content.

## Done (single-administrator withdrawal, branch `feature/q41-single-admin-withdrawal`)

PO decisions Q-41, Q-42 and Q-44 of 2026-10-31 (`docs/design/PO_DECISION_RECORD_2026_10_31_Q41_Q42_Q44.md`, RATIFIED); it supersedes
the orchestrator's interim Q-41 decision (two approvals) in `docs/reviews/PR21_2026_10_30_RESPONSE.md`.

- Q-41: one `security_admin` withdraws an active group-scoped class version with a reason, effective at once: the
  version becomes `withdrawn` (kept with the time, the administrator's pseudonym and the reason), leaves the next
  snapshot, and its groups fall back to `ANY`; a pending draft of the same rule, mode and scope (and any approval it
  holds) is superseded in the same transaction (PR 30 review D-01). The reason takes the platform-retirement checks (`IdentifierCheck`, the
  free-text layers, the estate dictionary; withheld from the masked role). Ledger action `policy.scope_withdraw`, so the
  SIEM export carries it. The viewer, the privacy officer alone and the masked role get 403. Residual risk accepted by
  the PO: one person can loosen policy for a group.
- Flyway `V9__single_admin_withdrawal.sql`: column `withdrawn_by`; the guard refuses a withdrawal whose ledger row does
  not name the same administrator and reason (as for retirement), refuses every new withdrawal request
  (`POLICY_WITHDRAWAL_REQUEST_RETIRED`) and the activation of an old one; a pending V3 request is superseded by the
  migration (ledgered as `system:migration`); an active V3 request and the version it withdrew stay as history.
- The two-approval request path is gone from the store, service, API (the withdrawal route now returns the withdrawn
  version, HTTP 200) and UI ("Geri çek": reason, in-page confirmation, result line; no approval card for a withdrawal).
- Q-42: runbook section 7 ratified as part of the frozen runbook (a ratification line under its heading). Q-44: the B3
  pseudonym registry is built next by its own lane (migration V10).
- Tests: `PolicyRegistryStoreTest` (one administrator withdraws; ledger actor and reason checked by the trigger; direct
  SQL without them refused; no request row; other scopes and drafts untouched; refused check rolls back),
  `SingleAdminWithdrawalMigrationTest` (V8 data with V3 requests, then V9), `SnapshotCompilerTest` (withdrawn version
  absent), `PolicyRegistryIntegrationTest` (403 for viewer, officer, masked and dual sessions; reason checks; snapshot
  drops the scope at once; ledger), `MaskedRoleLeakProbeTest` (seeds one withdrawn and one active scoped version and
  walks the withdrawal route), `policies.test.tsx` (withdraw, refusal, no button for viewer, officer, masked).
- Second review (Argon, `docs/reviews/PR30_2026_10_31_ARGON_SINGLE_ADMIN_WITHDRAWAL.md`, MERGE WITH CORRECTIONS),
  answered in `docs/reviews/PR30_2026_10_31_RESPONSE.md`: D-01 (drafts of the withdrawn scope superseded; the guard
  supersedes a pending draft only for a newer draft of its own mode and scope, a withdrawal of it in the same
  transaction or a retirement) and D-02 (the masked role reads the withdrawal reason withheld).

## Held (pseudonym registry, Q-44)

The B3 pseudonym registry is built on branch `feature/pseudonym-registry` (V10) and not merged: with the frozen
4-hex class tokens a kind holds 65 536 tokens per key, and `NUM-` (every run of six or more digits) can fill it at bank
scale, after which masked pages fail closed (503). Per the PO's rule of 2026-10-31 (prove the product end to end first,
decide governance details at go-live), the token width is decided at go-live; until then the 4-hex tokens may collide
(no leak, an auditor may see two values share a token).

## Not done

ICAP engine, later slices: decompression and base64 layers, the file pipeline, login-step tenant rules, flow shape
fingerprints (`docs/operations/LOCAL_RUN.md` lists them). Slice 2 of the data plane (pull
request 14) added the signed snapshot pull, Secure ICAP with a required client certificate, per-identity and pod-wide
admission, the body budget, the drain window, the verdict spool with backpressure and fixed-label metrics.
Every UNVERIFIED mark (phase 0 measures them); the prerequisite neXus PR (phase 1, needs the PO's go); vendoring of the
neXus delivery scripts (`tools/delivery/VENDORED_FROM_NEXUS.md`); Semgrep TypeScript rules for `frontend/`; control plane
later slices (mTLS on 8091 and 8092, SAML, policy exceptions with expiry for non-fail-closed rules, a server-side user
settings store for the UI language, the
ratified decision record that mirrors the seed fixture, the C4 raw capture and its grants, the Incidents, Identities
and roles and Administration screens, a browser-level (Playwright) masked-role leak probe on top of the API-level one,
the cluster PostgreSQL Job); the Jazzer targets for the LLM-gateway HTTP decoder and the SSE parser (they arrive with
them); Trivy image scanning and SBOM (with the first image, ship pipeline). SIEM export, later: a
client certificate towards the SIEM, the raw-access SIEM copy (with raw access), and one QRadar test event per format to
clear the LEEF UNVERIFIED marks (capture deletions reach the SIEM as exported ledger rows: "Done (redacted capture)").

## Next (ROADMAP phase 0, in this order)

1. Measurements that need the PO or the proxy team, each recorded masked where ROADMAP phase 0 names: ProxySG access-log
   shapes for the AI category and for uncategorised domains (Q-30), ProxySG capability record (Secure ICAP, max object
   size, Preview), SSL-interception bypass audit, vendor header verification on a lab client, login-flow frame fixtures
   (synthetic bodies), per-client trust matrix, Broadcom support case (Q-20), corporate contract facts incl. the art. 9
   instrument per vendor (Q-33), directory attribute for the HR acknowledgement (Q-35).
2. Phase 1 starts only after the PO's go and the Q-13 decision (neXus ingress PR).

Operating model from here: the High tier (Opus) orchestrates with subagents on the lighter tiers
(`docs/reference/MODEL_TIER_MAP.md`); the architect tier returns only for a new ADR or a decision-record amendment.
