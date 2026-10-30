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
- Scoped policy control (PO decisions Q-39 and Q-40, branch `feature/scoped-policy-control`): migration V3 gives every
  rule version a scope (`ANY` or 1 to 32 directory groups; one active version per rule, mode and scope), retires the
  percentage stages for new versions, adds the platform `retired` status (one `security_admin` with a reason, ledgered,
  never deleted, back only through a new two-approval version) and stores the scoped-rule ids of verdict events. The
  compiler emits snapshot format 2 (`scopedRules`, always present); the data-plane side is a separate lane. The masked
  role sees group names only as `GRP-` pseudonyms. Policies shows a scope column and a scope picker instead of the
  rollout bar; Platforms has the retire action with a reason and a built-in confirmation step. After the second review
  (`docs/reviews/PR21_2026_10_30_RESPONSE.md`): group names use the shared `java/policy` `GroupNames` normal form
  everywhere (API, database check, compiler, masked pseudonyms, UI duplicate check); a retirement supersedes the
  platform's pending drafts; an active group-scoped version can be withdrawn with a reason and two approvals (Q-41,
  status `withdrawn`, its groups fall back to `ANY`); drafts for different scopes wait side by side; verdict events
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
  client the probe enumerates); the layer 4 name dictionary and customer numbers (not implemented, so names are seeded
  only where pseudonymisation applies or where ingestion refuses them); third-party loggers below their production
  levels.

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
  link, retention days) come from `RWSAFE_ENDUSER_*` environment values, never committed. Seven wording items carry
  `LEGAL-REVIEW LR-1..7` for the PO and the data protection officer (`docs/i18n/README.md`).
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
  PO-Q3 taken as recommended (`PR22_2026_10_31_RESPONSE.md`); catalogue `tr-2`; the LR markers stay for the PO and the
  data protection officer.
- Open: the banner and IDE first-run surfaces that show the notice and post the acknowledgement, the directory import
  job, the `RWSAFE_ENDUSER_*` ConfigMap contract in `deploy/rwsafe/contracts`, a call site for the coaching page, and
  the data plane reasons `PLATFORM_NOT_ALLOWED`, `VENDOR_INSTRUMENT_MISSING` and `PERSONAL_ACCOUNT` (their pages exist).

## Not done

ICAP engine, later slices: decompression and base64 layers, the file pipeline, login-step tenant rules, flow shape
fingerprints (`docs/operations/LOCAL_RUN.md` lists them). Slice 2 of the data plane (pull
request 14) added the signed snapshot pull, Secure ICAP with a required client certificate, per-identity and pod-wide
admission, the body budget, the drain window, the verdict spool with backpressure and fixed-label metrics.
Every UNVERIFIED mark (phase 0 measures them); the prerequisite neXus PR (phase 1, needs the PO's go); vendoring of the
neXus delivery scripts (`tools/delivery/VENDORED_FROM_NEXUS.md`); Semgrep TypeScript rules for `frontend/`; control plane
later slices (mTLS on 8091 and 8092, SAML, policy exceptions with expiry for non-fail-closed rules, the PO's
confirmation of the orchestrator's Q-41 decision (withdrawal of a group scope under two approvals), a server-side user
settings store for the UI language, the
ratified decision record that mirrors the seed fixture, C3 capture store, the Incidents, Identities and roles and
Administration screens, a browser-level (Playwright) masked-role leak probe on top of the API-level one, the cluster PostgreSQL Job); the
Jazzer targets for the LLM-gateway HTTP decoder and the SSE parser (they arrive with them); Trivy image scanning and SBOM (with
the first image, ship pipeline). SIEM export, later: the Deployment's environment and volume wiring with the NetworkPolicy
egress to the SIEM (deploy lane), the 9400 metrics listener, a client certificate towards the SIEM, deletion events
(ADR-009 §4, with the retention job), the raw-access SIEM copy (with raw access), and one QRadar test event per format to
clear the LEEF UNVERIFIED marks.

## Next (ROADMAP phase 0, in this order)

1. Measurements that need the PO or the proxy team, each recorded masked where ROADMAP phase 0 names: ProxySG access-log
   shapes for the AI category and for uncategorised domains (Q-30), ProxySG capability record (Secure ICAP, max object
   size, Preview), SSL-interception bypass audit, vendor header verification on a lab client, login-flow frame fixtures
   (synthetic bodies), per-client trust matrix, Broadcom support case (Q-20), corporate contract facts incl. the art. 9
   instrument per vendor (Q-33), directory attribute for the HR acknowledgement (Q-35).
2. Phase 1 starts only after the PO's go and the Q-13 decision (neXus ingress PR).

Operating model from here: the High tier (Opus) orchestrates with subagents on the lighter tiers
(`docs/reference/MODEL_TIER_MAP.md`); the architect tier returns only for a new ADR or a decision-record amendment.
