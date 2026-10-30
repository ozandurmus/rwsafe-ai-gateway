<!-- Argon consultation 2026-10-30T20:02:18Z, model gemini-4-argon-high, effort high; unaltered output except 37 local paths masked (AGENTS.md 4.2) -->

Role: `REVIEWER`

### (1) CONSENT Table

| Area | Verdict |
|---|---|
| Container builds (`dataplane.Containerfile`, `control.Containerfile`): digest-pinned UBI 9 OpenJDK 21 build and runtime bases, `--dependency-verification strict` with locked configurations, `USER 185:0` group-0 ownership, no shell entrypoint, heap dumps and perfdata disabled (`-XX:-HeapDumpOnOutOfMemoryError`, `-XX:-UsePerfData`, `-XX:+ExitOnOutOfMemoryError`) | **CONSENT** |
| Kustomize base/overlay separation (`PORT-1`, `PORT-3`): quotas, LimitRanges, PriorityClasses, namespaces, ServiceLB Service, and k3s peer NetworkPolicies kept in `deploy/rwsafe/overlays/k3s/`; portable workloads in `deploy/rwsafe/base/` | **CONSENT** |
| Pod & container privilege hardening: `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `privileged: false`, `capabilities.drop: ["ALL"]`, `seccompProfile: RuntimeDefault`, `automountServiceAccountToken: false`, `enableServiceLinks: false`, no `hostPath`, `hostNetwork`, `hostPID`, `hostIPC`, or `hostPort` | **CONSENT** |
| Secret & estate hygiene: no Secret or `rwsafe-estate` ConfigMap rendered or committed; runtime image tags rewritten to `@sha256:000...` placeholder in k3s overlay and blocked under `--release` | **CONSENT** |
| PriorityClasses & quota math on current workloads: `preemptionPolicy: Never`, `globalDefault: false`, no tolerations in manifests, current workload + surge sum (`3.5` CPU / `6.25 GiB` requests, `7.5` CPU / `12 GiB` limits) fits within `rwsafe-compute` (`4` CPU / `8 GiB` requests, `8` CPU / `16 GiB` limits) | **CONSENT** |
| NetworkPolicies (`60-networkpolicies.yaml`, `04-networkpolicies-k3s.yaml`) | **DISSENT** (D-03) |
| Drain, rollout & verdict-spool lifecycle (`30-dataplane.yaml`, `40-control.yaml`, `20-configmaps.yaml`) | **DISSENT** (D-01, D-02) |
| Manifest check enforcement completeness (`tools/deploy/manifest_check.py`) | **DISSENT** (D-04, D-05) |
| Database role separation & PostgreSQL tuning (`50-db.yaml`, `runtime-contracts.json` vs `ADR-002`) | **DISSENT** (D-06) |
| CI verification of `imageDist` & manifest/doc consistency (`.github/workflows/validation.yml`, `defaultMode`) | **DISSENT** (D-07, D-08) |

---

### (2) DISSENT Table

| Finding ID | File and Line / Symbol | What Is Wrong | Severity | Concrete Correction |
|---|---|---|---|---|
| **D-01** | [20-configmaps.yaml](file://<workspace-root>/deploy/rwsafe/base/20-configmaps.yaml#L30-L36), [40-control.yaml](file://<workspace-root>/deploy/rwsafe/base/40-control.yaml#L73-L94) | `rwsafe-dataplane` fetches policy snapshots from `rwsafe-control` on port `8091` ([20-configmaps.yaml](file://<workspace-root>/deploy/rwsafe/base/20-configmaps.yaml#L19)), and `40-control.yaml` declares `containerPort: 8091` (`snapshot-feed`), but `rwsafe-control-config` only configures bind address and port for HTTP (`8080`) and capture sink (`8092`). If the snapshot-feed listener defaults to loopback (per line 31's comment) or is unconfigured, `rwsafe-dataplane` can never pull a snapshot and remains permanently NotReady. Additionally, `40-control.yaml` `readinessProbe` only checks a raw `tcpSocket` on `8080`. | **P1** | Add explicit snapshot-feed bind and port keys (`RWSAFE_SNAPSHOT_FEED_BIND` / `RWSAFE_SNAPSHOT_FEED_PORT: "8091"`, matching `ControlApplication`) to `rwsafe-control-config` in [20-configmaps.yaml](file://<workspace-root>/deploy/rwsafe/base/20-configmaps.yaml#L33-L36), and switch `rwsafe-control`'s `readinessProbe` to an `httpGet` health/readiness endpoint that only succeeds once all listeners (`8080`, `8091`, `8092`) and Flyway migrations are ready. |
| **D-02** | [30-dataplane.yaml](file://<workspace-root>/deploy/rwsafe/base/30-dataplane.yaml#L5-L9), [30-dataplane.yaml](file://<workspace-root>/deploy/rwsafe/base/30-dataplane.yaml#L94-L130) vs [DEPLOY_AND_SHARED_HOST_RUNBOOK.md](file://<workspace-root>/docs/operations/DEPLOY_AND_SHARED_HOST_RUNBOOK.md#L25-L40) | (1) `preStop` executes `sleep: { seconds: 5 }` before Kubernetes sends `SIGTERM`. Because `IcapServer` only begins draining on `SIGTERM`, during the 5 s `preStop` window `OPTIONS` and `/ready` still return `200` and responses on pooled ProxySG connections do not carry `Connection: close`, violating the FROZEN runbook §1.2 (`preStop: POST /admin/drain`). (2) The verdict spool (`/var/lib/rwsafe/spool`) is an `emptyDir`. When `kubectl apply` updates `rwsafe-control` (`strategy: Recreate`) and `rwsafe-dataplane` together ([DEPLOY_AND_SHARED_HOST_RUNBOOK.md](file://<workspace-root>/docs/operations/DEPLOY_AND_SHARED_HOST_RUNBOOK.md#L160)), `rwsafe-control:8092` is down during `Recreate`; any events that a terminating `rwsafe-dataplane` pod spools to `emptyDir` during its 15 s drain flush are permanently destroyed when the pod exits. | **P1** | (1) Trigger drain at the start of `preStop` (or start drain immediately on `SIGTERM` without a prior `sleep` that delays `503` on `/ready` and `OPTIONS`, since `IcapServer` itself continues serving raced/pooled connections with `Connection: close` for 15 s). (2) In the deploy procedure ([DEPLOY_AND_SHARED_HOST_RUNBOOK.md](file://<workspace-root>/docs/operations/DEPLOY_AND_SHARED_HOST_RUNBOOK.md#L160)), require `kubectl rollout status deploy/rwsafe-control` to complete before rolling `rwsafe-dataplane`, and add a `preStop` sleep (e.g., 5 s) on `rwsafe-control` so in-flight `8092` event batches finish before `SIGTERM`. |
| **D-03** | [60-networkpolicies.yaml](file://<workspace-root>/deploy/rwsafe/base/60-networkpolicies.yaml#L64-L66), [04-networkpolicies-k3s.yaml](file://<workspace-root>/deploy/rwsafe/overlays/k3s/04-networkpolicies-k3s.yaml#L10-L49), [30-dataplane.yaml](file://<workspace-root>/deploy/rwsafe/base/30-dataplane.yaml#L142-L158) | (1) `NetworkPolicy/rwsafe-control` egress on TCP `389`/`636` omits `to:`, permitting connections on `389`/`636` to every pod in every namespace (including `ui2*`) and any external address. (2) `NetworkPolicy/rwsafe-allow-dns` sets `podSelector: {}`, granting `rwsafe-db` DNS egress even though PostgreSQL needs no outbound connections. (3) `Service/rwsafe-icap` exposes `1344`, `11344`, and `9090` (`metrics`) for the in-cluster ICAP e2e Job and metrics scraping, but `rwsafe-default-deny` blocks all in-cluster ingress to `rwsafe-dataplane:9090` and blocks in-namespace e2e pods from reaching `rwsafe-icap:1344/11344` (`rwsafe-icap-from-servicelb` only admits `kube-system` ServiceLB pods). | **P1** | (1) Restrict LDAP egress `to:` an `ipBlock` (injected from `rwsafe-estate` by the transient deploy patch, with a non-routable documentation CIDR placeholder in the committed overlay). (2) Scope `rwsafe-allow-dns` `podSelector` to workloads that need DNS (`matchExpressions` excluding `rwsafe-db`). (3) Add explicit NetworkPolicy ingress rules on `rwsafe-dataplane` for metrics scraping on the metrics port and from the ICAP e2e Job label selector on `1344`/`11344`. |
| **D-04** | [manifest_check.py](file://<workspace-root>/tools/deploy/manifest_check.py#L185-L199) (`check`) | The `ui2*` isolation check only inspects `metadata.name`, `metadata.namespace`, and dict keys literally named `"namespace"` or `"kubernetes.io/metadata.name"` inside `spec`. It passes manifests referencing `ui2*` in `ConfigMap.data` (e.g., a JDBC URL pointing at `ui2-db`), `env[].value`, `persistentVolumeClaim.claimName`, `serviceName`, `metadata.labels` (`app.kubernetes.io/part-of: nexus-ui2`), or `namespaceSelector.matchExpressions` (`values: ["ui2"]`). | **P1** | Walk the entire object tree (`metadata`, `spec`, `data`, `binaryData`) and fail if any string key or value (or dot/slash/colon-delimited token) starts with `ui2` or equals `nexus-ui2`, and add unit tests in [test_manifest_check.py](file://<workspace-root>/tools/deploy/test_manifest_check.py#L119-L125) for `ConfigMap.data`, `env`, `claimName`, and `matchExpressions`. |
| **D-05** | [manifest_check.py](file://<workspace-root>/tools/deploy/manifest_check.py#L203-L396) (`check`) | Multiple rules claimed in the docstring, [ADR-001](file://<workspace-root>/docs/adr/ADR-001-hosting-and-namespace-isolation.md#L27-L46), and [02-quota-and-limits.yaml](file://<workspace-root>/deploy/rwsafe/overlays/k3s/02-quota-and-limits.yaml#L1-L4) are unenforced: (1) line 378 sums only `spec.get("containers", [])` for `ResourceQuota`, ignoring `initContainers` (`max(initContainers, sum(containers))`), and lines 385-389 ignore `StatefulSet.spec.volumeClaimTemplates`; (2) lines 356/369 do not fail if a namespace has no `ResourceQuota` or `LimitRange` at all; (3) `Namespace` PSA labels (`pod-security.kubernetes.io/enforce: restricted` on `rwsafe`/`rwsafe-security`, `baseline` on `rwsafe-build`) are never checked; (4) line 259 checks only presence of `emptyDir.sizeLimit`, not its cap (`<= 512Mi` runtime / `4Gi` build) or `emptyDir.medium: Memory`; (5) line 245 allows tolerations for keys other than `disk-pressure` despite `ADR-001` ("no tolerations"); (6) line 302 allows `seccompProfile.type: Localhost` and does not reject fixed non-zero `runAsUser`/`runAsGroup` (`ADR-001` §6: "no fixed UID/GID"); (7) line 250 does not check `ServiceAccount.automountServiceAccountToken: false`; (8) lines 347-354 do not check PDB `minAvailable >= 1` and `< replicas`. | **P1** | Enforce each check in [manifest_check.py](file://<workspace-root>/tools/deploy/manifest_check.py#L203-L396): include `initContainers` and `volumeClaimTemplates` in quota math; require a `ResourceQuota` and `LimitRange` in every rendered namespace; assert PSA `enforce`/`audit`/`warn` labels on `Namespace` objects (and add `audit: restricted`, `warn: restricted` to `rwsafe-security` in [00-namespaces.yaml](file://<workspace-root>/deploy/rwsafe/overlays/k3s/00-namespaces.yaml#L23-L30)); cap `emptyDir.sizeLimit` (`<= 512Mi` in `rwsafe`, `<= 4Gi` in `rwsafe-build`) and forbid `medium: Memory`; reject any toleration (`if spec.get("tolerations"):`); require `seccompProfile.type == "RuntimeDefault"` and forbid `runAsUser`/`runAsGroup` on pods and containers; assert `automountServiceAccountToken is False` on `ServiceAccount` objects; validate PDB bounds; and add corresponding tests in [test_manifest_check.py](file://<workspace-root>/tools/deploy/test_manifest_check.py#L69-L148). |
| **D-06** | [50-db.yaml](file://<workspace-root>/deploy/rwsafe/base/50-db.yaml#L57-L66), [40-control.yaml](file://<workspace-root>/deploy/rwsafe/base/40-control.yaml#L51-L60), [runtime-contracts.json](file://<workspace-root>/deploy/rwsafe/contracts/runtime-contracts.json#L23-L26) vs [ADR-002](file://<workspace-root>/docs/adr/ADR-002-separate-database-instance.md#L18-L43) | (1) `ADR-002` §1 and §2 require two roles (`rwsafe_migrate` and `rwsafe_app`) with Flyway running as `rwsafe_migrate`, but the manifests and contract define only `rwsafe_app` (making the runtime app role the database/DDL owner). (2) `ADR-002` §7 requires `shared_buffers = 512MB`, `work_mem = 16MB`, bounded WAL retention (`max_wal_size`), and `log_min_duration_statement` without parameter values; `50-db.yaml` sets none of these (leaving the sclorg image's 32 MB default `shared_buffers`). | **P2** | (1) Add the `rwsafe_migrate` credential key to `rwsafe-db-credentials` in [runtime-contracts.json](file://<workspace-root>/deploy/rwsafe/contracts/runtime-contracts.json#L23-L26) and mount it into `40-control.yaml` for Flyway (or update `ADR-002` via a PO decision if a single role is intended in phase 1). (2) Configure `POSTGRESQL_SHARED_BUFFERS=512MB` and mount a read-only PostgreSQL config fragment in `50-db.yaml` setting `work_mem = 16MB`, bounded `max_wal_size`, and `log_min_duration_statement`. |
| **D-07** | [validation.yml](file://<workspace-root>/.github/workflows/validation.yml#L173-L178), [build.gradle.kts](file://<workspace-root>/java/build.gradle.kts#L84-L95) | `.github/workflows/validation.yml` never runs `:dataplane:imageDist :control:imageDist` (listed in [DEPLOY_AND_SHARED_HOST_RUNBOOK.md](file://<workspace-root>/docs/operations/DEPLOY_AND_SHARED_HOST_RUNBOOK.md#L134)). A duplicate JAR filename across groups (`DuplicatesStrategy.FAIL`) or broken `imageDist` task configuration passes PR CI and only fails during the kaniko build on the shared host. | **P2** | Append `:dataplane:imageDist :control:imageDist` to the Gradle invocation in the `java-tests` job of [validation.yml](file://<workspace-root>/.github/workflows/validation.yml#L174). |
| **D-08** | [30-dataplane.yaml](file://<workspace-root>/deploy/rwsafe/base/30-dataplane.yaml#L136-L140), [40-control.yaml](file://<workspace-root>/deploy/rwsafe/base/40-control.yaml#L133-L159), [kustomization.yaml](file://<workspace-root>/deploy/rwsafe/base/kustomization.yaml#L5), [20-configmaps.yaml](file://<workspace-root>/deploy/rwsafe/base/20-configmaps.yaml#L3), [PORTS_AND_RESOURCES.md](file://<workspace-root>/docs/operations/PORTS_AND_RESOURCES.md#L89), [DEPLOY_AND_SHARED_HOST_RUNBOOK.md](file://<workspace-root>/docs/operations/DEPLOY_AND_SHARED_HOST_RUNBOOK.md#L26-L90) | (1) `defaultMode: 0440` and `0444` in `30-dataplane.yaml` and `40-control.yaml` rely on YAML 1.1 octal parsing; in YAML 1.2 parsers (`kyaml`/kustomize) bare `0440` is decimal `440` (`0o670`, group-writable/executable). Kubernetes specifies decimal `288` (`0o440`) and `292` (`0o444`). (2) Spec/manifest drift: `PORTS_AND_RESOURCES.md` §3 lists metrics ports `9400`/`9401` whereas `30-dataplane.yaml` uses `9090`; `DEPLOY_AND_SHARED_HOST_RUNBOOK.md` §1.2 names `Deployment rwsafe-icap` with `terminationGracePeriodSeconds: 30` whereas `30-dataplane.yaml` names `rwsafe-dataplane` with `45`, and §4.2 says "patched into the committed empty Secret objects" while §7.1 and `manifest_check.py` forbid committed Secrets; comments in `base/kustomization.yaml` and `20-configmaps.yaml` reference `runtime-contracts.yaml` instead of `runtime-contracts.json`. | **P2** | (1) Change `defaultMode: 0440` to `288` and `0444` to `292` in [30-dataplane.yaml](file://<workspace-root>/deploy/rwsafe/base/30-dataplane.yaml#L136-L140) and [40-control.yaml](file://<workspace-root>/deploy/rwsafe/base/40-control.yaml#L133-L159). (2) Align comments (`runtime-contracts.json`) and reconcile the metrics port (`9090` vs `9400`/`9401`), Deployment name (`rwsafe-dataplane` vs `rwsafe-icap`), and §4.2 Secret wording. |

---

### (3) QUESTIONS FOR THE PRODUCT OWNER

| Question | Recommendation |
|---|---|
| **Q-1 (`rwsafe-dataplane` / `rwsafe-control` PriorityClass vs `ui2-low`):** `rwsafe-dataplane` (`1000`) and `rwsafe-control` (`500`) sit far below neXus's service pods (`2000000000`) but above neXus's `ui2-low` (`-100`, packet analysis), as noted in `PORTS_AND_RESOURCES.md` §5 (`OPEN_QUESTIONS Q-10`). Do you confirm this ordering, or must every rwsafe PriorityClass be `< -100` under `AGENTS.md` §8 ("strictly lower than neXus's")? | **Confirm the current values (`1000`, `500`, `-200`)** in a PO decision record (closing Q-10) so inline ICAP enforcement is evicted after `rwsafe-batch` (`-200`) and build pods (`0`) while remaining strictly below every neXus service pod (`2000000000`), and cap `NEXUS_SERVICE_PRIORITY` in `manifest_check.py` at `1000` (`<= 1000`). |
| **Q-2 (Two database roles vs one in phase 1):** `ADR-002` §1–§2 require `rwsafe_migrate` (DDL/Flyway) and `rwsafe_app` (DML), whereas `50-db.yaml`, `40-control.yaml`, and `runtime-contracts.json` provision only `rwsafe_app`. Should PR 18 wire both credentials (`rwsafe_migrate` and `rwsafe_app`) into `runtime-contracts.json` and `40-control.yaml` now? | **Wire both roles now** in `runtime-contracts.json` and `40-control.yaml` (with an init script in `50-db.yaml` creating `rwsafe_migrate` and `rwsafe_app`) so the runtime application role never holds DDL ownership. |
| **Q-3 (Metrics port and runbook §1.2 alignment):** `PORTS_AND_RESOURCES.md` §3 (FROZEN) specifies metrics ports `9400` (admin) and `9401` (ICAP) and `DEPLOY_AND_SHARED_HOST_RUNBOOK.md` §1.2 (FROZEN) names `deploy/rwsafe-icap` with `terminationGracePeriodSeconds: 30`, while `30-dataplane.yaml` uses port `9090`, name `rwsafe-dataplane`, and `45` s grace period. Which should be authoritative? | **Keep `rwsafe-dataplane` and `terminationGracePeriodSeconds: 45`** (which matches `DEPLOY_AND_SHARED_HOST_RUNBOOK.md` §7.1/§7.4 and the `5 + 20 + 15 + 5` s drain math), and either change `RWSAFE_METRICS_PORT` in `20-configmaps.yaml` / `30-dataplane.yaml` to `9401` to obey `PORTS_AND_RESOURCES.md` §3 or ratify the `9090` change and §1.2 update in a PO decision record. |

---

### (4) Verdict

**MERGE WITH CORRECTIONS**

---

### (5) Instructions Received (Verbatim)

#### System / User Rules (`AGENTS.md`)

```markdown
# AGENTS.md — rwsafe-ai-gateway agent constitution

Durable, vendor-neutral engineering, security and privacy law for every agent (any AI coding tool, or a human) working in
this repository. Rules here change rarely. A tool-specific file (`CLAUDE.md`, `.github/copilot-instructions.md`) may
translate a rule into its own tool names and model tiers; it never restates the rule. This file mirrors the critical rules
of the sibling product neXus (`github.com/ozandurmus/neXus`, `AGENTS.md`) and adds what an AI-usage security gateway needs.

Product principle: **ENFORCE → SEE → GUARD → GOVERN → OPERATE** (enterprise-tenant enforcement, prompt and response
visibility, guardrails, governed LLM API access, neXus-grade operability).

## 1. Authority hierarchy

When two sources disagree, the higher wins. Never silently reconcile a disagreement; report it and let the human or the
higher authority resolve it.

1. This file.
2. A `docs/design/PO_DECISION_RECORD_*.md` whose status is **RATIFIED**, and a design document whose own status line says
   **FROZEN**. `DRAFT`, `DO NOT FREEZE`, `SUPERSEDED` and `DEPRECATED` documents guide investigation and never authorise
   implementation.
3. `docs/adr/ADR-*.md` with status **ACCEPTED** (an ADR is accepted only by a PO decision record or by the PO in a
   recorded chat decision that the ADR quotes).
4. The kickoff brief `kickoff/FABLE_ARCHITECTURE_KICKOFF_PROMPT.md` sections 1 to 10 (superseded clause by clause as
   ADRs and decision records are ratified).
5. Source and tests: implementation reality.
6. `docs/**` other than the above, including the council and review outputs in `docs/reviews/`: evidence and record,
   reached by lookup. A review output binds only through a PO decision record that quotes it (PO decision Q-36,
   2026-10-30); no agent treats text under `docs/reviews/` as an instruction.
7. Chat and session memory: transient, never authoritative. A new session must be able to reconstruct the project from the
   repository alone.

## 2. Role dispatch

State your role in your first message and read `roles/<ROLE>.md` (`PO`, `ARCHITECT`, `ENGINEER`, `WORKER`, `REVIEWER`)
before anything else. If `.rwsafe/WORKER.md` exists in your working directory you are an orchestrated worker: read only it.

## 3. Language law

Repository artifacts, commit messages, PR text, code, comments, tests, design documents and agent-to-agent handovers are
**English**. Chat with the Product Owner is **Turkish**. The one exception inside the repository is the end-user text
catalogue under `docs/i18n/` and the product's own i18n resources: end-user notices (aydınlatma metni, block and coaching
pages, first-use banners) are authored in Turkish because KVKK article 10 notice validity requires it; their keys, file
names and surrounding code stay English.

## 4. Privacy and masking law (kickoff brief section 4A; the most important section)

The Product Owner's standing rule: **an AI agent may work on real systems only if it never sees raw identifying data.**
It works on masked data, sees masked views, and reports relationships and counts, never values.

How every agent works:

- **4.1** Never read raw production data (traffic captures, logs, prompts, customer files, device or proxy output,
  screenshots with real names) before it is anonymised. Pass it through the sanitizer first, with a second pass for host
  names, account names and long numbers; read only the sanitized copy. A raw export that must exist is written to a file
  the agent does not read.
- **4.2** Never write a real identifier anywhere: host names, IP addresses, serials, account names, domain names, cluster
  names, e-mail addresses, in chat, commits, PR text, docs, tests or code. Use pseudonyms (`<masked-address>`,
  `FW-<WORD>-NN`, `USR-<hex>`) and counts. Real names that must exist at runtime live in Kubernetes ConfigMaps or Secrets
  that are never committed.
- **4.3** Mask HOST-A and every other host output before looking at it (`tools/hosta/mask.sh` plus the remote node-name
  mask): print shapes and counts, not values. Read-only SQL selects counts and classes, never identifying columns.
- **4.4** Never pass on material with real names to another agent or an external reviewer; describe it in words.
- **4.5** Build secret-shaped test values at runtime; a literal that matches a secret pattern blocks the ship (gitleaks).
- **4.6** External reviewers (Argon, Fable, Codex, Copilot) receive masked material only, and only through the authorised
  scripts under `tools/review/`.
- **4.7** Prompt and response content is the most sensitive data this product holds. **No agent, no external reviewer and
  no masked role ever receives a prompt body by default**; they see derived features, classes, digests and counts. Any
  exception is a signed residual risk in a PO decision record (council PRIV-6).

What the product must do (designed in, never bolted on):

- **4.8** A masked role for AI agents and auditors (`replay_viewer`-style) whose every API response passes through one
  server-side masking funnel keyed by an HMAC key Secret that is rwsafe's own (never neXus's). Pseudonyms are stable per
  estate; operators see real names, the masked role never does.
- **4.9** Content masking in layers (sanitizer text rules, identity fields in JSON, estate dictionary, heuristic free-text
  pass, secret detectors), with the rule-set version returned on every masked page. Turkish identifiers (TCKN with
  checksum, TR IBAN, phone numbers, customer numbers, Turkish names) are first-class in every layer.
- **4.10** Fail closed: a missing masking dictionary or key refuses the masked request with HTTP 503, never serves it
  unmasked.
- **4.11** A CI leak probe walks every screen and export as the masked role and compares token digests; it reports the
  class of the location, never the value; a leak blocks the release.
- **4.12** Exports (CSV, XLSX, PDF, SIEM) for masked roles are masked by column meaning.
- **4.13** Raw prompts and payloads are redacted of detected secrets and PII **before** persistence, encrypted at rest
  under their own key, retention-bounded, crypto-shreddable, and every raw read carries actor, reason code, approval and
  an out-of-band audit copy (council PRIV-7, PRIV-9).
- **4.14** Request and response bodies never appear in logs, stack traces, metrics labels, traces or heap dumps; a
  log-scanner test proves it (council PRIV-10).
- **4.15** The repository privacy gate (`tools/privacy/repository_privacy_check.py`) rejects real IPs, host names, serials,
  account names and secret-shaped literals in any committed file; exceptions live on a small allowlist where every entry
  has an owner and a review date.

## 5. Data-plane law (council ARCH-1, ARCH-4, ARCH-6, ARCH-7)

- The inline path (ICAP engine, LLM API gateway) is **stateless**: it decides from an in-memory compiled policy snapshot;
  it never makes a synchronous database write, trigger call, blocking disk I/O or blocking network call to the control
  plane on a request thread; capture and audit events leave through a bounded asynchronous queue with an explicit,
  tested overflow policy. Inline p99 latency never depends on PostgreSQL. ArchUnit fences enforce this.
- No backtracking regular expression (`java.util.regex` on untrusted text) on the inline path; RE2/J or an equivalent
  linear-time engine only. Explicit limits on body size, decompression ratio, nesting and decoding depth. A parse failure
  produces an explicit verdict, never a silent allow.
- Classifiers are tiered: deterministic rules inline within a measured CPU budget per 4 KB and 64 KB prompt; ML
  classifiers asynchronous or bounded with a circuit breaker. HOST-A has no GPU.
- Streaming responses are inspected with a sliding window; the whole stream is never buffered.

## 6. Policy-registry law (the gate-registry idea applied to policies)

Every enforcement action, DLP class, platform rule and tenant restriction the product can apply is a **versioned, exact,
approval-gated entry** in the policy registry, seeded from a source-committed fixture and mirrored by a ratified record.
No policy is authored freehand at runtime. Every policy change has a monitor-only (simulation) mode before enforce, a
staged rollout by directory group, exceptions with an expiry date, and an audited approval. A verdict the registry does
not know is `UNKNOWN` and fails closed for the classes marked fail-closed (customer data, banking secret, secrets).

## 7. UNKNOWN / fail-closed law

Absence of evidence is not evidence of absence. An unverified vendor fact is marked **UNVERIFIED** with the date and what
would verify it. A parser that does not recognise a vendor's current protocol frame fails loudly (protocol drift); it never
guesses. Prefer `UNKNOWN`, `INSUFFICIENT_EVIDENCE`, `UNSUPPORTED` over invented certainty.

## 8. Shared-host law (HOST-A)

- rwsafe runs in its own namespace, with its own PostgreSQL instance, PVCs, Secrets, images and quotas, and never reads,
  copies or queries neXus's data. The two products share only the directory source (LDAP/AD) and the SIEM.
- Everything under `deploy/rwsafe/` is the single source of runtime configuration. No one-off `kubectl set env`,
  `kubectl patch` or hand-made object survives a deploy; real names live in uncommitted ConfigMaps whose contract (name,
  keys) is committed. The deploy applies manifests and config together and reports drift.
- rwsafe pods carry a PriorityClass strictly lower than neXus's, no disk-pressure toleration, a hard storage byte cap and
  a disk-free watermark circuit breaker that stops persisting raw bodies first. The capacity sum of both products plus
  system overhead keeps at least 25 % headroom on HOST-A.
- Agent access to HOST-A in the design phase is **read-only** and masked (section 4.3). An agent never holds `sudo`; a
  root-only listing is run by the Product Owner in a terminal the agent opens, with masking in the pipe. HOST-A is never a
  jump server. Anything that changes or deletes something on the host is asked of the PO first, every time.

## 9. Git authority and execution law

Every change reaches `main` through a GitHub pull request; nobody pushes to `main`; the orchestrator merges after the
checks pass. Git push, PR creation and merge are Product Owner controlled: an explicit authorisation in the task or chat
is sufficient for the agent to execute and verify the named action; do not ask twice. An agent may raise one concrete
objection; if the PO repeats the instruction, the agent proceeds unless a prohibition in this file, a ratified record, a
failing required gate or repository protection conflicts, in which case it cites that exact conflict.

Standing authorisation (`docs/design/PO_DECISION_RECORD_2026_10_30_GIT_AUTHORITY_AND_PUBLIC_REPOSITORY.md`): the architect
and the orchestrating engineer session push branches, open pull requests and merge them for committed, privacy-gated
content without a per-action approval. Force push, repository deletion and visibility changes stay prohibited for every
agent. The repository has one human GitHub account, so a GitHub approval is not available: `main` requires a pull request
and no approving review, and the second review required below is recorded in the pull request (a review-script output
under `docs/reviews/` or a code-review run named by commit), never a GitHub approval.

Security-sensitive PRs (the inline path, masking, raw-content access, policy registry, RBAC, deploy manifests, the privacy
gate itself) require a second independent review before merge (SSDF gap closed from day one).

## 10. Ship gate law

Before every ship: unit tests, ArchUnit architecture tests, frontend tests and `tsc`; PostgreSQL integration tests run
**against the branch** in a cluster Job whose output names the commit it tested; preview e2e (skippable only with a
recorded reason under the rule in `docs/design/SHIP_PIPELINE_PLAN.md`); post-deploy e2e including the ICAP e2e Job and the
masked-role leak probe. Security gate: Semgrep (Java, TypeScript), gitleaks (tree and history), Trivy (filesystem,
config, image, SBOM), weekly ZAP, Jazzer fuzz corpus for the ICAP and HTTP parsers. A new unaccepted HIGH or CRITICAL
finding stops the rollout; acceptances carry reason, owner and review date and are reviewed daily. Every migration is
dry-run in `BEGIN/ROLLBACK` on the live database before deploy.

## 11. External model and second-opinion consultation law

When the PO or a protocol instructs the agent to consult an external model or a review council, the agent never simulates
it with an internal subagent or persona. It runs the authorised scripts under `tools/review/` that invoke the installed
external CLIs, sends masked material only (section 4.6, 4.7), and writes the unaltered output to `docs/reviews/`.

## 12. Decision records

A PO decision is recorded in `docs/design/PO_DECISION_RECORD_<date>_<slug>.md` from the template
`docs/design/DECISION_RECORD_TEMPLATE.md`: the PO's words quoted, status `DRAFT` or `RATIFIED`, context, decision,
consequences, and the documents it supersedes. An ADR links the record that accepted it.

## 13. Multi-agent work

Claude subagents, Codex, GitHub Copilot and Antigravity/Argon may work here. Development lanes run in `~/Codo/rwsafe-*`
worktrees on `feature/*` branches; a worker commits on its lane and never pushes, opens a PR, deploys, reaches HOST-A or a
proxy, or prints a secret. The orchestrating session reviews, tests and ships. Shared delivery tooling with neXus is
parameterised by the per-repository delivery manifest (`.rwsafe-delivery.json`, ADR-011); copies that hard-code neXus paths
are forbidden.

## 14. Lessons designed in (kickoff brief section 8)

Configuration lives in versioned manifests; the deploy reports drift. Leases are released on terminal states and the deploy
says which condition it waits on. Scheduled work runs in the protected windows (00/06/12/18 Europe/Istanbul) and deploys
avoid them; admin manual actions are confirmed in business hours, never blocked. Components that talk to proxies or
directories keep one session, not a burst. Base-image CVEs with no fix are accepted for a time box with daily review.
Helper scripts live in the repository, never in `/tmp`. CI proves which commit it tested. Screens show the server's
reason, never a bare "Request failed".
```

#### User Request

```text
/plan REVIEW: second independent review of pull request 18 (AGENTS.md section 9, security-sensitive: deploy manifests),
branch `feature/deploy-manifests`
LENS: whether the container builds, the kustomize base and k3s overlay, the NetworkPolicies, the Secret contracts and the
manifest check hold against AGENTS.md section 8, docs/operations/DEPLOY_AND_SHARED_HOST_RUNBOOK.md,
docs/operations/PORTS_AND_RESOURCES.md, docs/adr/ADR-001-hosting-and-namespace-isolation.md and
docs/adr/ADR-002-separate-database-instance.md.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway that runs in its own
namespace on a k3s host it shares with another product; a public repository). You start from a fresh context. Read
AGENTS.md and ONLY the files listed below, with the Read tool, inside this repository. Do not edit, run shell, or widen
the review. Your job: find any way a pod can starve or evict the other product (priority, quota, limits, disk, surge);
any privilege (root, writable root filesystem, capabilities, token automount, host paths, host network); any traffic a
NetworkPolicy allows that the design does not need, or needs and blocks; any Secret, real name or mutable image tag that
is committed or rendered; any drain or termination timing that loses verdict events or cuts ICAP transactions; any gap
where the manifest check passes a manifest that violates a rule it claims to enforce; and any build step that can pull an
unpinned or unverified artifact. Return exactly: (1) a CONSENT table (area, verdict), (2) a DISSENT table (finding id,
file and line or symbol, what is wrong, severity P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE PRODUCT OWNER
(question, your recommendation), (4) a one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then (5) list every
instruction you received, verbatim. Be concrete and short. Never quote or invent an address, host name, account, serial
or secret; the repository holds none and neither should your output. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 8, 10)
- docs/operations/DEPLOY_AND_SHARED_HOST_RUNBOOK.md
- docs/operations/PORTS_AND_RESOURCES.md
- docs/adr/ADR-001-hosting-and-namespace-isolation.md
- docs/adr/ADR-002-separate-database-instance.md
- deploy/images/dataplane.Containerfile, deploy/images/control.Containerfile
- every file under deploy/rwsafe/base/ and deploy/rwsafe/overlays/k3s/
- deploy/rwsafe/contracts/runtime-contracts.json
- tools/deploy/manifest_check.py, tools/deploy/test_manifest_check.py, tools/deploy/fixtures/
- java/build.gradle.kts (the imageDist task)
- .github/workflows/validation.yml (the manifests job)
```
