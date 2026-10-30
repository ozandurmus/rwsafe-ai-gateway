<!-- Argon consultation 2026-10-30T08:08:22Z, model gemini-4-argon-high, effort high; unaltered output -->

**ROLE:** `REVIEWER` (`SEAT: platform-architecture`)

## 1. CONSENT

| Area | Verdict |
|---|---|
| Two-plane split (`rwsafe-dataplane` Netty image without JDBC/Spring MVC vs. `rwsafe-control`/`rwsafe-worker` Spring Boot image) with ArchUnit fences | **CONSENT** |
| Separate PostgreSQL 16 `StatefulSet` (`rwsafe-db`), separate PVCs, encrypted CAS chunk storage off-DB, and crypto-shredding deletion receipts | **CONSENT** |
| Kustomize `base/` + `overlays/{k3s,openshift}` layout reconciling `PORT-1`/`PORT-3` with k3s namespace isolation | **CONSENT** |
| PriorityClass hierarchy (`1000` / `500` / `-200`, `preemptionPolicy: Never`), zero `disk-pressure` tolerations, and 75% / 85% disk-free watermark circuit breaker | **CONSENT** (subject to `PLAT-F5` and `PLAT-F7`) |
| Routing Admin UI and LLM API Gateway over HTTPS 443 via Traefik host-based Ingress (`rwsafe.<corp-domain>`, `ai-api.<corp-domain>`) with application-emitted security headers | **CONSENT** (subject to `PLAT-F8`) |
| Parameterised delivery manifest (`.rwsafe-delivery.json`), protected-window avoidance, and weekly registry garbage collection | **CONSENT** (subject to `PLAT-F9`) |
| Self-observability metrics/OTLP traces with zero raw identity/prompt labels and log-scanner e2e verification | **CONSENT** |

---

## 2. DISSENT

| Finding ID | Document and Section | What Is Wrong | Concrete Correction |
|---|---|---|---|
| **PLAT-F1** | `ICAP_AND_STREAMING_PROTOCOL_SPEC.md` §3 (lines 39 vs. 41); `PORTS_AND_RESOURCES.md` §4.3 (line 133) | **Self-deadlock & heap OOM in `rwsafe-icap`:** §3 sets `MAX_REQMOD_BODY = 4 MiB` (full body held in memory before `REQMOD` verdict), while setting Netty `maxInFlightBytesPerConnection = 1 MiB` ("a connection over its cap is paused via TCP backpressure"). Any `REQMOD` request > 1 MiB pauses its own socket at 1 MiB while waiting for the remaining up-to-3 MiB to arrive, deadlocking until the 2 s timeout. Furthermore, `PORTS_AND_RESOURCES.md` trims the `rwsafe-icap` pod limit to `1.5 GiB` while allowing `512 MiB` direct memory and `1 000` in-flight transactions (~700 MiB heap left for UTF-16 normalised strings and JSON trees). | 1. Set `maxInFlightBytesPerConnection >= MAX_REQMOD_BODY + 64 KiB` (`4.1 MiB`) for `REQMOD`, or stream `REQMOD` bodies through incremental chunk normalisers/matchers when `Preview` returns `204`.<br>2. Add a pod-wide semaphore capping concurrent full-body `REQMOD` heap buffers at `256 MiB` total (returning `ICAP 503` above cap) and raise `rwsafe-icap` memory limit to `2 GiB` (within the `16 GiB` quota by setting `rwsafe-worker` limit to `2 GiB`). |
| **PLAT-F2** | `deploy/rwsafe/overlays/k3s/03-icap-service-lb.yaml`; `ICAP_AND_STREAMING_PROTOCOL_SPEC.md` §2; `PORTS_AND_RESOURCES.md` §4.2 | **k3s ServiceLB (`klipper-lb`) MASQUERADE breaks engine IP allowlist:** `03-icap-service-lb.yaml` claims `externalTrafficPolicy: Local` preserves ProxySG's source IP through ServiceLB. In k3s, `svclb-*` pods forward to the Service IP using `iptables -t nat -A POSTROUTING -j MASQUERADE`, replacing the packet's source IP with the `svclb` CNI pod IP. Because `ICAP_AND_STREAMING_PROTOCOL_SPEC.md` §2 mandates that the engine and `NetworkPolicy` reject any TCP source IP not in the ProxySG address list, 100% of connections via `svclb` will be dropped. | Either: (a) Enforce the ProxySG source-IP allowlist in host `nftables` (`@icap_clients` in `HARDENING_EXCEPTIONS.md`, which runs before `svclb` NAT) plus mTLS client-certificate pinning on `11344`, and allow `kube-system` `svclb-rwsafe-icap-lb-*` pods in `NetworkPolicy` and the engine's plain-ICAP source check; or (b) Expose `1344`/`11344` via a `NodePort` Service (`externalTrafficPolicy: Local`) with an `nftables` prerouting redirect from `1344`/`11344` to the fixed `NodePort` (bypassing `klipper-lb` MASQUERADE so `kube-proxy` preserves the real ProxySG IP). |
| **PLAT-F3** | `ICAP_AND_STREAMING_PROTOCOL_SPEC.md` §7; `DEPLOY_AND_SHARED_HOST_RUNBOOK.md` §1.2 | **Graceful drain race causes `503` drops during rollout:** §7 states that on `preStop`, "no new transactions are accepted (new connections are closed after `ICAP/1.0 503`)". Because `kube-proxy` endpoint removal takes 0.5–2 s and ProxySG polls `OPTIONS` every 5 s, ProxySG will send new transactions on idle pooled connections and newly opened connections during the first 1–5 s of `preStop`. Returning `503` immediately causes ProxySG to trigger its `REQMOD` fail-closed policy and breaks the `AC-2` zero-drop test. | During the first 15 s of the 20 s `preStop` window: answer `OPTIONS` (and readiness probe) with `503` immediately, **but continue serving** `REQMOD`/`RESPMOD` transactions that arrive on existing pooled or raced connections, adding `Connection: close` to every ICAP response so each pooled connection closes cleanly after completing its transaction. Only refuse transactions after the drain window expires. |
| **PLAT-F4** | `ICAP_AND_STREAMING_PROTOCOL_SPEC.md` §4.4 (lines 115–129) and §6 (line 162) | **Three protocol bugs in `RESPMOD` SSE streaming:**<br>1. §6 sets ProxySG's `RESPMOD` transaction timeout to `30 s`, whereas §4.4 notes coding-agent SSE streams last `30–120 s`; ProxySG will abort every long coding-agent response at 30 s.<br>2. Line 128 says `RESPMOD` returns `204` when nothing changed, but RFC 3507 §4.5 forbids `204` once `100 Continue` has been sent.<br>3. Lines 119–123 state "forward the chunk to ProxySG unchanged" before "on a HIGH-CONFIDENCE hit: ABORT the stream", which leaks the offending chunk before terminating, and does not account for `Content-Encoding: gzip/br` when injecting an SSE error frame. | 1. Increase ProxySG's `RESPMOD` transaction timeout for the AI streaming service to `300 s` (with a `30 s` inter-chunk idle timeout in `rwsafe-icap`).<br>2. Clarify in §4.4 that `204` is returned only during `Preview` (e.g., `ieof` ≤ 64 KiB); once `100 Continue` is sent, the response is always `ICAP 200 OK` streamed.<br>3. Inspect each 16 KiB window **before** forwarding the chunk; on hit, drop the offending chunk, emit the SSE termination event (re-compressed if `Content-Encoding` is active, or strip `Accept-Encoding` on `REQMOD` for SSE endpoints), and send `0\r\n\r\n`. |
| **PLAT-F5** | `CAPACITY_AND_SLO_MODEL.md` §4 (line 81) vs. `ICAP_AND_STREAMING_PROTOCOL_SPEC.md` §3 (line 39) & `ADR-010` §2 | **Silent middle-body bypass above 256 KB:** `CAPACITY_AND_SLO_MODEL.md` §4 line 81 states "above 256 KB inspection samples head, tail and structured fields and records `PARTIAL_INSPECTION`", whereas `ICAP_AND_STREAMING_PROTOCOL_SPEC.md` §3 inspects up to `4 MiB` and coding-agent prompts average 60 KB with p99 `1 MB`. Skipping the middle of any prompt > 256 KB allows trivial DLP bypass by padding 130 KB before and after sensitive data, and `ADR-010` §2 has no rule for `PARTIAL_INSPECTION`. | Remove head/tail-only sampling below `MAX_REQMOD_BODY` (`4 MiB`): at the stated linear-time budget (`12 CPU-ms` per `64 KiB`), a `1 MiB` coding-agent body takes ~192 ms (well within the `2 000 ms` `REQMOD` timeout), and content-addressed chunk caching (`CAS` digest lookup of clean 16 KiB chunks in memory) skips re-scanning unchanged repo context across turns. Add `PARTIAL_INSPECTION` to `ADR-010` §2 as **block** for fail-closed classes if any decoding depth/size limit is hit. |
| **PLAT-F6** | `deploy/rwsafe/overlays/k3s/02-quota-and-limits.yaml`; `00-namespaces.yaml`; `ADR-001` §3; `PORTS_AND_RESOURCES.md` §3 | **Manifest & Quota mismatches in `overlays/k3s/`:**<br>1. `02-quota-and-limits.yaml` sets `services.loadbalancers: "1"`, which is consumed by `rwsafe-icap-lb`; adding the SNMP `LoadBalancer` Service (`1161/udp`, H-3) or forward proxy (`3128/tcp`, H-9) in `PORTS_AND_RESOURCES.md` §3 will fail quota admission.<br>2. `02-quota-and-limits.yaml` defines `ResourceQuota` and `LimitRange` only for `rwsafe`, leaving `rwsafe-build` and `rwsafe-security` unbounded.<br>3. `ADR-001` §3 and `HARDENING_EXCEPTIONS.md` state PSA `restricted` on all three namespaces, but `00-namespaces.yaml` line 20 sets `enforce: baseline` on `rwsafe-build`.<br>4. `emptyDir` scratch volumes are not capped by `requests.storage` in `ResourceQuota`. | 1. Set `services.loadbalancers: "2"` (or `"3"`) in `rwsafe-compute`.<br>2. Add `ResourceQuota` and `LimitRange` objects for `rwsafe-build` and `rwsafe-security` in `02-quota-and-limits.yaml` and require `priorityClassName: rwsafe-batch` on all Jobs.<br>3. Align `ADR-001` §3 and `HARDENING_EXCEPTIONS.md` with `00-namespaces.yaml` (`restricted` on `rwsafe` and `rwsafe-security`, `baseline` on `rwsafe-build` for kaniko).<br>4. Require explicit `emptyDir.sizeLimit` (`512Mi` on runtime pods, `4Gi` on build pods) enforced by the manifest test. |
| **PLAT-F7** | `ADR-001` §3; `CAPACITY_AND_SLO_MODEL.md` §2; `ARCHITECTURE.md` §2 | **Kubelet summary API requires cluster-scoped RBAC not portable to OpenShift:** `rwsafe-control` enables `automountServiceAccountToken: true` and requires a `ClusterRole` (`nodes/proxy` or `nodes/stats`) to read node disk usage from the kubelet summary API. `nodes/proxy` is a privilege escalation risk and is forbidden to tenant projects on OpenShift (`PORT-3`). | Read filesystem usage directly via `java.nio.file.FileStore` (`statvfs`) on the mounted `rwsafe-capture-store` PVC path inside `rwsafe-control`. On `HOST-A` (`local-path`), `statvfs` reports the exact root LVM filesystem usage; on OpenShift, it reports the exact PVC usage. Set `automountServiceAccountToken: false` on **all** `rwsafe` pods including `rwsafe-control`. |
| **PLAT-F8** | `ADR-003` (§3 and `deploy/ui2/60-ingress.yaml` diff); `deploy/rwsafe/overlays/k3s/kustomization.yaml` | **Unnecessary 404 backend pod & unstated ConfigMap host-injection mechanic:**<br>1. `ADR-003` §3 proposes a new static 404 `Deployment` and `IngressRoute` in `kube-system`. Once the host-less catch-all rule is removed from `deploy/ui2/60-ingress.yaml`, Traefik natively returns `404 Not Found` for any unmatched `Host` header or bare IP without an extra workload.<br>2. `ADR-003` shows `+ - host: nexus.<corp-domain>` in `60-ingress.yaml` and notes the value comes from `ui2-config` at render time, without specifying how `hosta_deploy.sh` / `module_deploy.py` injects uncommitted ConfigMap values into `Ingress` YAML without dirtying the git tree. | 1. Drop the extra 404 `Deployment` in `kube-system`; rely on Traefik's native 404 response when no Ingress `host` rule matches (and verify in the `neXus` PR test that `curl -sk https://127.0.0.1/` returns `404`).<br>2. Specify in `ADR-003` and `DEPLOY_AND_SHARED_HOST_RUNBOOK.md` §2 that `module_deploy.py` / `hosta_deploy.sh` reads `ingress_host*` from the in-cluster ConfigMap and passes a transient kustomize replacement/patch on stdin to `kubectl diff`/`kubectl apply -f -`, never writing real host names to disk. |
| **PLAT-F9** | `ADR-010` §2 (line 37); `ADR-011` §2 (line 26) | **1. Unbounded "never dropped" verdict queue during control-plane outage:** `ADR-010` §2 states the data plane keeps enforcing for up to 24 h when `rwsafe-control` is down and "never drops verdict or audit events" from "a separate, smaller queue". An in-memory queue fills in seconds at 40 req/s.<br>**2. One-sided build lock:** `ADR-011` §2 says until `neXus` adopts `~/.locks/hosta-build.lock`, `rwsafe` polls `ui2-build`. If `neXus` starts a build while `rwsafe` is mid-build, both builds collide on `HOST-A`. | 1. Back the data-plane verdict/audit queue with a bounded ring file on the pod's `emptyDir` (`256 MiB`, holding ~500k compact records written by the async emitter thread, never the Netty request thread); if the `emptyDir` spool reaches 100% during a prolonged control-plane outage, fail closed for fail-closed classes and emit a summary counter.<br>2. Add `flock ~/.locks/hosta-build.lock` to `neXus`'s `tools/delivery/hosta_deploy.sh` in the **same pre-requisite `neXus` PR** that updates line 121 (`ADR-003`). |

---

## 3. QUESTIONS FOR THE PRODUCT OWNER

| # | Question | Recommendation |
|---|---|---|
| **Q1** | Confirm **`rwsafe-dataplane` PriorityClass (`1000`) vs. `neXus` `ui2-low` (`-100`)** (`OPEN_QUESTIONS` Q-10): all `neXus` core services run at `system-cluster-critical` (`2000000000`), while `neXus` packet analysis runs at `ui2-low` (`-100`). Should `rwsafe-dataplane` (`1000`) and `rwsafe-control` (`500`) sit above `ui2-low` so background packet-analysis jobs are evicted before inline AI enforcement, while `rwsafe-batch` (`-200`) sits below `ui2-low`? | **Approve** — keeps every `neXus` core service strictly above `rwsafe` (`2000000000 > 1000`) while protecting inline enterprise AI traffic over background packet-capture jobs. |
| **Q2** | Confirm the **pre-requisite `neXus` PR scope** (`ADR-003` + `ADR-011`): removing the bare-IP catch-all from `deploy/ui2/60-ingress.yaml`, updating `tools/delivery/hosta_deploy.sh` line 121 to send the `Host` header via `--resolve`, and adding the shared `flock ~/.locks/hosta-build.lock` guard in `hosta_deploy.sh` before `rwsafe`'s first host build. | **Approve and ship before Phase 1** — zero-downtime change for `neXus` DNS users, closes the bare-IP catch-all ambiguity, and prevents dual-product build contention from day one. |
| **Q3** | Given that `HOST-A`'s root filesystem is currently **80% used** (above the **75% disk-free watermark** in `CAPACITY_AND_SLO_MODEL.md` §2), do you confirm launching MVP with the circuit breaker active (persisting metadata, verdicts, DLP digests, and redacted text `C3` if below 85%, while skipping raw body `C4` persistence until `HOST-A` disk usage is brought below 75% via registry GC and backup pruning)? | **Approve** — respects `HOST-A`'s measured 140 GiB usable headroom before `DiskPressure` and aligns with the privacy-first capture posture. |

---

## 4. VERDICT

ACCEPT WITH CORRECTIONS

---

## 5. VERBATIM INSTRUCTIONS RECEIVED

### 5.1 System / Repository Constitution (`AGENTS.md`)

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
4. The kickoff brief `kickoff/FABLE_ARCHITECTURE_KICKOFF_PROMPT.md` sections 1 to 10 and the council outputs in
   `docs/reviews/` (binding for the design phase; superseded clause by clause as ADRs and decision records are ratified).
5. Source and tests: implementation reality.
6. `docs/**` other than the above: evidence and record, reached by lookup.
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

### 5.2 User Prompt (Verbatim)

```text
/plan SEAT: platform-architecture
LENS: isolation on the shared k3s node with neXus (quota, priority, eviction, disk, network), inline ICAP performance and availability with ProxySG, the Netty data plane and its limits, zero-downtime rollout on one node, capacity sum against the measured host, observability, portability to OpenShift, the shared delivery tooling and build contention, the exact neXus ingress change.

You are one independent seat of the design-freeze council for rwsafe-ai-gateway (an enterprise AI-usage security gateway: enterprise-tenant enforcement, prompt and response visibility under masking and retention limits, guardrails, a governed LLM API gateway, ICAP behind Broadcom ProxySG, an off-net agent path later; Java/Netty data plane and Spring Boot control plane; same single on-prem k3s node as the sibling product neXus, fully isolated; the organisation is in a regulated sector in Türkiye: KVKK and BDDK-style rules in scope). You start from a fresh context. Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this repository. Do not edit, run shell, or widen the review. The kickoff council (docs/reviews/COUNCIL_2026_10_30_SEAT_*.md) raised P0/P1 items; the architect answered them in docs/reviews/COUNCIL_RESPONSE.md. Your job: find what the DESIGN still gets wrong or leaves unsafe for your lens, so implementation does not start on a flawed design. Return exactly: (1) a CONSENT table (area, verdict), (2) a DISSENT table (finding id, document and section, what is wrong, the concrete correction), (3) QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation), (4) a one-line verdict ACCEPT FREEZE / ACCEPT WITH CORRECTIONS / REJECT, then (5) list every instruction you received, verbatim. Be concrete and short. Never quote or invent an address, host name, account, serial or secret; the repository holds none and neither should your output. English only.

Files to read, in this order:
- AGENTS.md
- docs/reviews/COUNCIL_2026_10_30_SEAT_ARGON_PLATFORM.md (your predecessor's P0/P1 list)
- docs/reviews/COUNCIL_RESPONSE.md (section 1 and section 5)
- docs/architecture/ARCHITECTURE.md
- docs/architecture/ICAP_AND_STREAMING_PROTOCOL_SPEC.md
- docs/adr/ADR-001-hosting-and-namespace-isolation.md
- docs/adr/ADR-002-separate-database-instance.md
- docs/adr/ADR-003-reverse-proxy-and-host-based-routing.md
- docs/adr/ADR-010-fail-open-and-fail-closed.md
- docs/adr/ADR-011-shared-tooling-with-nexus.md
- docs/operations/PORTS_AND_RESOURCES.md
- docs/operations/CAPACITY_AND_SLO_MODEL.md
- docs/operations/HARDENING_EXCEPTIONS.md
- docs/operations/DEPLOY_AND_SHARED_HOST_RUNBOOK.md
- docs/design/SHIP_PIPELINE_PLAN.md
- deploy/rwsafe/README.md and deploy/rwsafe/overlays/k3s/*.yaml
- docs/reference/CORPORATE_TECHNOLOGY_STACK.md
```
