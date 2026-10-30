<!-- Argon consultation 2026-10-30T06:26:52Z, model gemini-4-argon-high, effort high; unaltered output -->

**ROLE:** `REVIEWER` (`SEAT: platform-architecture`)  
**LENS:** Platform, SRE and architecture — isolation on the shared k3s host with neXus, inline ICAP performance and availability with ProxySG, Java runtime choices for the inline path, deploy/blue-green, observability, capacity, portability, multi-agent development workflow and reuse of neXus tooling.

---

## 0. Evaluation of Candidate Additions (Platform & Architecture Lens)

- **Confirm & Sharpen — Failure modes (ICAP health checks, failover, Preview/204, streaming, backpressure, capacity plan):** Confirm as **P0**, but sharpen: must explicitly distinguish `REQMOD` (request buffered/inspected before upstream call) vs. `RESPMOD` on SSE/chunked streams (where full-response buffering breaks LLM time-to-first-token), and mandate how ProxySG connection pooling behaves during pod drain.
- **Confirm & Sharpen — Blue/green for ICAP service so ProxySG never loses its ICAP server during deploys:** Confirm as **P0**, but sharpen for **single-node k3s reality**: if ICAP uses `hostPort: 1344`, Kubernetes cannot schedule a second pod on the same single node (`HOST-A`), making blue/green or `maxSurge: 1` impossible. The brief must forbid `hostPort` for ICAP and require a multi-replica `Service` (`NodePort`/ServiceLB or kube-proxy bound to `1344`) with `RollingUpdate` (`maxUnavailable: 0, maxSurge: 1`).
- **Confirm & Sharpen — Self-observability (metrics, tracing, SLOs):** Confirm as **P1**, but sharpen: metrics/traces must never attach raw prompt/user/tenant strings as high-cardinality or unmasked labels, and must expose JVM GC pause, Netty direct-buffer memory, ICAP queue depth, and Preview `204` fast-path hit ratio.
- **Confirm & Sharpen — Portability (`deploy/ui2/openshift`):** Confirm as **P1**, but flag a **direct contradiction** with Section 4 Rule 1 of the brief: `deploy/ui2/00-namespace.yaml` (`PORT-3`) explicitly forbids `ResourceQuota` and `LimitRange` in the base manifest directory because OpenShift projects pre-provision quotas differently. Fable must isolate stage/platform-specific quota manifests (`deploy/rwsafe/k3s/` vs. `deploy/rwsafe/openshift/`).
- **Confirm & Sharpen — Protocol coverage (HTTP/2, QUIC/HTTP3, WebSocket, gRPC, SSE, file uploads):** Confirm as **P0** for the inline architecture: ProxySG's ICAP implementation historically encapsulates HTTP/1.1 semantics and has strict limits on native WebSocket frame-by-frame ICAP streaming and gRPC trailers. The brief must require Fable to verify exact ProxySG OS (`SGOS`) version capabilities in Phase 0 before committing WebSocket traffic to ICAP vs. the chained proxy/agent.
- **Confirm & Sharpen — Detection engineering (local classifiers only, no cloud API):** Confirm as **P0**, and add a **strict resource ceiling on HOST-A**: running local ML/ONNX/transformer models inside the inline JVM or on `HOST-A` CPU will starve `neXus` unless bounded by CPU quota, model size, and deterministic latency budgets.
- **Confirm & Sharpen — Integration with neXus without coupling & Multi-agent tooling reuse:** Confirm as **P1**, but sharpen: existing `neXus` scripts (`scripts/argon_task.py`, `tools/delivery/hosta_deploy.sh`, `tools/delivery/standalone_orchestrate.py`) hardcode `nexus-*` worktree names, `~/nexus.git`, `/tmp/nexus_build.log`, and `ui2` namespaces. Fable must design parameterized repo-config extraction, not copy-paste scripts that collide on `HOST-A`.

---

## 1. Gaps in the Kickoff Brief (P0 / P1 / P2)

### P0 Gaps (Design will be unsafe, broken, or starve `neXus` without these)

- **P0-1: Hot-Path (Data Plane) vs. Control/Persistence Plane Separation**
  - **What to add:** Require architectural separation between the **inline data plane** (`rwsafe-icap`, `rwsafe-llm-gateway`) and the **control/admin/persistence plane** (`rwsafe-service`, `rwsafe-worker`, `rwsafe-db`). Prohibit synchronous PostgreSQL writes, DB trigger execution, or blocking disk I/O on the inline ICAP/gateway request thread.
  - **Why:** `neXus` (`deploy/ui2/50-service-deployment.yaml`) runs as a single-replica (`replicas: 1`) `Recreate` deployment backed by synchronous Postgres triggers (`audit()`). Applying that pattern to an inline proxy path means every DB lock, Flyway migration, vacuum, or service restart stalls or drops enterprise AI traffic across ProxySG, and every prompt capture pays synchronous transactional + encryption I/O latency inline.
  - **Question Fable must answer:** *How does the inline ICAP/gateway data plane evaluate policies from an in-memory compiled snapshot and hand off captured prompts/audit events asynchronously (e.g., bounded in-memory ring buffer / persistent queue with explicit drop or fail-closed backpressure policy) so inline p99 latency has zero dependency on PostgreSQL availability or transaction latency?*

- **P0-2: Real Node-Level Isolation Beyond `ResourceQuota` (`PriorityClass`, Eviction Order, Disk I/O, and Storage Cap)**
  - **What to add:** Require `rwsafe` workloads to use a dedicated `PriorityClass` strictly lower than `neXus` (`neXus` uses `system-cluster-critical` in `deploy/ui2/40-database-statefulset.yaml` and `50-service-deployment.yaml`), forbid `node.kubernetes.io/disk-pressure` tolerations on `rwsafe` pods, and mandate a hard byte cap (`MAX_STORE_BYTES` + disk-free watermark circuit breaker) on `rwsafe` prompt storage and DB WAL/data growth.
  - **Why:** Kubernetes `ResourceQuota` and `LimitRange` only enforce admission-time CPU/memory declarations; they do **not** isolate disk space, disk IOPS, or kubelet eviction priority. `HOST-A` disk was already ~60% full in Oct 2026 and `neXus` allocates up to 100 GB for Packet Analysis (`deploy/ui2/50-service-deployment.yaml`). Coding agents (`Claude Code`, `Copilot`, `Devin`, `Windsurf`) resend 100k–200k token repo contexts on every turn; unbounded day-one prompt capture will push `HOST-A` past the 85% kubelet `DiskPressure` threshold and evict or degrade `neXus`.
  - **Question Fable must answer:** *What exact `PriorityClass` values, `preemptionPolicy`, PVC size caps, ring-buffer/pruning watermarks, and payload deduplication (e.g., content-addressed storage for repeated system/repo context blocks in coding-agent sessions) prevent `rwsafe` from ever triggering `DiskPressure` or IOPS starvation on `HOST-A`?*

- **P0-3: `neXus` Catch-All Ingress Rule & Health-Check Collision on `HOST-A`**
  - **What to add:** Document that `deploy/ui2/60-ingress.yaml` currently contains a **host-less catch-all rule** (matching any `Host` header and bare IP requests) in addition to `host: ui2.nexus.local`, and that `tools/delivery/hosta_deploy.sh` (line 121) validates `neXus` deployments via `curl -sk https://127.0.0.1/` with no `Host` header.
  - **Why:** Section 2 & 4 assume adding host-based routing (`nexus.<corp-domain>` and `rwsafe.<corp-domain>`) is trivial. If the `neXus` catch-all rule is removed without updating `hosta_deploy.sh` and operator bookmarks, `neXus` deploys will fail health checks; if left in place, Fable must verify Traefik priority/TLS SNI certificate selection so `rwsafe.<corp-domain>` never falls through to `ui2-service` or serves the wrong TLS cert.
  - **Question Fable must answer:** *What is the exact diff to `deploy/ui2/60-ingress.yaml` and `tools/delivery/hosta_deploy.sh`, how are TLS certificates provisioned and bound per SNI host in Traefik, and why is the LLM API gateway not also routed via HTTPS 443 host-based Ingress (e.g. `ai-api.<corp-domain>`) instead of opening a separate custom port?*

- **P0-4: Java ICAP Server Architecture, SSE Streaming Semantics, and Off-Heap/GC Bounds**
  - **What to add:** Require an explicit Java ICAP protocol engine design (Spring Boot has no native RFC 3507 ICAP server), defining the Netty frame decoder, `OPTIONS` / `Preview` / `204 No Modifications` state machine, direct `ByteBuf` memory cap, and streaming `RESPMOD` behavior for SSE (`text/event-stream`).
  - **Why:** If `rwsafe` buffers full `RESPMOD` bodies to run DLP/guardrails on streaming LLM responses, SSE token streaming freezes until completion (30–120s), breaking IDEs and CLIs (`Claude Code`, `Copilot`) and exhausting JVM heap/direct memory under concurrent streams. Conversely, if `RESPMOD` streams chunks immediately, already-flushed chunks cannot be retroactively blocked/redacted.
  - **Question Fable must answer:** *Which Java/Netty stack implements RFC 3507 ICAP, what is the maximum in-flight buffer per connection, and what is the exact `RESPMOD` strategy for SSE/chunked responses (e.g., `REQMOD` full inspection + `RESPMOD` sliding-window chunk inspection with stream-abort on critical leak vs. async post-stream audit)?*

- **P0-5: Single-Node Zero-Downtime ICAP Rollout & ProxySG Connection Drain**
  - **What to add:** Forbid `hostPort` and `strategy: Recreate` on the ICAP/gateway deployments; require `replicas >= 2` with `RollingUpdate` (`maxUnavailable: 0, maxSurge: 1`), `PodDisruptionBudget`, and an explicit ICAP connection-drain lifecycle (`preStop` hook + graceful close of pooled ProxySG TCP connections).
  - **Why:** On a single-node cluster (`HOST-A`), `hostPort: 1344` prevents a second pod from starting during a rollout. Furthermore, ProxySG reuses long-lived pooled TCP connections to ICAP servers; Kubernetes removing a terminating pod from Service `Endpoints` does not close established TCP connections, causing in-flight ICAP transactions to reset when the pod exits.
  - **Question Fable must answer:** *How is port 1344 exposed on `HOST-A` (e.g., k3s ServiceLB / `NodePort` with `externalTrafficPolicy: Local`) so two ICAP pods coexist during rollout, and how does the ICAP server drain persistent ProxySG TCP pools without dropping a single inline request?*

### P1 Gaps (Required to avoid a second design round and operational friction)

- **P1-1: Build Pipeline & Image Registry Contention on `HOST-A`**
  - **What to add:** Require Fable to specify how `rwsafe` builds images (`rwsafe-build` namespace vs. sharing `ui2-build`), how build scheduling avoids `neXus` deploys and protected windows (`00/06/12/18`), and how `registry.kube-system.svc.cluster.local` garbage-collects old layers.
  - **Why:** `neXus` builds run in-cluster via kaniko (`tools/delivery/hosta_deploy.sh`). Concurrent Java/Gradle + React builds for two products on one host will spike CPU/memory/disk I/O and fill the local registry with unreferenced layers.
  - **Question Fable must answer:** *How are in-cluster builds serialized or resource-capped across `neXus` and `rwsafe` (e.g., shared host-level build lock and `ui2-low`-equivalent priority for build pods), and what automated retention/GC policy keeps `registry.kube-system.svc.cluster.local` from filling the disk?*

- **P1-2: OpenShift Portability (`PORT-1`/`PORT-3`) vs. Namespace `ResourceQuota`/`LimitRange`**
  - **What to add:** Reference `neXus`'s `PORT-1`/`PORT-3` contract (`deploy/ui2/00-namespace.yaml`, `deploy/ui2/40-database-statefulset.yaml`, `deploy/ui2/openshift/60-route.yaml`): arbitrary-UID compatibility (`runAsNonRoot: true`, no hardcoded UID/GID/fsGroup), read-only root filesystem (`readOnlyRootFilesystem: true` with `emptyDir` scratch mounts), and separation of k3s-only `Ingress`/`ResourceQuota` objects from portable workload manifests.
  - **Why:** The brief demands `ResourceQuota`/`LimitRange` in Section 4 Rule 1 and OpenShift portability in the candidate additions, without noting that `neXus` enforces strict manifest portability rules (`PORT-1`/`PORT-3`).
  - **Question Fable must answer:** *How is `deploy/rwsafe/` structured so workload manifests remain 100% identical between k3s (`HOST-A`) and OpenShift (arbitrary UID, group-0 writable mounts, `readOnlyRootFilesystem: true`), while k3s-specific `ResourceQuota`, `LimitRange`, and `Ingress` objects live cleanly alongside `openshift/60-route.yaml`?*

- **P1-3: Parameterizing Shared `neXus` Multi-Agent and Delivery Tooling**
  - **What to add:** Require the tooling ADR to audit hard-coded `neXus` assumptions in `scripts/argon_task.py` (rejects worktrees not matching `~/Codo/nexus-*`), `tools/delivery/standalone_orchestrate.py` (hardcodes `ui2/frontend`, `ui2_app`, `nexus-standalone`), and `tools/delivery/hosta_deploy.sh` (hardcodes `~/nexus.git`, `~/run_build.sh`, `/tmp/nexus_build.log`, `ui2` namespace).
  - **Why:** Neither blind vendoring nor unparameterized sharing will work; running `hosta_deploy.sh` or `argon_task.py` for `rwsafe` without isolating host paths (`~/rwsafe.git`, `~/run_rwsafe_build.sh`, `/tmp/rwsafe_build.log`) and worktree prefixes (`~/Codo/rwsafe-*`) will either fail preflight checks or overwrite `neXus` state on `HOST-A`.
  - **Question Fable must answer:** *Which exact parameters (repo slug, worktree prefix, k8s namespace, host bare-repo path, build script/log path, DB pod/role names) are extracted into a per-repo manifest (`.nexus-delivery.json` or equivalent) so `neXus` and `rwsafe` share one delivery/review engine with zero state or `/tmp` file collisions?*

- **P1-4: Classifier/Guardrail Execution Budget on Shared CPU**
  - **What to add:** Specify that all inline guardrails (regex, tokenizers, secret scanners, and any local ML/ONNX prompt-injection classifier) must execute within a strict per-request CPU and memory budget on `HOST-A` (no GPU assumed) with circuit-breaker fallback when CPU saturation occurs.
  - **Why:** "Use the classifiers you find to be standard" (Section 5C) often leads architects to propose local BERT/DeBERTa prompt-injection models (e.g., ProtectAI/Lakera-style local models) that consume 100–300ms of multi-core CPU per call—catastrophic on a shared single-node k3s server without a GPU.
  - **Question Fable must answer:** *What exact classifier tiers run synchronously on the inline path vs. asynchronously out-of-band, and what is the measured CPU-ms per 4 KB / 64 KB prompt on CPU-only `HOST-A` hardware?*

### P2 Gaps (Nice-to-have refinements for Phase 1+)

- **P2-1: Synthetic Canary & Replay Harness for Inline ICAP**
  - **What to add:** Extend the `neXus` post-deploy e2e pattern (`deploy/ui2/70-e2e-job.yaml`) with an in-cluster ICAP client job that replays sanitized `REQMOD`/`RESPMOD` fixtures (tenant block, secret redaction, `204` allow, SSE stream, and masked `aiview` verification) on every deploy.
  - **Why:** Proves both ICAP protocol correctness and `aiview` masking before switching ProxySG traffic or concluding a deploy.
  - **Question Fable must answer:** *How does the post-deploy e2e Job test the ICAP port, LLM gateway, and `aiview` masking end-to-end inside the cluster without touching ProxySG?*

---

## 2. Risks in the Stated Decisions & Mandated Mitigations

| Stated Decision | Platform / SRE / Architecture Risk | Mitigation the Brief Must Demand from Fable |
|---|---|---|
| **1. Hosting on the same single server (`HOST-A`) as `neXus`** | **Shared-kernel / shared-disk / shared-IO blast radius:** `ResourceQuota` does not cap disk IOPS, page-cache thrashing, PID exhaustion, or disk space. A runaway `rwsafe` query, prompt flood, or kaniko build can trigger node `DiskPressure`/`MemoryPressure` and evict `neXus` pods. | 1. Assign `rwsafe` pods a lower `PriorityClass` than `neXus` (`system-cluster-critical`) with `preemptionPolicy: Never` and no `disk-pressure` toleration.<br>2. Set explicit container `pids.limit` / thread-pool bounds and JVM `-XX:MaxDirectMemorySize` + `-XX:MaxRAMPercentage`.<br>3. Enforce a hard disk budget (`MAX_STORE_BYTES`) with an automatic high-watermark circuit breaker that stops raw prompt persistence if `HOST-A` disk usage exceeds 75%. |
| **2. ICAP behind Broadcom ProxySG as primary inline path** | **Protocol mismatch & proxy coupling:** ProxySG ICAP has strict timeouts, pools TCP connections, does not natively stream bidirectional WebSockets frame-by-frame over ICAP the way modern AI coding agents use them, and buffers `RESPMOD` unless Preview/streaming is carefully tuned. An slow ICAP server degrades all proxied AI traffic. | 1. Mandate ICAP `Preview:` header negotiation (e.g., 4–16 KB preview) and fast-path `204 No Modifications` for low-risk flows.<br>2. Require explicit ProxySG health-check (`OPTIONS`) tuning and a per-rule fail-open/fail-closed matrix on ProxySG.<br>3. Require Phase 0 verification of exact ProxySG SGOS version behavior for SSE, HTTP/2, and WebSockets before writing the ICAP adapter. |
| **3. Prompt & response capture ON from day one** | **Write-amplification & storage explosion:** Coding agents (`Claude Code`, `Copilot`, `Windsurf`, `Devin`) send massive context windows (100k+ tokens of repo files) on every turn. Encrypting, masking, indexing, and storing full raw payloads inline will saturate disk and DB WAL within days. | 1. Decouple capture from the inline path via a bounded async persistence pipeline.<br>2. Mandate content-addressed chunk deduplication (CAS) before encryption so repeated system prompts/repo files across turns are stored once.<br>3. Store raw encrypted blobs in a bounded filesystem/object store (`rwsafe-artefact-store` PVC, like `neXus` `35-artefact-store-pvc.yaml`), never as large `BYTEA`/`TEXT` columns in PostgreSQL tables, and index only masked metadata/digests in Postgres. |
| **4. Java for the inline ICAP & LLM gateway path** | **No standard Spring ICAP server; GC/memory spikes under streaming load:** Naive String/byte-array copying of multi-megabyte JSON/SSE payloads across regex/masking layers causes allocation spikes, GC pauses, and carrier-thread pinning in Java 21. | 1. Use a dedicated Netty-based ICAP/HTTP proxy engine for the data plane with bounded pooled `ByteBuf` memory and zero-copy streaming parsers (Jackson streaming `JsonParser` / Aho-Corasick / RE2J linear-time regex—forbid backtracking `java.util.regex` on untrusted prompts to prevent ReDoS).<br>2. Keep Spring Boot MVC/jOOQ/Flyway strictly in the control/admin plane or decoupled from the Netty inline event loop. |
| **5. Reverse proxy change on 443 (`nexus.<corp-domain>` & `rwsafe.<corp-domain>`)** | **Breaking existing `neXus` access & deploy automation:** `deploy/ui2/60-ingress.yaml` has a host-less catch-all rule and `tools/delivery/hosta_deploy.sh` checks `https://127.0.0.1/`. Changing `neXus` Ingress carelessly breaks bare-IP fallback or `hosta_deploy.sh`. | 1. Require Fable to inspect `deploy/ui2/60-ingress.yaml` and `tools/delivery/hosta_deploy.sh` first.<br>2. Specify the exact two-step zero-downtime migration: keep `neXus` answering on `ui2.nexus.local` and `nexus.<corp-domain>`, add `rwsafe.<corp-domain>` as an explicit host rule (evaluated before any catch-all), and update `hosta_deploy.sh` via a standalone `neXus` PR before `rwsafe` deploys. |

---

## 3. Missing Deliverables & Acceptance Criteria for the Design Phase

Add the following concrete deliverables and acceptance gates to **Section 9** of the brief:

1. **`docs/operations/CAPACITY_AND_SLO_MODEL.md` (New Deliverable):**
   - Back-of-envelope sizing grounded in `HOST-A`'s actual CPU, RAM, and free disk (from read-only inspection): peak concurrent ICAP connections, coding-agent requests/min, average & p99 payload size (separating chat UI vs. coding-agent full-context requests), daily raw + deduplicated storage growth (GB/day), Postgres growth (GB/day), and hard PVC/store quotas.
   - Explicit inline latency breakdown budget (e.g., network + ICAP framing + identity lookup + deterministic DLP/redaction + policy verdict $\le X\text{ ms}$ p95 / $\le Y\text{ ms}$ p99).
2. **`docs/architecture/ICAP_AND_STREAMING_PROTOCOL_SPEC.md` (New Section in `ARCHITECTURE.md` or ADR):**
   - Exact state machines for `OPTIONS`, `REQMOD`, and `RESPMOD` (including `Preview:`, `100 Continue`, `204 No Modifications`, SSE chunked streaming, WebSocket fallback/chained proxy handoff, and graceful connection drain on `SIGTERM`).
3. **`docs/operations/DEPLOY_AND_SHARED_HOST_RUNBOOK.md` (New Deliverable):**
   - Exact blue-green / zero-downtime rolling-update mechanics on single-node k3s for ICAP (`1344`) and LLM Gateway without `hostPort` conflicts, plus build/deploy serialization lock protocol with `neXus` on `HOST-A`.
4. **Measurable Design-Freeze Acceptance Criteria (add to Section 9):**
   - **AC-1 (Zero-Starvation Proof):** Sum of `rwsafe` namespace `ResourceQuota` limits + `neXus` (`ui2`, `ui2-build`, `ui2-security`) requests/limits + system overhead fits within `HOST-A` physical RAM/CPU/disk with at least 25% headroom, and `rwsafe` `PriorityClass` is strictly below `neXus`.
   - **AC-2 (Zero-Downtime Proof):** The ICAP and LLM Gateway manifest designs support `kubectl rollout restart` on single-node `HOST-A` with `0` dropped requests in an active load test and `0` `hostPort` scheduling deadlocks.
   - **AC-3 (Linear-Time Inline Guarantee):** No inline guardrail uses backtracking regular expressions (`java.util.regex`), blocking JDBC calls, or unbounded heap allocation on the request thread; max inspectable payload size and chunk window are explicitly bounded.
   - **AC-4 (OpenShift Parity Check):** Workload manifests pass the `neXus` `PORT-1`/`PORT-3` checklist (`runAsNonRoot: true`, no fixed UID/GID/fsGroup, `readOnlyRootFilesystem: true`, digest-pinned images, Secret file mounts under `/run/secrets/`).

---

## 4. Council Seat Summary Tables (`roles/REVIEWER.md`)

### Consent
| Area | Verdict |
|---|---|
| Product scope, 5 core jobs, and day-one `aiview` / privacy masking parity with `neXus` | **CONSENT** |
| Separate `rwsafe` namespace, separate Postgres `StatefulSet`/PVC, and host-based 443 Ingress routing | **CONSENT** (subject to P0-2 and P0-3 mitigations) |
| Reuse of `neXus` SSDF, gate-registry concept, and multi-agent orchestration tooling | **CONSENT** (subject to P1-3 parameterization) |

### Dissent (Must be corrected in the brief before handing to Fable)
| Finding ID | Brief Section | Dissent / Required Correction |
|---|---|---|
| **P0-1** | §2, §5B, §7 | Do not allow a monolithic single-replica `Recreate` service with synchronous DB writes/triggers on the inline ICAP/gateway path; require a stateless hot-path data plane decoupled from PostgreSQL via async bounded queues. |
| **P0-2** | §4 Rule 1, §2 | `ResourceQuota`/`LimitRange` alone does not protect `neXus` on `HOST-A`. Mandate lower `PriorityClass`, no `disk-pressure` toleration, CAS deduplication for coding-agent contexts, and a hard disk watermark circuit-breaker. |
| **P0-3** | §2, §4 Rule 3 & 4 | Account for `deploy/ui2/60-ingress.yaml`'s host-less catch-all rule and `hosta_deploy.sh`'s `https://127.0.0.1/` check; route the LLM API gateway over 443 host-based Ingress rather than a custom port unless justified. |
| **P0-4 / P0-5** | §2, §6, §7 | Specify Netty-based RFC 3507 ICAP framing, non-buffering SSE `RESPMOD` semantics, linear-time regex (`RE2J`), and `Service`-based (non-`hostPort`) `RollingUpdate` (`maxUnavailable: 0, maxSurge: 1`) on single-node k3s. |

### Questions for the Product Owner
| # | Question | Recommendation |
|---|---|---|
| **Q1** | For **streaming SSE responses (`RESPMOD`)** where full buffering would freeze IDE/CLI token streaming for 30–120s, do you accept **strict inline blocking/redaction on `REQMOD` (prompts/uploads) + sliding-window stream inspection on `RESPMOD` (which aborts the stream mid-flight on a high-confidence leak and audits all responses asynchronously)**? | **Yes** — full `RESPMOD` buffering makes interactive coding agents (`Claude Code`, `Copilot`) unusable. |
| **Q2** | Should the **LLM API Gateway** (`OPENAI_BASE_URL` / `ANTHROPIC_BASE_URL`) be exposed on **standard HTTPS port 443 via its own Ingress hostname** (e.g., `ai-api.<corp-domain>` or `rwsafe.<corp-domain>/v1`) instead of a separate TCP port on `HOST-A`? | **Yes** — eliminates extra port openings/hardening exceptions and works natively with corporate firewalls and SDKs. |
| **Q3** | When `HOST-A` disk usage crosses a safety watermark (e.g., **75% used**), should `rwsafe` **stop persisting raw encrypted prompt/response bodies** (keeping only masked metadata, risk verdicts, and audit logs, while continuing inline enforcement) so `neXus` is never threatened by `DiskPressure`? | **Yes** — preserves inline security enforcement and `neXus` availability while preventing disk exhaustion. |

---

## Verbatim Instruction Audit Trail (`roles/REVIEWER.md`)

1. **System / Constitution (`AGENTS.md` & `roles/REVIEWER.md`):**
   - `AGENTS.md`: *"If `.nexus/WORKER.md` exists in your working directory you are an orchestrated worker: read only it. Otherwise state your role in your first message and read `roles/<ROLE>.md` (`PO`, `ENGINEER`, `WORKER`, or `REVIEWER`) before anything else in the reading order."*
   - `roles/REVIEWER.md`: *"Read `AGENTS.md` and only the repository files the brief names. Review only the supplied evidence for the named concern; never widen the review, decide, edit, run shell, spawn another agent, or retrieve additional evidence not already supplied. Report a secret or identity by file, location, and classification, never by value. Return exactly what the brief's own procedure asks for (a claim/finding structure for an evidence review, or `consent`/`dissent`/`questions for the Product Owner` tables for a council seat) and nothing else, then end by listing every instruction you received, verbatim, so isolation can be audited."*
2. **User Prompt (Verbatim Invocation Header & Task):**
   - `SEAT: platform-architecture`
   - `LENS: Platform, SRE and architecture: isolation on the shared k3s host with neXus, inline ICAP performance and availability with ProxySG, Java runtime choices for the inline path, deploy/blue-green, observability, capacity, portability, multi-agent development workflow and reuse of neXus tooling.`
   - `# Security and architecture council: review of the rwsafe-ai-gateway architecture kickoff brief`
   - *"You are one independent seat of a design council. The Product Owner wants the strongest possible start: the kickoff brief below will be given to Fable to produce the architecture of a new product (an enterprise AI-usage security gateway: enterprise-tenant enforcement for Claude, Copilot, Codex/ChatGPT, Devin, Windsurf, Gemini; prompt/response capture (legal approval exists); guardrails/DLP; an LLM API gateway; ICAP behind Broadcom ProxySG with SSL interception; an agent-based path for Edge SWG/off-net users; same single on-prem k3s server as the sibling product neXus, fully isolated; Java; the neXus governance, masking and admin platform from day one). The organisation is in a regulated sector in Turkey (treat KVKK and possible BDDK-style banking rules as in scope unless shown otherwise).*
   - *Your job: find what the brief is MISSING or gets WRONG, so that the design phase does not need a second round. Answer with: 1. P0 gaps (the design would be wrong or unsafe without them), P1 gaps, P2 nice-to-have. For each: what to add to the brief, why, and the concrete design question Fable must answer. 2. Risks you see in the stated decisions (hosting on the same server as neXus, ICAP inline path, prompt capture on from day one, Java for the inline path, reverse proxy change) and the mitigation the brief should demand. 3. Missing deliverables or acceptance criteria for the design phase. Be concrete and short (bullets). No generic advice. Do not rewrite the brief. Your seat lens is given at the top of the message. The candidate additions the engineering session already listed are included after the brief; confirm, reject or sharpen them, and add what is still missing."*
   - Followed by the full text of `# rwsafe-ai-gateway: architecture kickoff brief for Fable` (Sections 1–9) and `## Candidate additions already listed by the engineering session`.
