# Capacity and SLO model, sized from HOST-A's measured CPU, RAM and disk

**Status:** DRAFT for design freeze. Inputs: the 2026-10-30 masked inventory (`PORTS_AND_RESOURCES.md` §1, §4.1), the
kickoff brief sections 4 and 6, council ARCH-1, ARCH-2, ARCH-7, P0-2 and the AC-1 acceptance criterion. Traffic figures
are **assumptions to be replaced by phase-0 measurement** of ProxySG logs (ROADMAP phase 0); each is marked ASSUMED.

## 1. Node capacity and the AC-1 headroom sum

| Resource | HOST-A | neXus requests (measured) | neXus limits (measured) | system (kube-system, measured working set, no limits) | rwsafe requests (plan) | rwsafe limits (quota cap) |
|---|---|---|---|---|---|---|
| CPU | 16 | 4.6 | 25 | about 0.5 | 3.0 | 8 |
| Memory | 62 GiB | 10.4 GiB | 73.9 GiB | about 0.5 GiB working set, 2 GiB reserve assumed | 6.3 GiB | 16 GiB |

**Requests sum** (what the scheduler guarantees): 4.6 + 3.0 + 0.5 = **8.1 CPU of 16 (49 % headroom)**; 10.4 + 6.3 + 2.0 =
**18.7 GiB of 62 (70 % headroom)**. AC-1's 25 % headroom holds on requests with margin.

**Limits sum** (the burst ceiling): neXus alone is already over the node (25 CPU, 74 GiB). Adding rwsafe's quota ceiling
(8 CPU, 16 GiB) makes 33 CPU and 90 GiB. Limits are not simultaneous demand, but the memory side matters: if neXus's
service, worker and policy pods all hit 8 GiB while packet analysis holds 24 GiB, the node is at 48 GiB before rwsafe.
Mitigations that are rwsafe's to make: rwsafe memory limits are hard and small (16 GiB quota), rwsafe pods have no
disk-pressure toleration and a lower PriorityClass, so **rwsafe is the first thing evicted**, never neXus. The
observation that neXus's own limits over-commit the node is reported to the PO (OPEN_QUESTIONS Q-11); rwsafe does not
change neXus manifests.

**Live working set** today: 8 GiB of 62. The real contention is disk, not CPU or memory.

## 2. Disk model

| Item | GiB | Source |
|---|---|---|
| Root filesystem | 1005 | measured |
| Used | 764 (80 %) | measured |
| Available | 189 | measured |
| kubelet eviction threshold (5 % nodefs) | about 50 | kubelet config |
| **Usable before DiskPressure** | **about 140** | derived |
| Image filesystem | 47.5 | measured |
| neXus claims (nominal) | 400 (artefact store) + 120 (packet analysis) + 2 (db) + 6 (build) | PVC list; local-path enforces none of it |
| Security and registry claims | 50 + 20 | PVC list |

Two consequences. First, rwsafe's claims must be **small and application-capped**: `requests.storage` 150 GiB in the
quota is a ceiling, not a plan; the plan is 100 GiB for the capture store with an **80 GiB application byte cap**
(`MAX_STORE_BYTES`), 20 GiB database, 10 GiB models. Second, the **disk-free watermark circuit breaker** (council Q3,
recommendation yes): when node-filesystem usage crosses **75 %** (it is 80 % today, so the breaker starts tripped) rwsafe
stops persisting raw bodies, keeps metadata, verdicts, redacted features and audit, and keeps enforcing; at **85 %** it
also stops persisting redacted content and keeps only metadata and verdicts; enforcement never stops for disk. The
watermark is read from the kubelet summary API (node fs) by the control plane every 30 s and pushed to the data plane in
the policy snapshot; with no reading for 5 minutes the breaker trips (fail closed for persistence).

**Until HOST-A is below 75 %, day-one capture stores metadata, verdicts and redacted content, not raw bodies.** This is a
capacity fact the PO's capture decision meets, and it coincides with the privacy seat's recommendation; it is presented
as such in OPEN_QUESTIONS Q-4 rather than silently applied.

## 3. Traffic and storage growth model (ASSUMED until phase 0)

| Parameter | Chat UI (web) | IDE and CLI coding agents | API gateway |
|---|---|---|---|
| Users in scope at MVP | ASSUMED 300 | ASSUMED 150 | ASSUMED 30 service identities |
| Requests per active user per working hour | ASSUMED 12 | ASSUMED 60 (agent loops) | ASSUMED 120 |
| Mean request body | ASSUMED 4 KB | ASSUMED 60 KB (repeated repository context) | ASSUMED 20 KB |
| p99 request body | ASSUMED 64 KB | ASSUMED 1 MB | ASSUMED 400 KB |
| Mean response body | ASSUMED 6 KB (SSE) | ASSUMED 12 KB (SSE) | ASSUMED 8 KB |
| Peak concurrent ICAP transactions | ASSUMED 120 | ASSUMED 300 | n/a (gateway: 60 concurrent streams) |
| Peak requests per second (all) | ASSUMED 40 | | ASSUMED 10 |

Raw bytes per working day at these assumptions: web 300 × 8 h × 12 × 10 KB ≈ 0.3 GB; coding agents 150 × 8 × 60 × 72 KB
≈ 5.2 GB; gateway 30 × 8 × 120 × 28 KB ≈ 0.8 GB; **about 6.3 GB/day raw**. Coding-agent context repeats the same
repository chunks every turn, so **content-addressed chunk deduplication (council ARCH-2)** is expected to remove 70–90 %
of the agent volume: planning figure **about 1.5 GB/day after dedup**, before compression. With 30-day raw retention
(OPEN_QUESTIONS Q-5) that is 45 GiB, inside the 80 GiB cap; redacted content and metadata at 90 days add about 10 GiB;
PostgreSQL metadata (one row per request, about 1.5 KB, 1 M requests/month) about 1.5 GB/month plus indexes. All of this
is re-derived from the phase-0 measurement before the MVP capture store size is fixed.

## 4. Inline latency budget (ICAP path, per transaction)

| Stage | Budget p95 | Budget p99 | How it is kept |
|---|---|---|---|
| TCP and ICAP framing (Netty decoder, Preview) | 1 ms | 2 ms | zero-copy ByteBuf, Preview 4 KB |
| Identity resolution (proxy-claimed user, group cache) | 0.5 ms | 1 ms | in-memory snapshot, no directory call inline |
| Policy decision (platform, tenant, DLP class routing) | 0.5 ms | 1 ms | compiled snapshot |
| Deterministic inspection, 4 KB body | 3 ms | 6 ms | RE2/J + Aho-Corasick, measured CPU-ms budget 2 ms |
| Deterministic inspection, 64 KB body | 15 ms | 30 ms | budget 12 ms; above 256 KB inspection samples head, tail and structured fields and records `PARTIAL_INSPECTION` |
| Verdict and response encoding | 0.5 ms | 1 ms | |
| **Total added by rwsafe (REQMOD, 64 KB)** | **≤ 20 ms** | **≤ 40 ms** | SLO; measured by the ICAP e2e Job and Micrometer histograms |
| RESPMOD sliding window per chunk | 2 ms | 5 ms | window 16 KB, overlap 2 KB |
| ML classifier (prompt injection, async tier) | not inline | not inline | runs in the worker on the captured, redacted text; verdict arrives after the response; bounded 200 ms per item with a circuit breaker, queue depth 1000 |

The budget never includes PostgreSQL or disk: the data plane does neither on the request thread (ARCH-1). The 204 fast
path (no modification) is expected for ≥ 95 % of transactions; its ratio is a metric.

## 5. Availability model

| Scenario | Behaviour | Source of truth |
|---|---|---|
| rwsafe rollout | 2 ICAP replicas, RollingUpdate `maxUnavailable: 0`, PDB; preStop drains ProxySG's pooled connections (ICAP `Connection: close` on in-flight responses, 20 s grace) | ADR-010, ICAP spec §7 |
| rwsafe control plane down | data plane keeps the last compiled snapshot (TTL 24 h), keeps enforcing, buffers capture events in its bounded queue, drops the oldest capture events when full and counts the drops; audit events are never dropped before verdict events | ADR-010 |
| rwsafe data plane down | ProxySG's own per-service fail-open/fail-closed setting applies; the PO decides per category (ADR-010): fail-closed for the AI domain category (no AI without inspection) is the recommendation, with ProxySG health checks every 5 s and a 2-second ICAP timeout | ADR-010 |
| HOST-A down | neXus and rwsafe are both down; AI traffic follows the ProxySG setting above | out of scope for rwsafe design |
| Disk above watermark | raw persistence stops first, then redacted; enforcement continues | §2 |

## 6. Horizontal scaling inside the quota

Within the 8 CPU / 16 GiB quota the data plane scales to 4 ICAP and 3 gateway replicas (each 1.5 CPU / 1.5 GiB limit)
before the control plane has to be trimmed; beyond that the answer is a second node, not a bigger quota. The classifier
CPU budget per 4 KB and 64 KB prompt is measured in CI on the pinned JDK image and recorded next to the SLO.

## 7. SLO summary

| SLO | Target |
|---|---|
| ICAP REQMOD added latency, 64 KB | p95 ≤ 20 ms, p99 ≤ 40 ms |
| RESPMOD per-chunk added latency | p99 ≤ 5 ms |
| Gateway added latency (non-streaming, excluding upstream) | p95 ≤ 30 ms |
| ICAP availability (successful OPTIONS from ProxySG) | 99.9 % monthly, rollouts included |
| Coverage ratio (requests rwsafe saw / AI requests ProxySG saw) | ≥ 0.98, alert below 0.95 (SEC-6) |
| Capture event loss under overflow | counted, alert above 0.1 % per hour |
| Masked-role leak probe | 0 canary hits per release |
