# Council response: every P0 answered by ID, every P1 answered or deferred

**Status:** DRAFT for the design-freeze council (AC-8). The three seats' unaltered outputs are the `COUNCIL_2026_10_30_*`
files in this directory. Each row says where the design answers the item and what remains for the PO. Where a council
recommendation conflicts with a PO decision in brief section 2, the conflict is in `docs/product/OPEN_QUESTIONS.md` with
both options, never overruled here.

## 1. Architecture and platform (Argon seat, brief 10.1)

| ID | Answer | Where |
|---|---|---|
| ARCH-1 | Data plane and control plane are separate images and processes; the inline path decides from a signed in-memory snapshot, has no JDBC on its classpath (ArchUnit), no blocking I/O or synchronous control-plane call on a request thread, and emits capture and verdict events through bounded queues with an explicit overflow policy (capture events drop oldest and count; verdict and audit events are never dropped). Inline p99 is independent of PostgreSQL by construction. | ARCHITECTURE §2–3, AGENTS.md 5, ICAP spec §3, ADR-010 §2, SR-DP-6, SR-DP-7 |
| ARCH-2 | PriorityClasses 1000/500/−200 with `preemptionPolicy: Never`, all below every neXus service class; no disk-pressure toleration; ResourceQuota and LimitRange in the k3s overlay; hard byte cap 80 GiB with a 75 %/85 % disk-free watermark breaker that stops raw bodies first; content-addressed deduplicated chunks; the capacity sum on requests is 8.1 of 16 CPU and 18.7 of 62 GiB (49 % and 70 % headroom); measured disk 80 % used, so raw capture starts off. The one deviation (rwsafe data plane above neXus's `ui2-low` packet-analysis class) is Q-10. | ADR-001, PORTS §4, CAPACITY §1–2, SR-HOST-1, SR-HOST-4, Q-10, Q-11 |
| ARCH-3 | Exact diffs for `deploy/ui2/60-ingress.yaml` (catch-all removed, corporate host added, TLS Secret bound by SNI) and `tools/delivery/hosta_deploy.sh` line 121 (`--resolve` with the Host header); a 404 default backend for unknown Host or bare IP; the LLM gateway on 443 by host name (`ai-api.<corp-domain>`); `__Host-` cookies, host-only CSP, HSTS, no snippet annotations (headers from the application). | ADR-003, Q-2, Q-13, SR-ADM-1 |
| ARCH-4 | Netty-based RFC 3507 engine; OPTIONS/REQMOD/RESPMOD state machine with Preview, 100 Continue, 204, ieof; direct-buffer cap 512 MiB per pod and 1 MiB per connection; 1 000 in-flight; RESPMOD sliding window 16 KiB/2 KiB overlap, never a whole stream in memory, abort on high-confidence leak, async full analysis. | ICAP spec §3–4, ADR-005 |
| ARCH-5 | No hostPort, no Recreate for the data plane; 2 replicas, RollingUpdate maxUnavailable 0/maxSurge 1, PDB minAvailable 1; 1344/11344 exposed through a LoadBalancer Service via k3s ServiceLB (the mechanism Traefik already uses, measured); preStop drain with OPTIONS 503, `Connection: close`, 20 s; the AC-2 load drill (50 pooled connections, 200 tx/s, 0 drops) is specified. | DEPLOY runbook §1, ICAP spec §7, SR-ICAP-5, SR-AVL-1 |
| ARCH-6 | RE2/J only (ArchUnit forbids `java.util.regex` in `dataplane` and `detect`); explicit body, decompression, nesting and decoding limits; Jazzer fuzz targets and a committed corpus in the ship gate; a parse failure is an explicit verdict with the ADR-010 class action, never a silent allow. | ICAP spec §3, §4.5, §5; ADR-010 §2; SR-DP-1..4 |
| ARCH-7 | Tier 1 deterministic inline with a measured budget of 2 CPU-ms per 4 KiB and 12 CPU-ms per 64 KiB recorded in CI; Tier 2 ML asynchronous in the worker on redacted text, bounded 200 ms, 2 threads, circuit breaker; no GPU assumed; inline ML only after measurement and a PO decision. | ADR-008, CAPACITY §4, SR-DP-9, Q-22 |

P1 (Argon): **P1-1** build namespace `rwsafe-build`, shared host build lock, protected windows, registry GC rule (SHIP plan
§3–4, ADR-011) — answered. **P1-2** kustomize base/overlays reconcile brief rule 1 with PORT-1/PORT-3 (ADR-001) — answered.
**P1-3** per-repository delivery manifest `.rwsafe-delivery.json` listing every hard-coded assumption Argon found;
vendored parameterised copy until neXus adopts it (ADR-011, SHIP plan §2) — answered. **P1-4** classifier budget (ARCH-7
row) — answered. **P2-1** in-cluster ICAP e2e Job with REQMOD/RESPMOD fixtures and masked-view check (SHIP plan §5 step 5,
SR-ICAP-6) — answered. Argon's three PO questions are Q-1, Q-2, Q-3 with the council's recommendations adopted as the
architect's recommendation.

## 2. Privacy and compliance (Fable seat, brief 10.2)

| ID | Answer | Where |
|---|---|---|
| PRIV-1 | Legal basis per class (14 classes) with purpose, store, retention, hold, deletion proof, backup and SIEM columns; VERBIS mapping assigned to the DPO; UNVERIFIED legal readings listed for counsel. | DATA_CLASSES §1, §5; REGULATORY_MAPPING §1 |
| PRIV-2 | Notice is in the product: Turkish templates for first use, block page, coaching, personal-account block, exception form, stream termination; acceptance recorded as class C12 with the notice version; content capture for a user without acceptance stores metadata and verdict only (recommendation adopted). | docs/i18n/tr, ADR-009 §1, SR-PRIV-10 |
| PRIV-3 | The platform matrix carries region, DPA and zero-retention columns per vendor (UNVERIFIED until the contracts are read in phase 0) and the "never leaves" classes; the customer-data / banking-secret class is fail-closed and blocked for every external model until Q-7 decides otherwise; the sector regulator's primary-system, audit-trail and outsourcing rules are assessed with UNVERIFIED readings for counsel. | PLATFORM_MATRIX §5, ADR-010, REGULATORY_MAPPING §2, Q-7 |
| PRIV-4 | Retention matrix with one deletion path for expiry and DSAR: receipts, crypto-shredding of C4 data keys, SIEM deletion events, backup restore replays receipts; legal hold by the privacy officer with case id. | DATA_CLASSES §2–3, ADR-002 §5, ADR-009 §4, SR-PRIV-8 |
| PRIV-5 | A separate DSAR search for `privacy_officer` (by identifier or digest), audited with a case id, distinct from the masked search; objection handled as a no-capture group. | ADR-009 §6, SR-PRIV-9, REGULATORY_MAPPING art. 11 |
| PRIV-6 | Pseudonymisation is not treated as anonymisation; the masked role and external reviewers never receive prompt bodies by default (AGENTS.md 4.7); derived features only; any exception is a signed residual risk and the body is framed as untrusted. | AGENTS.md 4.7, MASKING §B4, SR-PRIV-3, THREAT_MODEL §10 |
| PRIV-7 | Findings store class, offset, length and digest (HMAC with its own key), never the value; every detected secret and PII span is redacted before persistence; the capture sink re-runs detectors on redacted text and rejects a hit. | ADR-009 §2, SR-PRIV-11 |
| PRIV-8 | No secondary use: captured content never trains or tunes classifiers, never feeds productivity analytics, never leaves the product; the evaluation corpus is synthetic; team analytics apply k ≥ 5. Design rule plus test. | ADR-009 §8, DATA_CLASSES §4 |
| PRIV-9 | No single admin opens raw content: JIT grant, four eyes across roles, reason codes, ≤ 4 h, DPO group notified at grant, immediate SIEM copy, watermarked view, per-view audit; break-glass only for an active P1 with next-day review; new `privacy_officer` role; masking and retention rules changed by `privacy_officer` proposal + `security_admin` approval. | RAW_CONTENT_ACCESS, MASKING §B1, SR-PRIV-5 |
| PRIV-10 | Bodies never in logs, traces, metrics labels, heap dumps or error pages; heap dumps off, JFR off in production; body-bearing types redact `toString()`; a log-scanner e2e proves it after the ICAP e2e. | ADR-009 §7, SR-PRIV-6 |

P1 (privacy): PIA written (PRIVACY_IMPACT_ASSESSMENT); 72-hour breach runbook (PIA §6); 5651 analysed, decided by
compliance (REGULATORY_MAPPING §3); contractors/BYOD/personal profiles → Q-6 with the recommendation "blocked, event only;
managed devices only"; blocked personal logins store the event, not the content (DATA_CLASSES §4); encrypted backups with
receipt replay (ADR-002); quarterly access review (RAW_CONTENT_ACCESS §6); synthetic prompt bodies in corpora (C11);
small-team aggregation k ≥ 5. All answered. P2 (ISO 27001/42001, NIST AI RMF, export watermarks, aggregated shadow-AI
discovery): answered in REGULATORY_MAPPING §4–5, MASKING §B5, ADR-004 (uncategorised-AI inventory from metadata).

The seat's "capture mode" risk (MVP in metadata + verdict + redacted mode, raw behind a separate key and approval record)
is presented to the PO as **Q-4 with both options**, because brief section 2 says capture is on from day one; the
architect's recommendation is the seat's option, which still keeps capture on (redacted content is content) and is also
forced by HOST-A's disk watermark today.

## 3. Offensive security (Fable seat, brief 10.3)

| ID | Answer | Where |
|---|---|---|
| SEC-1 | Blind-spot matrix per flow: WebSocket after upgrade (I, upgrade refused by default), HTTP/2 (E/L, UNVERIFIED encapsulation, force HTTP/1.1 fallback), oversize bodies (ProxySG rule set to deny, rwsafe limit below), gRPC trailers (L/I), uploads (E for text, archives depth 2, images no OCR in MVP → L), pinned apps (I), direct API (E via key class), off-net (I until the agent), cloud agents (T), QUIC (I, blocked). Each with the compensating control. | PLATFORM_MATRIX §3, OUT_OF_SCOPE §3 |
| SEC-2 | Devin, Codex cloud, Copilot coding agent, Claude Code on the web and Gemini cloud agents are declared out of gateway scope; the enforcement point is the vendor tenant (SSO/EMU/domain capture/app installation policy), rwsafe enforces the console login and records attestation; presented to the PO as Q-8. | OUT_OF_SCOPE §1, Q-8 |
| SEC-3 | Secure ICAP with mTLS (ProxySG client certificate pinned to the proxy team's CA), source-IP allowlist in NetworkPolicy and in the engine, `identity_source=proxy_claim` on every record with mTLS state; VDI/terminal-server/NAT addresses classified as shared and labelled; plain ICAP only during the pilot exception H-2 (Q-28). | ICAP spec §2, ADR-007 §3, SR-ICAP-1..3, HARDENING H-1/H-2 |
| SEC-4 | Normalisation (NFKC, zero-width, tag characters flagged, homoglyph folding, URL/HTML/base64/hex decoding to depth 2, decompression caps), archives to depth 2, images without OCR in the MVP (documented limitation, OCR later), per-user volume and finding-rate thresholds over a 10-minute window; a bypass catalogue with 40 rows, each with expected result and test; pilot acceptance depends on the MVP rows. | ADR-008 §2, BYPASS_CATALOGUE, SR-DET-3 |
| SEC-5 | Stored prompts are hostile input: inert rendering (text nodes, sandboxed container, CSP without inline scripts), CSV formula escaping, CR/LF and ANSI stripping on syslog/SIEM, untrusted framing for any AI consumer of the masked view and no bodies to it by default. STRIDE rows added. | THREAT_MODEL §4, SR-ADM-4, SR-SIEM-1, SR-PRIV-3, MASKING §B4 |
| SEC-6 | Coverage ratio = AI requests rwsafe saw / AI requests ProxySG saw (masked ProxySG access-log summaries imported by the worker), target ≥ 0.98, alert below 0.95; ProxySG fail-open events exported to the SIEM; a missing tenant header on a header-vendor host is a coverage fault alert. | CAPACITY §7, SR-DET-4, ADR-007 §1, ADR-010 §3 |
| SEC-7 | Phase 0 read-only audit of the SSL-interception bypass list for AI-relevant domains; "uncategorised AI domain → inspect and send to ICAP" rule drafted for the proxy team; new domains feed shadow-AI discovery. | ROADMAP phase 0, ADR-004 |

P1 (offensive): per-client trust matrix (PLATFORM_MATRIX §4, phase 0 fills it) — answered; tenant headers do not revoke
sessions → cookie/token-level checks where visible, re-login coaching, `NOT_EVALUABLE` counted, personal keys and
Bedrock/Vertex/relays blocked by the key class and the relay blocklist (ADR-007 §1–2) — answered; re-identification →
masked search over pseudonyms only, no raw filters, rwsafe-own HMAC key (MASKING §B2–B3, SR-PRIV-4) — answered; gateway
open relay → short-lived user+device credentials, fixed upstream list, no SSRF, cache isolation (THREAT_MODEL §3,
SR-GW-*) — answered; agent channel → mTLS with MDM certificate, signed updates, user-space only, MV3 feasibility note
(ADR-006 §3, §5) — answered, implementation deferred to phase 4; model and rule-pack supply chain → safetensors/ONNX only,
signed, hash-pinned, licence recorded (ADR-008 §3, SR-SC-1) — answered; k3s Secrets encryption (verified **on**, AES-CBC,
re-encryption finished), PSA restricted, no hostPath, CAP_NET_RAW dropped (ADR-001, SR-HOST-3) — answered; responses as an
attack path → RESPMOD async injection detection with alerting (ADR-005 §2) — answered as alert-only, block deferred
(Q-22). P2 (low-and-slow aggregation, platform-switching behaviour, OpenShift, agent SBOM): low-and-slow in
BYPASS BY-FRAG-3 (later), OpenShift in ADR-001 overlays, agent SBOM with ADR-006 implementation; platform-switching
analytics deferred (k-anonymity constraints).

## 4. Engineering-session additions (brief 10.4)

Scope, personas and success metrics (ARCHITECTURE §1, ROADMAP metrics); policy lifecycle with simulation, staged rollout,
expiring exceptions, break-glass and the coaching page with justification (ADR-008 §4–5, i18n); shadow-AI discovery
from aggregated metadata (ADR-004, worker); MCP governance via managed settings allowlists and tool-call inspection where
visible (ADR-007, THREAT_MODEL §9 LLM06); SIEM CEF/LEEF/HEC, alert taxonomy (worker, SR-SIEM-*), neXus coupling limited
to the directory and the SIEM (ADR-001 §7); testing: sanitized frame fixtures, protocol-drift detection, production
canary prompts, in-cluster ICAP e2e Job (ICAP spec §5, SHIP plan §5); self-observability without raw labels (ICAP spec §8,
ARCHITECTURE §8); shared delivery tooling with the per-repo manifest, build lock and registry GC (ADR-011, SHIP plan);
portability PORT-1/PORT-3 (ADR-001). All answered.

## 5. Design-freeze acceptance criteria (10.5)

| AC | Status at this draft |
|---|---|
| AC-1 | capacity sum shows 49 % CPU and 70 % memory headroom on requests; rwsafe PriorityClasses below every neXus service class (Q-10 on `ui2-low`) — **designed, manifest test specified** |
| AC-2 | rollout design: no hostPort, ServiceLB exposure, RollingUpdate 0/1, PDB, drain; the 0-drop load drill specified — **designed, drill pending implementation** |
| AC-3 | RE2/J only, no JDBC on the inline path, explicit limits — **designed, ArchUnit specified** |
| AC-4 | OpenShift portability checklist in ADR-001 §3, manifest test specified — **designed** |
| AC-5 | leak probe with Turkish identifiers and prompt-body screens — **designed** (SR-PRIV-2) |
| AC-6 | seven designed tests — **designed** (SR-PRIV-5, -7, -12, -6, -9, -8, -3) |
| AC-7 | bypass catalogue (40 rows with tests) and coverage metric (≥ 0.98) — **written** |
| AC-8 | this document — **written** |

## 6. What the council is asked to review at the freeze

The ADRs, ARCHITECTURE, ICAP spec, CAPACITY, PORTS, HARDENING, THREAT_MODEL, SECURITY_REQUIREMENTS, MASKING, DATA_CLASSES,
RAW_CONTENT_ACCESS, PIA, REGULATORY_MAPPING, BYPASS_CATALOGUE, PLATFORM_MATRIX, OUT_OF_SCOPE, ROADMAP, OPEN_QUESTIONS and
this response, through `tools/review/` (masked material, no prompt bodies), one seat per lens as in the kickoff council.

## 7. Design-freeze council (2026-10-30): dissents and what changed

Three seats, run through `tools/review/` (outputs unaltered: `FREEZE_2026_10_30_SEAT_FABLE_PRIVACY_COMPLIANCE.md`,
`FREEZE_2026_10_30_SEAT_FABLE_OFFENSIVE.md`, `FREEZE_2026_10_30_SEAT_ARGON_PLATFORM.md`). All three: **ACCEPT WITH
CORRECTIONS**. Every dissent is answered below with the correction made or the reason it is deferred to the PO.

### 7.1 Privacy and compliance (PC-1..PC-14)

| ID | Correction | Where |
|---|---|---|
| PC-1 | Notice gains controller identity, automated collection via the proxy, transfer to vendors abroad under an art. 9 instrument, SIEM metadata transfer, objection consequence, "not consent" sentence; placeholder table and the re-acknowledgement rule added | `docs/i18n/tr/notice_first_use.md`, `docs/i18n/README.md` |
| PC-2 | "Acceptance" → "acknowledgement" everywhere; explicit consent excluded as a basis (Q-32) | ADR-009, DATA_CLASSES, MASKING, REGULATORY art. 5, SR-PRIV-10 |
| PC-3 | C12 has four sources incl. the directory attribute (HR acknowledgement) and gateway credential issuance (Q-35) | DATA_CLASSES C12, SR-PRIV-10 |
| PC-4 | A vendor row is fail-closed for every class until its art. 9 instrument is recorded (Q-33) | ADR-007 §3a, REGULATORY art. 9, PIA §3 |
| PC-5 | No monitor-only on fail-closed classes (shadow evaluation instead); exceptions need `privacy_officer` + `security_admin` and a legal instrument; block page hides the exception link | ADR-010 §4, ADR-008 §4, SR-DLP-1, `tr/block_page.md` |
| PC-6 | C6 split: PII and customer-identifier digests 90 d then tombstone; digest key rotation; reversibility added to Q-29 | ADR-009 §1, DATA_CLASSES C6, Q-29 |
| PC-7 | Residual stated: undetected names and context remain in C3; layers 4 and 5 run at persistence; a C5 flag means no C3 | ADR-009 §2, DATA_CLASSES, PIA §4, SR-PRIV-15 |
| PC-8 | Break-glass needs another person's P1 case or a system alert id; DPO at grant time; 1 h, no extension; monthly cap | RAW_CONTENT_ACCESS §2, SR-PRIV-16 |
| PC-9 | Personal-account logins store class and corporate pseudonym only; the personal identifier is neither stored nor digested | ADR-009 §2, DATA_CLASSES §4, SR-PRIV-14 |
| PC-10 | `viewer` and `auditor` see pseudonymised C1 by default; resolve is a per-action audited step | MASKING B1, ADR-009 §5 |
| PC-11 | External reviewers: synthetic fixtures and aggregates only; AI agents as `replay_viewer` on production data added to Q-29 | MASKING A7, ADR-009 §5, PIA §3, Q-29 |
| PC-12 | BDDK incident notification owner added; third persons identified only by a content read under a grant | PIA §6, REGULATORY art. 12 |
| PC-13 | Q-12 backup target must be in Türkiye; C10 row records the location | OPEN_QUESTIONS Q-12, DATA_CLASSES C10 |
| PC-14 | New class C15 for case, grant and exception notes; "policy tuning" defined as deterministic rule review | DATA_CLASSES, ADR-009 §8 |

### 7.2 Offensive security (OFF2-1..OFF2-17)

| ID | Correction | Where |
|---|---|---|
| OFF2-1 | 204 on a preview only with `ieof`; otherwise full-body decision; fixture BY-PAD-1 | ICAP spec §4.3, SR-DP-10, BYPASS |
| OFF2-2 | `OVERSIZE` is `UNINSPECTABLE`; block on fail-closed flows; one body limit (4 MiB) on the engine, ProxySG denies above it | ICAP spec §3, ADR-010 §1–3, BY-PAD-2 |
| OFF2-3 | Residual blobs > 256 B uninspectable; a finding inside a decoded layer replaces the whole field; BY-ENC-8 to MVP | ICAP spec §3, BYPASS |
| OFF2-4 | Fail behaviour by **flow policy** ("fail-closed flow" defined); SR-DLP-1 added; dangling SR-DLP-* reference resolved | ADR-010 §1, SECURITY_REQUIREMENTS |
| OFF2-5 | Coverage-metric limit stated; header-only metadata mode for uncategorised domains (Q-30) | ADR-004, ADR-010 §2, CAPACITY §7 note |
| OFF2-6 | Every JSON string leaf inspected; base64 leaves with file magic → file pipeline; fingerprint on required fields only | ICAP spec §4.3, §5, SR-DP-11, BY-FIELD-1 |
| OFF2-7 | Tool-result and web-content blocks run injection detectors at REQMOD (block possible); RESPMOD abort set on agentic surfaces; monitor first (Q-31) | ADR-005 §2, 3a; ADR-008 §2; ICAP spec §4.3–4.4 |
| OFF2-8 | Client-chosen metadata and justification text are content-grade | ADR-008 §2, ADR-009 §1, DATA_CLASSES, THREAT_MODEL §4, SR-ADM-9 |
| OFF2-9 | Estate names matched whole-token over keyed digests in the data plane; plaintext dictionary only in the control plane and worker; limitation documented | ADR-008 §2, THREAT_MODEL §1 |
| OFF2-10 | Per-identity in-flight cap, body receive rate and receive timeout; pool never exhausted by one identity | ICAP spec §3, SR-DP-2, PENTEST |
| OFF2-11 | Monotonic snapshot version; replayed older snapshot refused | ICAP spec §4.2, ADR-008 §4, SR-DP-8 |
| OFF2-12 | Group claims drive policy only on mTLS connections; strictest policy and no exception on plain connections | ADR-007 §3, ICAP spec §2, SR-ICAP-2 |
| OFF2-13 | Storage-integrated and embedded AI blind spots with compensating controls | PLATFORM_MATRIX §3, OUT_OF_SCOPE §3a |
| OFF2-14 | Gateway credentials bound to the MDM certificate or a directory session; fingerprint is a signal | SR-GW-1 |
| OFF2-15 | Agent tooling surface added to the threat model; demotion of `docs/reviews/` to evidence proposed (Q-36, needs the PO's hand on AGENTS.md) | THREAT_MODEL §8a, Q-36 |
| OFF2-16 | Build pods hardened (baseline PSA, no token, egress to registry and proxy only, size-limited ephemeral storage); pentest item added | THREAT_MODEL §8, PENTEST |
| OFF2-17 | Pentest scope extended (lab tenants Q-34, CRLF/smuggling after rewrite, fail-open flipping, injection against AI consumers) | PENETRATION_TEST_PLAN §2 |
| Q-E | Secure ICAP first, then the fail-open window; never both | ADR-010 §2, HARDENING H-2, ROADMAP MVP, Q-28 |

### 7.3 Platform and architecture (PLAT-F1..PLAT-F9)

| ID | Correction | Where |
|---|---|---|
| PLAT-F1 | Per-connection buffer ≥ body limit + 64 KiB; 256 MiB pod-wide full-body semaphore; ICAP pod memory 2 GiB, worker trimmed | ICAP spec §3, PORTS §4.3 |
| PLAT-F2 | ServiceLB masquerade acknowledged: allowlist at the host firewall, peer identity by mTLS, NetworkPolicy admits ServiceLB pods | ICAP spec §2, PORTS §3, HARDENING, runbook §1.2, `03-icap-service-lb.yaml` |
| PLAT-F3 | Drain keeps serving for 15 s with `Connection: close`; refusal only afterwards | ICAP spec §7, runbook §1.2, SR-DP-13 |
| PLAT-F4 | RESPMOD timeout 300 s with 30 s idle; 204 only within Preview; one-window delay so the offending window never leaves; `Accept-Encoding` stripped for SSE | ICAP spec §4.4, §6; ADR-005 |
| PLAT-F5 | No head/tail sampling; full inspection up to 4 MiB with a clean-chunk cache; no `PARTIAL_INSPECTION` | CAPACITY §4, ADR-010 §1 |
| PLAT-F6 | `services.loadbalancers: 3`; quotas and LimitRanges for `rwsafe-build` and `rwsafe-security`; PSA baseline on the build namespace stated consistently; emptyDir `sizeLimit` rule | `02-quota-and-limits.yaml`, `00-namespaces.yaml`, ADR-001 §3, HARDENING, PORTS §4.2 |
| PLAT-F7 | Disk watermark read by `statvfs` on the PVC path; `automountServiceAccountToken: false` on every pod | ADR-001 §3, CAPACITY §2 |
| PLAT-F8 | No 404 backend pod (Traefik's native 404); host names injected as a transient kustomize patch on stdin, never written to the tree | ADR-003, runbook §2 |
| PLAT-F9 | Verdict/audit spool on emptyDir (256 MiB) with fail-closed-on-full; the shared build lock lands in the same prerequisite neXus PR | ADR-010 §3, ADR-011 §2, SHIP plan §3, SR-DP-12 |
| Q1–Q3 | PriorityClass relation (Q-10), prerequisite neXus PR scope (Q-13 + lock), MVP capture under the watermark (Q-3/Q-4): recommendations unchanged, confirmations requested from the PO | OPEN_QUESTIONS |

### 7.4 Status

All P0-grade corrections named by the seats (PC-1, PC-4, PC-5, PC-8; OFF2-1..7; PLAT-F1..F9) are applied in the documents.
Open for the PO: Q-30..Q-36 and the AGENTS.md changes that need the PO's hand (Q-36 and the Git-authority sentence). The
freeze is accepted when the PO ratifies by decision record.
