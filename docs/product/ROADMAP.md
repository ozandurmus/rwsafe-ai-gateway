# Roadmap

**Status:** DRAFT for design freeze. Phases per brief section 9 item 8, with acceptance criteria, size (S/M/L/XL in
engineering weeks for the Opus-led implementation team) and risk. No phase changes HOST-A, neXus, ProxySG or any
production system until its own acceptance says so; phase 0 changes nothing at all.

## Phase 0: discovery and measurement (no production change) — size M, risk low

| Task | Output | Acceptance |
|---|---|---|
| Masked measurement of ProxySG access logs for the AI category | request counts per platform, surface and hour; body-size distributions; share of WebSocket upgrades and HTTP/2; client user-agent classes; coverage baseline for SEC-6 (a Job run by the proxy team or the PO through a sanitising script; the agent reads counts only) | the CAPACITY §3 ASSUMED rows are replaced by measured values |
| ProxySG capability record for the installed SGOS | Secure ICAP and client-certificate support, max object size setting and its error handling, Preview behaviour, SSE pass-through to RESPMOD (incremental or buffered), HTTP/2 → ICAP encapsulation, WebSocket upgrade visibility, `X-Authenticated-User` encoding | PLATFORM_MATRIX §1 rows lose their UNVERIFIED marks or gain a documented limitation |
| Read-only SSL-interception bypass audit (SEC-7) | which AI-relevant domains are exempt; the "uncategorised AI → inspect" rule drafted | a list of categories to change, for the proxy team |
| Vendor header verification | Entra, Google, ChatGPT headers tested on a lab client; Gemini-app coverage by the Google header | ADR-007 rows verified |
| Login-flow frame fixtures per platform | sanitized, synthetic-body REQMOD/RESPMOD frames for login, OAuth callback, session bootstrap, chat POST, SSE response, upload | fixtures committed; shape fingerprints defined |
| Per-client trust matrix | measured column of PLATFORM_MATRIX §4 | every client row measured or marked unreachable |
| Broadcom support case: Cloud SWG → on-prem ICAP (Q-20) | answer recorded | ADR-006 §4 resolved |
| Corporate contract facts (PRIV-3) | region, DPA, zero-retention per platform from the contracts | PLATFORM_MATRIX §5 filled |
| Repository and CI | GitHub repository created by the PO; skeleton, privacy gate, ArchUnit fences, Gradle lockfiles, empty data-plane and control modules compiling; CI running the gate and unit tests | first green pipeline on a PR |

## Phase 1: quick wins (ProxySG tenant headers; no rwsafe runtime yet) — size S, risk low

| Task | Acceptance |
|---|---|
| Proxy team deploys `Restrict-Access-To-Tenants`/`Restrict-Access-Context` (+ `restrict-msa`), `X-GoogApps-Allowed-Domains`, `ChatGPT-Allowed-Workspace-Id` on the pilot group's policy layer (Q-21) | lab users with a personal account are refused by the vendor; corporate users unaffected; blocked sign-ins visible in the vendors' admin reports |
| Claude Code managed settings and Copilot enterprise policies on managed devices (ADR-007 endpoint row) | `/status` shows enterprise managed settings; a personal API key or a relay base URL fails |
| Vendor tenant settings attestation (domain capture, Require SSO, EMU, Devin/Windsurf SSO) | an attestation record per platform (described, not screenshot-stored) |
| neXus ingress PR (ADR-003) with the 404 default backend and the health-check fix (Q-13) | zero-downtime rollout confirmed; bare-IP requests get 404 |
| Hardening exception H-1 approved and the firewall rule template added in the neXus repository | rule present with an empty set until the pilot |

Metrics live from here: share of AI sign-ins on enterprise tenants (from vendor reports and, later, rwsafe).

## MVP: ICAP enforcement, prompt capture (redacted mode), admin baseline — size XL, risk medium

Preconditions: phase 0 fixtures and ProxySG record; Q-1 to Q-6, Q-9, Q-10, Q-13, Q-14, Q-15, Q-16, Q-30, Q-31, Q-33 decided;
the prerequisite neXus PR merged (ingress, health check, shared build lock); the ProxySG client certificate for Secure
ICAP issued; lab tenants for the ICAP e2e tenant fixtures (Q-34).

| Deliverable | Acceptance |
|---|---|
| Namespace, quota, PriorityClasses, PSA, NetworkPolicies, `rwsafe-db`, control plane, worker | AC-1, AC-4 manifest tests green; capacity sum recorded |
| Data plane: ICAP engine (OPTIONS/REQMOD/RESPMOD, Preview, 204, limits), Tier-1 detectors, policy snapshot, event queues | SR-DP-*, SR-ICAP-1..4, SR-ICAP-6 green; fuzz corpus in the gate; AC-3 |
| Zero-downtime rollout proof | AC-2 load drill recorded |
| Identity: LDAP/AD login, group → role binding, break-glass, roles incl. `privacy_officer` and `replay_viewer` | SR-ADM-*; CLI parity suite |
| Policy registry with simulation mode, staged rollout by group, exceptions with expiry, approvals | SR-AUD-3; a policy moves monitor → enforce only through the UI/CLI with approval |
| Capture in redacted mode (Q-4 b): C1/C2/C3/C6, notice acceptance gate, watermark breaker | SR-PRIV-10, SR-PRIV-11, SR-HOST-2 |
| Masking funnel, leak probe with Turkish identifiers, exports, 503 fail-closed | AC-5, SR-PRIV-1..7, SR-PRIV-12 |
| Audit triggers, SIEM out (CEF/LEEF/HEC), notifications, SNMP health, health and change-feed screens | SR-AUD-*, SR-SIEM-*, SR-NOT-1 |
| Turkish end-user texts (notice, block, coaching) with acceptance recording | PRIV-2 tests |
| In-cluster ICAP e2e Job, masked-role e2e, log scanner, coverage metric | AC-6 rows except deletion drill; AC-7 metric |
| Pilot on one AD group: **Secure ICAP from day one**, then REQMOD fail-open for one to two weeks with the coverage alert armed, then fail-closed (Q-14, Q-E); plain ICAP and fail-open never at the same time | coverage ≥ 0.98, p99 within budget, zero leak-probe hits, no neXus incident attributable to rwsafe |

Risks: ProxySG SSE behaviour (if buffered, RESPMOD for streams is dropped and the gateway becomes the response-side
visibility path); detector false positives on Turkish text (mitigated by the synthetic corpus and monitor-first);
HOST-A disk (raw capture stays off until the watermark clears).

## Phase 3: LLM API gateway — size L, risk medium

Gateway on `ai-api.<corp-domain>`, short-lived client credentials, corporate keys server-side, model/region allowlist per
class (Q-7), per-team quotas and cost reports, streaming relay with window, REQMOD key-class blocking of personal keys on
the API hosts, relay blocklist. Acceptance: SR-GW-* green; a tool configured with the gateway base URL works for
Anthropic- and OpenAI-compatible SDKs; a personal key on the corporate network is blocked and coached.

## Phase 4: agent path and advanced guardrails — size XL, risk high

MV3 extension spike (2 weeks) then the policy-installed extension for managed browsers (Q-19), the agent channel with
mTLS and signed updates, optional endpoint agent for CLI tools, Edge SWG integration if Broadcom's answer allows (Q-20),
async ML prompt-injection tier (Q-22), OCR for images if the bypass catalogue shows the need, shadow-AI discovery
screens, MCP allowlist and tool-call inspection where visible, chained proxy if Q-18 says so. Acceptance: SR-AGT-*,
SR-DET targets on the extended corpus, spike report with measured block reliability.

## Continuous

Daily security scans and acceptance review; weekly ZAP and registry GC; quarterly access review and restore drill;
protocol-drift alerts handled within one day; the root-cause log kept; the pre-pilot independent penetration test
(`PENETRATION_TEST_PLAN.md`) before the pilot group goes to fail-closed.

## Success metrics (brief 10.4)

| Metric | Source | Target |
|---|---|---|
| Share of AI traffic on enterprise tenants | rwsafe tenant verdicts + vendor reports | ≥ 99 % after the pilot |
| Personal logins blocked | login-step verdicts | trend to zero attempts |
| DLP incidents and false-positive rate | analyst dispositions on findings | FP ≤ 5 % of blocks after tuning |
| Inline p95/p99 | histograms | p95 ≤ 20 ms, p99 ≤ 40 ms (64 KiB) |
| Coverage ratio (SEC-6) | ProxySG summary vs rwsafe counts | ≥ 0.98 |
