# ADR-010: Fail-open and fail-closed

Status: PROPOSED (revised after the design-freeze council 2026-10-30: OFF2-2, OFF2-3, OFF2-4, PLAT-F5, PLAT-F9, PC-5, Q-E)
Date: 2026-10-30
Answers: brief section 6; council ARCH-1, ARCH-6, PRIV-3, SEC-1, SEC-6, Argon risk table row 2

## Context

Two systems can fail: ProxySG's decision when its ICAP server is unreachable, slow or errors (a per-service setting), and
rwsafe's own decision when a dependency is unavailable or a body cannot be inspected. The brief asks for an explicit default
per policy with the reason. The privacy seat requires the customer-data and banking-secret class to be fail-closed and
never relaxed; the offensive seat requires that every uninspectable body be treated as such, and that the fail behaviour be
decided by the **flow's policy**, not by a class the engine could not detect.

## Decision

### 1. Vocabulary

- **Fail-closed classes**: `secret`, `customer_data` (incl. banking secret), `special_category`, `internal_identity` (estate
  names and addresses). The set is a policy-registry constant with a test (SR-DLP-1).
- **Fail-closed flow**: a platform × surface × step × group policy entry whose class list contains at least one fail-closed
  class **and** whose mode is `enforce`. The engine knows this from the snapshot before it reads the body, so it can act
  on it even when inspection fails (OFF2-4).
- **Uninspectable**: `UNINSPECTABLE(reason)` with reasons `OVERSIZE`, `UNDECODABLE_BLOB`, `ENCRYPTED_ARCHIVE`, `IMAGE_NO_OCR`,
  `DEPTH_LIMIT`; `MALFORMED`, `INSPECTION_FAILED`, `INSPECTION_TIMEOUT`, `UNKNOWN_FLOW` are the other non-verdicts.
- There is **no `PARTIAL_INSPECTION`**: bodies up to the 4 MiB limit are inspected in full (PLAT-F5); anything the engine
  could not fully inspect is `UNINSPECTABLE`.

### 2. ProxySG side (configured by the proxy team, specified by rwsafe)

| ICAP service | Default | Reason |
|---|---|---|
| `rwsafe-reqmod-ai` (REQMOD for the AI category) | **fail closed** | no corporate AI use without inspection is the product's purpose. Health check every 5 s, connection timeout 2 s, REQMOD transaction timeout 15 s, 2 replicas behind one Service keep the closed window short |
| `rwsafe-respmod-ai` (RESPMOD) | **fail open** | an uninspected response costs visibility, not exfiltration; blocking responses on an rwsafe outage breaks every IDE session. Logged by ProxySG and counted by the coverage metric |
| uncategorised domains and selected broad categories (OFF2-5, Q-30) | **fail open**, REQMOD in **header-only metadata mode** (no body capture, 30-day retention) to detect relays and new AI hosts by request shape | discovery, not enforcement |
| any other category | not sent to rwsafe | the privacy seat's scope concern |

The pilot order is **Secure ICAP first, then the fail-open measurement window** (Q-E, Q-28 recommendation changed to
Secure ICAP from day one); a plain-ICAP pilot and REQMOD fail-open never run at the same time. The switch to fail closed
is a recorded ProxySG change (ROADMAP phase 1 acceptance).

### 3. rwsafe side

| Condition | Behaviour | Reason |
|---|---|---|
| No snapshot at start | OPTIONS and readiness 503 | never route to an engine without a policy |
| Snapshot stale (control plane down) | keep enforcing from the last snapshot up to 24 h, then 503 | a stale policy beats none; a day-old policy is a visible incident |
| Capture queue full | drop the oldest **capture** events, count, alert above 0.1 %/h | visibility may degrade |
| Verdict and audit events (PLAT-F9) | an in-memory queue backed by a **bounded spool file on the pod's emptyDir (256 MiB, about 500 k compact records)**, written by the async emitter thread, never the request thread; while the control plane is down the spool fills and drains later; when the spool is 100 % full the engine treats fail-closed flows as **block** and counts the degradation | accountability never silently degrades |
| Capture store or disk watermark | raw bodies stop first, then redacted; metadata, verdicts and enforcement continue | ARCH-2 |
| Masking dictionary or HMAC key missing (masked role) | 503 to the masked request; never unmasked | brief 4A rule 3 |
| **Fail-closed flow** gets a non-verdict (`UNINSPECTABLE`, `MALFORMED`, `INSPECTION_FAILED`, `INSPECTION_TIMEOUT`) | **block** with the coaching page naming the reason class; SIEM event | an uninspected body on a fail-closed flow is the exfiltration the product exists to prevent (OFF2-2, OFF2-3, PLAT-F5) |
| Non-fail-closed flow gets a non-verdict | **allow with warn**, metadata captured, SIEM event; the group may be moved to block by policy | proportionality |
| An expiring exception on a fail-closed flow | requires `privacy_officer` + `security_admin` approval and a recorded legal instrument (customer instruction or contract clause); an analyst-approved exception is refused by the registry (PC-5) | Banking Law art. 73 (REGULATORY_MAPPING §2) |
| Tenant check not evaluable (unknown auth flow version) | `UNKNOWN_FLOW`: block the login step and alert (protocol drift) | brief 10.4 |
| Identity unresolvable | anonymous policy (strictest tenant rule, no content capture), `IDENTITY_UNCLAIMED` label | SEC-3 |
| Per-identity in-flight cap or body-receive timeout hit | the ADR-010 flow action for that identity's transaction; pool unaffected | OFF2-10 |
| LLM gateway upstream unreachable | 502 with the upstream's reason class; no fallback to another vendor or region | PRIV-3 |
| Async ML classifier unavailable | inline deterministic verdicts stand; `NOT_EVALUATED` recorded | ARCH-7 |

### 4. Monitor-only and staged rollout (PC-5)

Monitor-only (simulation) exists for **new or changed rules on non-fail-closed classes and for tenant rules**. For
fail-closed classes there is no monitor-only relaxation: a new rule is **shadow-evaluated** (its verdict recorded next to
the live verdict) while the seed baseline keeps enforcing. The block page hides the exception link for fail-closed classes.

### 5. Every fail-open or degraded event is an auditable record

Each row above that allows traffic in a degraded state produces a SIEM event with class, count and reason, feeds the
coverage metric, and shows on the health screen as a word with a colour.

## Alternatives considered

- Fail open everywhere: contradicts the product's purpose and the fail-closed classes.
- Fail closed everywhere: breaks IDE and CLI sessions on every deploy; rejected for RESPMOD and non-sensitive flows.
- Allow-with-warn for oversize or encoded bodies on fail-closed flows: a free bypass by padding or encoding (OFF2-2,
  OFF2-3); rejected.
- Head/tail sampling above 256 KB: a free bypass by padding (PLAT-F5); rejected.

## Consequences

- The availability design (two replicas, PDB, drain) is load-bearing for REQMOD fail-closed: AC-2 is a precondition.
- SR-DLP-1 (fail-closed class set and flow rule) is added to SECURITY_REQUIREMENTS with tests per non-verdict.
- The data plane needs an emptyDir spool with `sizeLimit` 256 MiB (ADR-001 emptyDir rule).

## Evidence and UNVERIFIED facts

UNVERIFIED: ProxySG's exact ICAP service settings (fail open/closed, health check, timeouts, object size) for the
installed SGOS version; phase 0.

## Open questions

Q-1, Q-14, Q-28 (now: Secure ICAP first), Q-30 (header-only metadata mode for uncategorised domains), Q-31 (tool-result
injection blocking).
