# ADR-010: Fail-open and fail-closed

Status: PROPOSED
Date: 2026-10-30
Answers: brief section 6 (Performance, Availability); council ARCH-1, ARCH-6 (parse failure is a verdict), PRIV-3
(customer data fail-closed), SEC-1 (oversize bodies fail open at ProxySG), SEC-6 (fail-open events to the SIEM), Argon
risk table row 2

## Context

Two independent systems can fail: ProxySG's decision when its ICAP server is unreachable, slow or returns an error (a
per-ICAP-service setting on ProxySG: fail open or fail closed), and rwsafe's own decision when a component it depends on
is unavailable (policy snapshot, masking dictionary, capture store, classifier, database). "Fail open" means the AI
request proceeds uninspected; "fail closed" means it is blocked. The brief asks for an explicit default per policy and the
reason. The privacy seat requires the customer-data and banking-secret class to be fail-closed; the offensive seat requires
every fail-open event to be visible.

## Decision

### 1. ProxySG side (configured by the proxy team, specified by rwsafe)

| ICAP service | Default | Reason |
|---|---|---|
| `rwsafe-reqmod-ai` (REQMOD for the AI domain category) | **fail closed** | the product's job is "no corporate AI use without inspection"; an uninspected prompt to a personal tenant is the loss the product exists to prevent. Health check (OPTIONS) every 5 s, connection timeout 2 s, transaction timeout 5 s, 2 replicas behind one Service make the closed window short |
| `rwsafe-respmod-ai` (RESPMOD for the same category) | **fail open** | a response that arrives uninspected costs visibility, not exfiltration; blocking responses on an rwsafe outage would break every IDE session for a monitoring loss. The event is logged by ProxySG and counted by the coverage metric |
| any other category | not sent to rwsafe | ICAP applies only to the AI domain list (privacy seat: scope explosion); the uncategorised-AI rule (SEC-7) adds new AI domains to the inspected list, not every site |

A pilot group may start with REQMOD fail open for two weeks to measure rwsafe's availability; the switch to fail closed is
a ProxySG change recorded in ROADMAP phase 1 acceptance.

### 2. rwsafe side, per dependency

| Dependency unavailable | Inline behaviour | Reason |
|---|---|---|
| Compiled policy snapshot missing at start | ICAP OPTIONS answers unhealthy (no 200), pods stay not-ready | ProxySG never routes to an engine with no policy |
| Snapshot stale (control plane down) | keep enforcing from the last snapshot up to 24 h, then unhealthy | a stale policy beats no policy; a day-old policy is a visible incident |
| Capture queue full | drop the oldest **capture** events, count them, raise an alert above 0.1 %/h; **never drop verdict or audit events** (they have a separate, smaller queue that applies backpressure by marking the transaction `AUDIT_DEGRADED` and still enforcing) | visibility can degrade, enforcement and accountability cannot |
| Capture store or disk watermark | stop persisting raw bodies, then redacted content; keep metadata, verdicts, enforcement | ARCH-2 |
| Masking dictionary or HMAC key (masked role) | HTTP 503 to the masked request; never unmasked | brief 4A rule 3 |
| DLP class engine failure (rule pack load error, budget exceeded, parse failure) | the transaction gets verdict `INSPECTION_FAILED`; the action is **block** for fail-closed classes (secrets, customer data, banking secret, special-category personal data) and **allow with warn** for the rest, plus a SIEM event | a parse failure is never a silent allow (ARCH-6) |
| Body above the inspection limit (default 4 MB REQMOD, 16 MB upload) | verdict `OVERSIZE`; action **block** for the fail-closed classes' platforms when the body is an upload, **allow with warn and metadata capture** otherwise; the limit is below ProxySG's ICAP max-file-size so ProxySG never silently bypasses rwsafe | SEC-1 |
| Tenant check cannot be evaluated (unknown auth flow version) | verdict `UNKNOWN_FLOW`, action **block the login step** and alert (protocol drift) | brief 10.4 |
| Identity unresolvable (no proxy-claimed user, surrogate missing) | enforce the **anonymous policy** (strictest tenant rule, no capture of content) and label the record `IDENTITY_UNCLAIMED` | SEC-3 |
| LLM gateway upstream unreachable | 502 to the client with the upstream's reason class; no fallback to another vendor or region (PRIV-3: the model and region allowlist is per data class) | |
| Async ML classifier unavailable | inline deterministic verdicts stand; the async verdict is recorded as `NOT_EVALUATED` | ARCH-7 |

### 3. Every fail-open or degraded event is an auditable record

Each row above that allows traffic in a degraded state produces a SIEM event with class, count and reason, feeds the
coverage metric, and shows on the system health screen as a word with a colour (`Degraded: capture`, never a bare dot).

## Alternatives considered

- Fail open everywhere for availability: contradicts the product's purpose and the privacy seat's fail-closed classes.
- Fail closed everywhere: breaks IDE and CLI sessions on every rwsafe deploy and makes rwsafe a single point of failure for
  all AI work; rejected for RESPMOD and for non-sensitive classes.
- Buffering responses for full inspection: rejected in ADR-005.

## Consequences

- The availability design (two replicas, PDB, drain) is load-bearing for REQMOD fail-closed: AC-2 is a precondition for
  switching ProxySG to fail closed.
- Fail-closed classes need a precise definition and tests (SECURITY_REQUIREMENTS SR-DLP-*).

## Evidence and UNVERIFIED facts

- UNVERIFIED: ProxySG's exact ICAP service settings names (fail open/closed, health check interval, max file size) for
  the installed SGOS version; to be verified from Broadcom documentation and the proxy team in phase 0.

## Open questions

OPEN_QUESTIONS Q-1 (SSE strategy), Q-14 (REQMOD fail-closed from pilot start or after two weeks).
