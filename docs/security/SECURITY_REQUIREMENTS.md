# Security requirements catalogue, each with the test that proves it

**Status:** FROZEN by `docs/design/PO_DECISION_RECORD_2026_10_30_DESIGN_FREEZE.md` (2026-10-30); amended only through a PO decision record or an ADR
that quotes one.

**History:** DRAFT for design freeze (SSDF PO.1, PW.8). Ids are stable and referenced from the threat model, ADRs and the
council response. Test kinds: `unit`, `arch` (ArchUnit), `fuzz` (Jazzer), `it` (PostgreSQL integration Job), `e2e-icap`
(in-cluster ICAP Job), `e2e-ui` (Playwright as the masked role), `load`, `manifest` (manifest tests), `scan` (ship gate),
`drill` (operator exercise with a recorded result). AC-n marks the brief's design-freeze criteria.

## Data plane (SR-DP)

| Id | Requirement | Test |
|---|---|---|
| SR-DP-1 | No backtracking regex on the inline path: only RE2/J (or an equivalent linear engine) may be referenced from `dataplane` and `detect` | arch: forbid `java.util.regex` imports in those modules (AC-3) |
| SR-DP-2 | Explicit limits: REQMOD body 4 MiB inspected in full (no sampling), RESPMOD window 16 KiB/64 KiB max in memory with one window of delay, decompression 8× and ≤ body limit, JSON depth 64, decoding depth 2 with residual blobs > 256 B uninspectable, header sizes, 1 000 in-flight, per-connection buffer ≥ body limit + 64 KiB, 256 MiB pod-wide full-body semaphore, per-identity in-flight cap 32 (256 per shared address), body receive rate ≥ 64 KiB/s and 10 s receive timeout (OFF2-10, PLAT-F1, PLAT-F5) | unit per limit; fuzz; load (AC-3) |
| SR-DP-3 | A parse failure or inspection exception yields an explicit verdict (`MALFORMED`, `INSPECTION_FAILED`) and the ADR-010 action; never a silent 204 | unit with malformed fixtures; fuzz corpus asserts no 204 on crash paths |
| SR-DP-4 | ICAP and HTTP decoders are fuzzed in CI (line, headers, `Encapsulated`, chunked, preview/ieof, SSE, JSON extractor, normaliser) with a committed corpus; a crash or timeout fails the gate | fuzz in the ship gate |
| SR-DP-5 | Inline decision time ≤ 2 s wall clock, ≤ 200 ms per RESPMOD chunk; p95/p99 budgets of CAPACITY §4 | load (ICAP e2e load profile), histograms |
| SR-DP-6 | The data plane makes no JDBC call, no blocking disk write, no synchronous HTTP to anything but the control plane, and no Internet egress (ICAP role) | arch (no `java.sql`, no Spring MVC); manifest (NetworkPolicy); it |
| SR-DP-7 | Capture events may be dropped under overflow (counted, alerted); verdict and audit events are never dropped | unit (queue policy), load |
| SR-DP-8 | Snapshot signature verified before activation; unsigned, stale (> 24 h) or **lower-versioned than the active one** (OFF2-11) snapshots are refused; without any snapshot the engine is not ready | unit (signed older snapshot refused); e2e-icap (OPTIONS 503 without snapshot) |
| SR-DP-10 | A 204 on a Preview is sent only when the preview carries `ieof`; otherwise the full body is received and inspected (OFF2-1) | unit fixture: 4 KiB benign prefix + secret after the preview → BLOCK |
| SR-DP-11 | Every JSON string leaf is inspected regardless of schema; base64 leaves with a file magic go to the file pipeline; unknown fields are counted, not ignored (OFF2-6) | unit fixture: secret in an unknown field → detected |
| SR-DP-12 | Verdict and audit events spool to a bounded emptyDir ring file (256 MiB) during a control-plane outage; a full spool turns fail-closed flows to block (PLAT-F9) | unit, it (outage drill) |
| SR-DP-13 | Drain: OPTIONS/readiness 503 at once, transactions served with `Connection: close` for 15 s, refusal only afterwards (PLAT-F3) | load drill (AC-2) |
| SR-DLP-1 | The fail-closed class set (`secret`, `customer_data`, `special_category`, `internal_identity`) is a registry constant; a **fail-closed flow** (an enforce-mode policy entry containing one of them) blocks on every non-verdict (`UNINSPECTABLE`, `MALFORMED`, `INSPECTION_FAILED`, `INSPECTION_TIMEOUT`); fail-closed classes have no monitor mode and no analyst-granted exception (OFF2-2, OFF2-4, PC-5) | unit per non-verdict; registry test (analyst exception refused) |
| SR-DP-9 | Tier-1 detectors cost ≤ 2 CPU-ms per 4 KiB and ≤ 12 CPU-ms per 64 KiB on the pinned JDK image | perf test in CI with recorded numbers (ARCH-7) |

## ICAP interface (SR-ICAP)

| Id | Requirement | Test |
|---|---|---|
| SR-ICAP-1 | Secure ICAP on 11344 requires a client certificate chained to the ProxySG CA; plain 1344 exists only while the pilot exception H-2 is open and is removed by manifest | unit (TLS handshake), manifest, e2e-icap |
| SR-ICAP-2 | The ProxySG source allowlist is enforced at the host firewall (ServiceLB masquerades the TCP source, PLAT-F2); the engine admits the ServiceLB pods and identifies the peer by client certificate on 11344; group claims on plain connections select no exception (OFF2-12) | manifest (NetworkPolicy), e2e-icap, firewall rule review |
| SR-ICAP-3 | Every record carries `identity_source`, mTLS state and the shared-address label | unit, it |
| SR-ICAP-4 | rwsafe's body limit is below ProxySG's ICAP max object size; oversize yields `OVERSIZE` with the ADR-010 action | unit; phase-0 configuration record |
| SR-ICAP-5 | Zero dropped transactions during `kubectl rollout restart` under load (50 pooled connections, 200 tx/s) | load drill (AC-2) |
| SR-ICAP-6 | Unknown platform/step fingerprint → `UNKNOWN_FLOW` verdict and alert within 60 s (protocol drift) | unit, e2e-icap |

## Gateway (SR-GW)

| Id | Requirement | Test |
|---|---|---|
| SR-GW-1 | Client credentials are short-lived (≤ 8 h), bound to the MDM client certificate (mTLS) where present, otherwise to a directory session with re-authentication; the device fingerprint is an anomaly signal only, never the binding (OFF2-14); revocable | unit, it |
| SR-GW-2 | Unauthenticated requests get 401; no path serves the corporate key without a credential | unit, e2e |
| SR-GW-3 | Upstream hosts, models and regions come from the snapshot allowlist per data class; client-supplied URLs or unknown headers are rejected or stripped (no SSRF) | unit, fuzz (header injection) |
| SR-GW-4 | Token counts and cost per request are recorded and exported per team | it |
| SR-GW-5 | No response or prompt cache is shared across credentials | unit |
| SR-GW-6 | Upstream keys never appear in logs or error bodies | log-scanner test with a canary key shape |
| SR-GW-7 | Per-team and per-credential rate and token quotas; upstream circuit breaker | unit, load |
| SR-GW-8 | Keys mounted only in gateway pods; PSA restricted; read-only root; no shell | manifest |

## Admin (SR-ADM)

| Id | Requirement | Test |
|---|---|---|
| SR-ADM-1 | `__Host-` cookies, host-only CSP without inline scripts, HSTS when on the corporate certificate, `X-Frame-Options: DENY` | e2e-ui header assertions |
| SR-ADM-2 | LDAP filters parameterised; bind credential in a Secret; break-glass accounts audited and business-hours-confirmed; SAML SP (if enabled) validates signatures and audience | unit, it |
| SR-ADM-3 | CSRF token on every mutation; four-eyes on `enforce` changes to fail-closed classes | unit, e2e-ui |
| SR-ADM-4 | Captured content is rendered inert (text node, sandboxed container), exports escape CSV formulas (`=`, `+`, `-`, `@`, tab, CR) | e2e-ui with hostile fixtures; unit |
| SR-ADM-5 | Exports are bounded and asynchronous | unit |
| SR-ADM-6 | Group → role bindings are integrity-protected and audited | it |
| SR-ADM-7 | Every UI action has a CLI counterpart using the same routes and gates | e2e (CLI parity suite) |
| SR-ADM-8 | Error responses carry the server's reason code and message; the UI never shows a bare "Request failed" | e2e-ui |
| SR-ADM-9 | Client-chosen metadata fields (file names, tool and MCP names, model, URL path and query, user agent, SSE event names, upstream error text) and justification free text are content-grade: length-capped, control characters stripped, rendered inert, untrusted-framed in the masked API, digest or enum in the SIEM (OFF2-8) | unit, e2e-ui hostile fixtures per field |

## Privacy and masking (SR-PRIV)

| Id | Requirement | Test |
|---|---|---|
| SR-PRIV-1 | Every API response for `replay_viewer` passes the masking funnel; the rule-set version header is present | unit (funnel coverage test over all controllers), e2e-ui |
| SR-PRIV-2 | The leak probe walks every screen, tab and export as the masked role with canary values including TCKN (valid checksum), TR IBAN, TR mobile numbers, customer numbers, Turkish names, host names and addresses, and prompt-body screens; zero hits | e2e-ui canary digests (AC-5) |
| SR-PRIV-3 | The masked role and external reviewers receive no prompt body by default; the masked API frames content fields as untrusted | unit, e2e-ui, review-script test (AC-6 "external review scripts send no content") |
| SR-PRIV-4 | Masked search runs only over pseudonymised fields and derived features; no raw-value filter exists; analytics apply k ≥ 5 | unit, e2e-ui |
| SR-PRIV-5 | A raw read without a grant (reason code, approver, case, time) returns 403 and is audited; a grant notifies the DPO and emits a SIEM copy | it, e2e-ui (AC-6) |
| SR-PRIV-6 | Bodies never appear in logs, traces, metrics labels, heap dumps or error pages; a log scanner finds no canary body after the ICAP e2e | log-scanner e2e (AC-6), unit on logging rules |
| SR-PRIV-7 | Missing masking dictionary or HMAC key → 503 for masked requests, never unmasked | unit, e2e-ui (AC-6) |
| SR-PRIV-8 | Deletion (retention or DSAR) removes rows and manifests, shreds data keys, writes receipts, emits SIEM deletion events; restore replays receipts | it, drill (AC-6 "after deletion nothing remains in backups or the SIEM") |
| SR-PRIV-9 | The DSAR search finds a person's records by employee identifier or by a digest match and is audited with a case id | it, e2e-ui (AC-6) |
| SR-PRIV-10 | Content capture for a user without a notice **acknowledgement** record from any source (banner, IDE first run, directory attribute, gateway credential issue) stores metadata and verdict only (PC-2, PC-3) | it (AC-6 privacy seat test, both sources) |
| SR-PRIV-14 | A blocked non-corporate login stores class, platform and the corporate pseudonym only; the personal identifier is neither stored nor digested (PC-9) | unit, it |
| SR-PRIV-15 | A record with a C5 special-category flag persists no C3 text; masking layers 4 and 5 run at persistence (PC-7) | unit, it |
| SR-PRIV-16 | Break-glass raw access needs a P1 case opened by another person or a system alert id; DPO notified at grant; 1 h, no extension; monthly cap (PC-8) | it |
| SR-PRIV-11 | Findings store class, offset, length and digest, never the value; the capture sink rejects C3 text in which a detector still hits | unit, it |
| SR-PRIV-12 | Exports for masked roles are masked by column meaning, including spreadsheet cells | unit, e2e-ui (AC-6) |
| SR-PRIV-13 | The repository privacy gate rejects real IPs, host names, serials, account names, secret shapes, TCKN/IBAN/phone values and unmarked prompt fixtures; allowlist entries carry owner and review date | gate self-test in CI |

## Audit (SR-AUD)

| Id | Requirement | Test |
|---|---|---|
| SR-AUD-1 | Every mutation carries actor fingerprint, action id, reason code and correlation id set per transaction; a trigger writes the audit row and refuses a transaction without them | it |
| SR-AUD-2 | Audit rows are append-only (no UPDATE/DELETE grants to the app role) | it |
| SR-AUD-3 | Policy changes record old and new snapshot hashes and the approvers | it |

## Availability and host (SR-AVL, SR-HOST)

| Id | Requirement | Test |
|---|---|---|
| SR-AVL-1 | ICAP and gateway: 2 replicas, RollingUpdate maxUnavailable 0, PDB minAvailable 1, preStop drain, readiness tied to snapshot | manifest, load drill |
| SR-HOST-1 | rwsafe never tolerates disk pressure, carries PriorityClasses below neXus, enforces the byte cap and watermarks | manifest (AC-1), unit |
| SR-HOST-2 | Above the watermark raw persistence stops first, then redacted; enforcement continues | unit, it |
| SR-HOST-3 | PSA restricted, no hostPath, no hostPort in pod specs, caps dropped incl. NET_RAW, read-only root, no privileged | manifest (AC-4) |
| SR-HOST-4 | Capacity sum (requests) of neXus + rwsafe + system ≤ 75 % of the node | manifest test against the recorded inventory (AC-1) |

## SIEM and notifications (SR-SIEM, SR-NOT)

| Id | Requirement | Test |
|---|---|---|
| SR-SIEM-1 | Exported strings are stripped of control characters and length-capped | unit with CR/LF/ANSI fixtures |
| SR-SIEM-2 | The SIEM event schema has no body field; a schema test enforces it | unit |
| SR-SIEM-3 | Syslog over TLS by default; UDP only by recorded PO acceptance | manifest, unit |
| SR-NOT-1 | Mail uses a fixed sender and the configured relay only | unit |

## Agent channel (SR-AGT, later phase)

SR-AGT-1 mTLS device certificate; SR-AGT-2 signed packages and pinned update server; SR-AGT-3 no bodies by default,
server rejects body fields outside capture conditions; SR-AGT-4 per-device rate limits; SR-AGT-5 user-space only. Tests
are specified with ADR-006's implementation.

## Supply chain (SR-SC)

| Id | Requirement | Test |
|---|---|---|
| SR-SC-1 | Models and rule packs: safetensors/ONNX only, hash-pinned, signed, licence recorded | unit (loader refuses other formats), scan |
| SR-SC-2 | Gradle lockfiles and verification metadata; Trivy on lockfiles; SBOM per image | scan |
| SR-SC-3 | Images digest-pinned; signature and provenance verified at deploy | deploy script test |

## Detection quality (SR-DET)

| Id | Requirement | Target | Test |
|---|---|---|---|
| SR-DET-1 | Secret shapes (vendor keys, PEM, JWT) | FN ≤ 1 %, FP ≤ 0.5 % on the synthetic corpus | unit corpus |
| SR-DET-2 | TCKN, TR IBAN, card numbers with checksum | FN 0 % on well-formed, FP ≤ 0.1 % | unit corpus |
| SR-DET-3 | Bypass catalogue techniques | each technique's expected result holds | unit corpus per technique (AC-7) |
| SR-DET-4 | Coverage ratio | ≥ 0.98, alert < 0.95 | metric test with synthetic ProxySG summaries (AC-7) |

## Design-freeze acceptance mapping

AC-1 SR-HOST-1, SR-HOST-4; AC-2 SR-ICAP-5, SR-AVL-1; AC-3 SR-DP-1, SR-DP-2, SR-DP-6; AC-4 SR-HOST-3; AC-5 SR-PRIV-2;
AC-6 SR-PRIV-5, SR-PRIV-7, SR-PRIV-12, SR-PRIV-6, SR-PRIV-9, SR-PRIV-8, SR-PRIV-3; AC-7 SR-DET-3, SR-DET-4; AC-8
`docs/reviews/COUNCIL_RESPONSE.md`. Council-added: SR-DP-10..13, SR-DLP-1, SR-ADM-9, SR-PRIV-14..16.
