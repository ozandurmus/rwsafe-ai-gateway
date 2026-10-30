# ICAP and streaming protocol specification

**Status:** FROZEN by `docs/design/PO_DECISION_RECORD_2026_10_30_DESIGN_FREEZE.md` (2026-10-30); amended only through a PO decision record or an ADR
that quotes one.

**History:** DRAFT for design freeze, revised after the design-freeze council (2026-10-30: OFF2-1, OFF2-2, OFF2-3, OFF2-6,
OFF2-10, OFF2-11, PLAT-F1, PLAT-F3, PLAT-F4). Answers brief 10.5, council ARCH-4, ARCH-5, ARCH-6, Argon P0-4, P0-5,
offensive seat "ReDoS and parser DoS", SEC-1, SEC-3. Normative references: RFC 3507 (ICAP/1.0) and its errata, the ICAP
Extensions draft (`X-Client-IP`, `X-Authenticated-User`, `X-Server-IP`), RFC 9112 (HTTP/1.1), the HTML living standard for
`text/event-stream`, RFC 6455 (WebSocket), RFC 9113 (HTTP/2). ProxySG-specific behaviour is marked and is **verified in
phase 0 against the installed SGOS version** (UNVERIFIED until then).

## 1. Scope and non-goals

The engine `rwsafe-icap` is an ICAP/1.0 server (RFC 3507) on Netty, serving ProxySG as its only intended client. It
implements OPTIONS, REQMOD and RESPMOD with Preview, `100 Continue`, `204 No Content` (only where RFC 3507 allows it),
`Encapsulated` parsing, chunked HTTP bodies, `Allow: 204`, `ieof`, keep-alive connections and `Connection: close` drain. It
does not implement ICAP over HTTP/2, FTP RESPMOD, `206 Partial Content` or `X-Include`. Non-HTTP traffic (WebSocket frames
after the upgrade, raw tunnels, QUIC) is out of ICAP scope by protocol; ADR-004 and ADR-005 say what covers it.

## 2. Transport and trust (SEC-3, PLAT-F2)

| Item | Rule |
|---|---|
| Listeners | 1344 plain ICAP (pilot only, HARDENING_EXCEPTIONS H-2), 11344 Secure ICAP: TLS 1.2+/1.3 with **mutual authentication**; the ProxySG client certificate chain is pinned to the proxy team's CA, which lives in a Secret |
| Who may connect | **The source-address allowlist is enforced at the host firewall** (`@icap_clients` in the nftables table, HARDENING H-1), which sees the real ProxySG address. Inside the cluster, k3s ServiceLB masquerades the source to its own pod address (PLAT-F2), so the engine and the NetworkPolicy accept connections **from the ServiceLB pods** and the engine identifies the peer by **client certificate** (11344). On plain 1344 the engine has no peer identity beyond the firewall allowlist; every record on that port carries `transport=plain_allowlisted` and the pilot exception H-2 bounds it |
| Identity | `X-Authenticated-User` and `X-Authenticated-Groups` are **claims of the proxy**. Every record carries `identity_source=proxy_claim`, `transport` (`mtls_verified` or `plain_allowlisted`) and the surrogate type inferred from `X-Client-IP` (shared ranges for VDI and terminal servers, configured per estate, mark the record `identity_shared_address`). Group claims select policy entries, rollout groups and exceptions **only on `mtls_verified` connections**; on `plain_allowlisted` connections the strictest group policy applies and no exception is honoured (OFF2-12). A missing or malformed identity header selects the anonymous policy (ADR-010) |
| Client address | `X-Client-IP` is used for surrogate classification and the per-identity limits (§3), never stored raw: it is masked by the subnet-preserving masker before persistence |
| Clock | ICAP has no timestamps; the engine stamps receipt time in UTC |

## 3. Connection, buffer and identity limits (ARCH-4, ARCH-6, OFF2-10, PLAT-F1)

| Limit | Default | Behaviour on breach |
|---|---|---|
| Connections per engine | 2 000 | TCP backlog; above it new connections are refused (ProxySG retries another engine) |
| Idle connection timeout | 300 s (UNVERIFIED ProxySG pool idle default) | close |
| ICAP header section | 32 KiB total, 8 KiB per line, 64 headers | ICAP `400`, connection closed |
| Encapsulated HTTP header section | 64 KiB | `400`, verdict `MALFORMED` (never a silent allow) |
| Preview | engine advertises `Preview: 4096`; accepts any preview up to 64 KiB | |
| REQMOD body (`MAX_REQMOD_BODY`) | **4 MiB** for every surface; **16 MiB** for a multipart upload part is **not** a separate limit on the engine: the whole encapsulated request is bounded by 4 MiB; ProxySG's own ICAP object-size rule is set to **deny** above it (BY-FILE-6) | above 4 MiB: verdict **`UNINSPECTABLE`** (reason `OVERSIZE`) with the ADR-010 flow rule; the body is drained to `/dev/null`, never stored |
| Per-connection receive buffer | `maxInFlightBytesPerConnection` = **MAX_REQMOD_BODY + 64 KiB** so a 4 MiB body can be received without the connection pausing on itself (PLAT-F1) | above it (protocol violation): `400`, close |
| Full-body buffers per engine | a pod-wide semaphore caps concurrent full-body REQMOD buffers at **256 MiB** in total | above it: ICAP `503` for that transaction only, counter, alert; ProxySG's fail setting applies to the one transaction |
| Per-identity in-flight transactions | **32** per claimed user (fallback `X-Client-IP`), **256** per shared address | the identity's new transactions get the ADR-010 flow action (block on fail-closed flows) and a SIEM event; the pool-wide capacity is never exhausted by one identity |
| Body receive rate | minimum 64 KiB/s after the first 4 KiB, and a body-receive timeout of **10 s** independent of the 2 s decision time | `INSPECTION_TIMEOUT` verdict for that transaction; slow-loris cannot hold slots |
| RESPMOD window | 16 KiB sliding window, 2 KiB overlap; never more than 64 KiB of a response in memory per transaction | |
| Direct memory | `-XX:MaxDirectMemorySize=512m` per engine pod; Netty pooled allocator; pod memory limit **2 GiB** (PORTS §4.3 revised) | pool over 90 %: `503` for new transactions |
| Decompression | gzip/deflate/br of encapsulated bodies when declared or detected by magic bytes (BY-PROTO-7); output capped at 8× input and at `MAX_REQMOD_BODY`; nested encodings not decoded | `UNINSPECTABLE` |
| JSON nesting | 64 levels, 10 000 fields | `MALFORMED` |
| Base64 / nested decoding (SEC-4, OFF2-3) | depth 2, 2 MiB decoded per field | a residual undecodable or high-entropy blob **above 256 bytes** inside a prompt field → `UNINSPECTABLE`; a finding inside a decoded layer → the **whole encoded field** is replaced by the class token (REDACT) or the request is blocked, never a partial rewrite of encoded bytes |
| Regex | RE2/J only; patterns compiled at snapshot load; a pattern over 10 000 program steps is refused at load | no inline `java.util.regex` (ArchUnit) |
| Transaction time | REQMOD decision within 2 s wall clock after the full body is received; RESPMOD per window within 200 ms | `INSPECTION_TIMEOUT` → ADR-010 flow rule; never hangs ProxySG past its own timeout |
| In-flight transactions per engine | 1 000 | ICAP `503` beyond; metric |

## 4. The ICAP state machine

### 4.1 Connection states

```
ACCEPTED ──(TLS handshake, mTLS verified | plain, from a ServiceLB pod)──► READY
READY ──(request line)──► PARSING_HEADERS ──► {OPTIONS | REQMOD | RESPMOD}
after a transaction: ──(keep-alive)──► READY | ──(Connection: close | drain)──► CLOSING ──► CLOSED
any parse error ──► ERROR(4xx, Connection: close) ──► CLOSED
```

### 4.2 OPTIONS

`ICAP/1.0 200 OK`, `Methods: REQMOD` or `RESPMOD` per service URI (`/reqmod-ai`, `/respmod-ai`), `Service:
rwsafe-ai-gateway/<version>`, `ISTag: "<snapshot-version>-<snapshot-hash-prefix>"` (changes with every compiled policy, so
ProxySG re-validates), `Encapsulated: null-body=0`, `Max-Connections: 1000`, `Options-TTL: 300`, `Preview: 4096`,
`Allow: 204`, `Transfer-Preview: *`, `Transfer-Ignore: jpg,jpeg,gif,png,webp,woff,woff2,mp4` (RESPMOD only). OPTIONS is the
health check: **503** when the engine has no snapshot, is draining, or its pool is at the fail threshold, so ProxySG stops
selecting it. **Snapshot versions are monotonic** (OFF2-11): the engine refuses any signed snapshot whose version is lower
than the last activated one, so a replayed older snapshot with a weaker policy is never loaded.

### 4.3 REQMOD (the enforcing path)

```
REQMOD request line + ICAP headers
  Encapsulated: req-hdr=0, req-body=N | null-body=N
  Preview: P (optional)
  Allow: 204
  X-Client-IP, X-Server-IP, X-Authenticated-User, X-Authenticated-Groups
┌─ parse encapsulated HTTP request headers (method, URL, Host, Authorization/Cookie presence, Content-Type, Content-Length)
├─ classify flow: platform × surface × step (login, chat, upload, tool-call, other) from the platform matrix; the
│    fingerprint is on REQUIRED fields and content types only (OFF2-6); unknown platform+step → UNKNOWN_FLOW → ADR-010
├─ identity + tenant rule (ADR-007): login/OAuth steps are decided on headers alone
├─ Preview handling (OFF2-1):
│     a 204 on the preview is allowed ONLY when the preview carries `ieof` (the whole body was in the preview);
│     otherwise the engine always answers "ICAP/1.0 100 Continue" and decides on the FULL body (a benign 4 KiB prefix
│     can never buy an allow for what follows)
├─ full body available: normalisation (SEC-4), inspection of EVERY string leaf of JSON regardless of schema (unknown
│    extra fields are inspected and counted, never ignored and never UNKNOWN_FLOW by themselves; OFF2-6); base64 leaves
│    whose decoded bytes carry a known file magic (PDF, ZIP, DOCX, images) go to the file pipeline (BY-FILE-*);
│    deterministic DLP classes; tool_result / function result / fetched-web-content blocks run the injection detectors
│    (OFF2-7); tenant-at-token level where visible
├─ verdict ∈ {ALLOW, WARN, REDACT, BLOCK, UNINSPECTABLE(reason), MALFORMED, INSPECTION_FAILED, INSPECTION_TIMEOUT,
│    UNKNOWN_FLOW}; action per policy registry entry and the ADR-010 flow rule
├─ emit capture event (metadata always; redacted features/digests; content per ADR-009) to the bounded queue;
│    emit verdict event (spooled, never dropped; ADR-010 §4)
└─ respond:
     ALLOW ─────────────► ICAP/1.0 204 No Content (or 200 with the unchanged request when 204 is not allowed)
     WARN  ─────────────► as ALLOW + coaching event out of band; a WARN on a login step is a 200 + interstitial
     REDACT ────────────► ICAP/1.0 200 OK, Encapsulated: req-hdr, req-body: the rewritten request with sensitive spans
                           replaced by class tokens ([REDACTED:TCKN], [REDACTED:SECRET]); whole encoded fields replaced
                           as one token; Content-Length recomputed; no Transfer-Encoding left on the rewritten message;
                           CR/LF in rewritten header values rejected (request-smuggling guard, OFF2-17)
     BLOCK ─────────────► ICAP/1.0 200 OK, Encapsulated: res-hdr, res-body: HTTP 403 with the Turkish block page (HTML for
                           browsers, JSON {"error":{"type":"rwsafe_blocked",...}} for API clients by Accept/Content-Type),
                           X-RWSAFE-Reason: <class>, X-RWSAFE-Ref: <correlation id>; header values sanitised
     UNINSPECTABLE/MALFORMED/INSPECTION_FAILED/TIMEOUT/UNKNOWN_FLOW ─► the ADR-010 flow action, same encodings
```

A REQMOD decision is made **once**; the engine never issues a second ICAP request or contacts the control plane
synchronously. The compiled snapshot is the only input besides the request.

### 4.4 RESPMOD (the visibility path, sliding window; PLAT-F4)

```
RESPMOD request: Encapsulated: req-hdr=0, res-hdr=N, res-body=M ; Preview: P
┌─ parse the original request headers and the response headers (status, Content-Type, Transfer-Encoding, Content-Encoding)
├─ Transfer-Ignore types → 204 (ProxySG does not send them after OPTIONS anyway)
├─ Preview with ieof and body ≤ 64 KiB (non-streaming JSON): whole-body inspection → 204, or 200 with redaction
├─ everything else: "ICAP/1.0 100 Continue"; from here the answer is ALWAYS "ICAP/1.0 200 OK" with a streamed body
│    (RFC 3507 forbids 204 after 100 Continue). The body is relayed with ONE WINDOW OF DELAY:
│       receive chunk → append to window (16 KiB, 2 KiB overlap) → inspect the window (high-confidence leak detectors:
│         secret shapes, TCKN/IBAN with checksum, estate dictionary, customer-number formats; plus the high-confidence
│         prompt-injection patterns on agentic surfaces, OFF2-7) → only then forward the PREVIOUS, already-inspected
│         bytes to ProxySG. An offending window is never forwarded.
│       on a HIGH-CONFIDENCE hit: drop the offending window, emit a final SSE event
│         `event: error` / data: {"type":"rwsafe_stream_terminated","reason":"<class>","ref":"<id>"}, terminate the
│         encapsulated body (`0\r\n\r\n`), verdict STREAM_ABORTED, `bytes_forwarded_before_abort` recorded
│       Content-Encoding: for SSE endpoints the engine strips `Accept-Encoding` on REQMOD (policy flag per platform row)
│         so streamed responses arrive identity-encoded; a compressed stream that still arrives is inspected on the
│         decoded view and, on abort, the termination event is written in the stream's encoding
│       every window's text is also queued for the asynchronous full analysis (worker), alert-only
├─ WebSocket upgrade responses (101) → 204 within the preview, flow marked WEBSOCKET_INVISIBLE_AFTER_UPGRADE (SEC-1)
└─ inter-chunk idle timeout 30 s (engine side); ProxySG's RESPMOD transaction timeout for the AI streaming service is set
     to 300 s (coding-agent streams last 30–120 s; PLAT-F4), UNVERIFIED setting name
```

Why the engine never buffers a whole stream: time-to-first-token would become the whole response time and memory per
stream would be unbounded (Argon P0-4). The one-window delay adds at most 16 KiB of latency (a few milliseconds at
streaming rates) and is what makes "the offending chunk never leaves" true.

### 4.5 Error mapping

| Condition | ICAP status | ProxySG effect (per its fail setting) |
|---|---|---|
| bad ICAP syntax | 400 | ICAP error → fail setting |
| unknown service URI | 404 | fail setting |
| method not allowed on this service | 405 | fail setting |
| engine overloaded or draining (new connections) | 503 | fail setting; OPTIONS also 503 so the engine is deselected |
| internal exception before classification | 500 | fail setting; counted; **never** a 204 |

An internal exception on the REQMOD path after classification is **a verdict (`INSPECTION_FAILED`)** handled by the
ADR-010 flow rule, so a fail-closed flow gets the 403 block page rather than a 500 that ProxySG might fail open (ARCH-6).

## 5. Protocol frame fixtures and drift detection

- `fixtures/icap/<platform>/<surface>/<step>.icap`: sanitized, synthetic-body REQMOD and RESPMOD frames per platform flow,
  replayed by unit tests and by the in-cluster ICAP e2e Job. Mandatory fixtures from the council: a 4 KiB benign prefix
  followed by a secret after the preview boundary → BLOCK (OFF2-1); a secret inside an unknown JSON field → detected
  (OFF2-6); a spoofed `X-Authenticated-Groups` on a plain connection → no exception applied (OFF2-12); a signed older
  snapshot → refused (OFF2-11); a 1 MiB body held at 1 KiB/s → `INSPECTION_TIMEOUT`, pool unaffected (OFF2-10).
- Shape fingerprints pin **required** field paths and content types per flow; a live frame missing a required field
  produces `UNKNOWN_FLOW` and an alert within one minute; extra fields are inspected and counted (OFF2-6). Fingerprints
  change only by reviewed PR.
- Fuzzing: Jazzer targets for the ICAP decoder, `Encapsulated` offsets, chunked decoding, preview and `ieof`, the SSE
  parser, the JSON leaf walker, the normaliser and the response rebuilder (REDACT/BLOCK header and length rewriting);
  corpus committed; a crash or timeout is a HIGH finding (AC-3).

## 6. Timeouts negotiated with ProxySG (phase 0 configuration, UNVERIFIED option names)

ICAP connection timeout 2 s; REQMOD transaction timeout 15 s (covers the 10 s body-receive timeout plus the 2 s decision);
RESPMOD transaction timeout 300 s for the streaming service; health check every 5 s, 2 failures to mark down; `Preview`
honoured; `Allow 204` on; `Transfer-Ignore` from OPTIONS; fail behaviour per ADR-010; Secure ICAP with the client
certificate issued by the proxy team's CA; ICAP object-size rule set to deny.

## 7. Drain (ARCH-5, PLAT-F3)

On `preStop` (20 s window): OPTIONS and the readiness probe answer **503 at once**, so ProxySG and the Service stop
selecting the pod; **transactions that still arrive on pooled or raced connections during the first 15 s are served
normally**, each response carrying `Connection: close`, so every pooled connection ends at a transaction boundary; new
connections are accepted and served the same way during those 15 s (endpoint removal and the ProxySG health-check interval
take up to 5 s to converge). After 15 s new transactions are refused with `503`; the engine exits when in-flight
transactions reach zero or at 20 s. The AC-2 load drill (`DEPLOY_AND_SHARED_HOST_RUNBOOK.md` §1.2) proves zero dropped
transactions.

## 8. Metrics (no raw labels)

`icap_transactions_total{method,service,verdict}`, `icap_fast_path_204_ratio`, `icap_inflight`,
`icap_inflight_by_identity_capped_total`, `icap_fullbody_semaphore_rejections_total`, `icap_queue_depth{queue}`,
`icap_queue_dropped_total{queue}`, `icap_spool_bytes`, `icap_decision_seconds` histogram, `icap_body_bytes` histogram,
`netty_direct_memory_bytes`, `jvm_gc_pause_seconds`, `icap_connections{state,transport}`, `icap_identity_source_total{source}`,
`icap_unknown_flow_total{platform}`, `icap_snapshot_version`. No label ever carries a user, tenant, host, prompt or URL
string.

## 9. Open items for phase 0

ProxySG: Secure ICAP support and client-certificate issuance; WebSocket and HTTP/2 handling; the ICAP object-size rule and
`max_file_size_exceeded` error class; SSE pass-through to RESPMOD (incremental or buffered); REQMOD and RESPMOD transaction
timeout option names and maxima; `X-Authenticated-User` encoding; preview negotiation; whether `Accept-Encoding` stripping
on REQMOD is honoured end to end. Each becomes a row in `PLATFORM_MATRIX.md` §1 with its evidence.
