# ICAP and streaming protocol specification

**Status:** DRAFT for design freeze. Answers brief 10.5 (this document), council ARCH-4, ARCH-5, ARCH-6, Argon P0-4,
P0-5, offensive seat "ReDoS and parser DoS", SEC-1, SEC-3. Normative references: RFC 3507 (ICAP/1.0), RFC 3507 errata and
the ICAP Extensions draft (`X-Client-IP`, `X-Authenticated-User`, `X-Server-IP`), RFC 9112 (HTTP/1.1), the WHATWG/HTML
living standard for `text/event-stream`, RFC 6455 (WebSocket), RFC 7540/9113 (HTTP/2). ProxySG-specific behaviour is
marked and is **verified in phase 0 against the installed SGOS version** (every such item is UNVERIFIED until then).

## 1. Scope and non-goals

The engine `rwsafe-icap` is an ICAP/1.0 server (RFC 3507) implemented on Netty, serving ProxySG as its only intended
client. It implements OPTIONS, REQMOD and RESPMOD with Preview, `100 Continue`, `204 No Content` and `206 Partial
Content` (RFC 3507 does not define 206; ProxySG's behaviour with partial modification is UNVERIFIED, so rwsafe never
sends it), `Encapsulated` parsing, chunked HTTP bodies, `Allow: 204`, `ieof`, keep-alive connections and `Connection:
close` drain. It does not implement ICAP over HTTP/2, FTP RESPMOD, or `X-Include` extensions. Non-HTTP traffic
(WebSocket after the upgrade, raw TCP tunnels, QUIC) is out of ICAP scope by protocol; ADR-004 and ADR-005 say what
covers it.

## 2. Transport and trust (SEC-3)

| Item | Rule |
|---|---|
| Listeners | 1344 plain ICAP (pilot only, HARDENING_EXCEPTIONS H-2), 11344 Secure ICAP: TLS 1.2+/1.3 with **mutual authentication**; the ProxySG client certificate chain is pinned to the proxy team's CA, which lives in a Secret |
| Source allowlist | the NetworkPolicy and the engine itself accept connections only from the ProxySG addresses (uncommitted ConfigMap); any other source gets a TCP close and a counter |
| Identity | `X-Authenticated-User` (base64 of `LDAP://` or `WinNT://` URI, per the ICAP Extensions draft and ProxySG's `X-Authenticated-User` format, UNVERIFIED exact encoding) and `X-Authenticated-Groups` are **claims of the proxy**. Every record carries `identity_source=proxy_claim`, the connection's authentication state (`mtls_verified`, `plain_allowlisted`) and the surrogate type ProxySG used when it can be inferred from `X-Client-IP` (shared addresses from VDI/terminal-server ranges, configured per estate, mark the record `identity_shared_address`). A missing or malformed identity header selects the anonymous policy (ADR-010) |
| Client address | `X-Client-IP` is used for the surrogate classification and the per-user volume thresholds (SEC-4), never stored raw: it is masked by the subnet-preserving masker before persistence |
| Clock | ICAP has no timestamps; the engine stamps receipt time in UTC |

## 3. Connection and buffer limits (ARCH-4, ARCH-6)

| Limit | Default | Behaviour on breach |
|---|---|---|
| Connections per engine | 2 000 | TCP accept backlog; above the limit new connections are refused (ProxySG retries another engine) |
| Connections per source address | 512 | refuse, counter |
| Idle connection timeout | 300 s (ProxySG keeps pooled connections; UNVERIFIED pool idle default) | close |
| ICAP header section | 32 KiB total, 8 KiB per header line, 64 headers | `400 Bad Request` ICAP, connection closed |
| Encapsulated HTTP header section | 64 KiB | `400`, verdict `MALFORMED` (no silent allow) |
| Preview | engine advertises `Preview: 4096` (4 KiB); accepts any preview ProxySG sends up to 64 KiB | |
| REQMOD body held in memory | **4 MiB** (`MAX_REQMOD_BODY`) | beyond: verdict `OVERSIZE` per ADR-010; the body is drained to `/dev/null` (not stored), the decision is made on the first 4 MiB and the structured fields |
| RESPMOD window | 16 KiB sliding window, 2 KiB overlap; never more than 64 KiB of a response in memory per transaction | |
| Direct memory | `-XX:MaxDirectMemorySize=512m` per engine pod; Netty pooled allocator with a 1 MiB per-connection cap (`maxInFlightBytesPerConnection`) | a connection over its cap is paused (TCP backpressure); the pool over 90 % refuses new transactions with ICAP `503` (ProxySG applies its fail setting) |
| Decompression | gzip/deflate/br of encapsulated bodies only when `Content-Encoding` says so, output capped at 8× input and at `MAX_REQMOD_BODY`; nested encodings not decoded | verdict `OVERSIZE` or `MALFORMED` |
| JSON nesting | 64 levels, 10 000 fields | `MALFORMED` |
| Base64 / nested decoding for DLP normalisation | depth 2, 2 MiB decoded | stop decoding, mark `PARTIAL_INSPECTION` |
| Regex | RE2/J only; patterns compiled at snapshot load; a pattern over 10 000 program steps is refused at load | no inline `java.util.regex` (ArchUnit) |
| Transaction time | REQMOD decision within 2 s wall clock, RESPMOD per chunk within 200 ms | on breach: verdict `INSPECTION_TIMEOUT` → ADR-010 class rule; the transaction never hangs ProxySG past its own timeout |
| In-flight transactions per engine | 1 000 | ICAP `503 Service Unavailable` beyond; metric |

## 4. The ICAP state machine

### 4.1 Connection states

```
ACCEPTED ──(TLS handshake, mTLS verified or plain allowlisted)──► READY
READY ──(request line)──► PARSING_HEADERS ──► {OPTIONS | REQMOD | RESPMOD}
after a transaction: ──(keep-alive)──► READY | ──(Connection: close | drain)──► CLOSING ──► CLOSED
any parse error ──► ERROR(4xx, Connection: close) ──► CLOSED
```

### 4.2 OPTIONS

Response: `ICAP/1.0 200 OK`, `Methods: REQMOD` or `RESPMOD` per service URI (`/reqmod-ai`, `/respmod-ai`), `Service:
rwsafe-ai-gateway/<version>`, `ISTag: "<policy-snapshot-id>"` (changes when the compiled policy changes, so ProxySG
re-validates), `Encapsulated: null-body=0`, `Max-Connections: 1000`, `Options-TTL: 300`, `Preview: 4096`, `Allow: 204`,
`Transfer-Preview: *`, `Transfer-Ignore: jpg,jpeg,gif,png,webp,woff,woff2,mp4` (RESPMOD only), `Transfer-Complete:` (none).
OPTIONS is the health check: it answers **503** when the engine has no snapshot, is draining, or its queue is at the
fail threshold, so ProxySG stops selecting it.

### 4.3 REQMOD (the enforcing path)

```
REQMOD request line + ICAP headers
  Encapsulated: req-hdr=0, req-body=N | null-body=N
  Preview: P (optional)
  Allow: 204
  X-Client-IP, X-Server-IP, X-Authenticated-User, X-Authenticated-Groups
┌─ parse encapsulated HTTP request headers (method, URL, Host, Authorization/Cookie presence, Content-Type, Content-Length)
├─ classify flow: platform × surface (web, IDE, CLI, API) × step (login, chat, upload, tool-call, other) from the
│    platform matrix; unknown platform+step → UNKNOWN_FLOW (protocol drift) → ADR-010
├─ identity + tenant rule (ADR-007): login/OAuth steps are decided on headers alone
├─ if Preview present:
│     decide early when possible (allow → 204 within the preview; block → ICAP 200 with an HTTP 403 block page;
│     redact or need-more → "ICAP/1.0 100 Continue", read the rest up to MAX_REQMOD_BODY)
│     "ieof" in the preview means the whole body was in the preview
├─ full body available: normalisation (SEC-4), deterministic DLP classes, platform-specific field extraction
│    (messages[], contents[], input, tools, system prompt), tenant-at-token level where visible
├─ verdict ∈ {ALLOW, WARN, REDACT, BLOCK, OVERSIZE, MALFORMED, INSPECTION_FAILED, INSPECTION_TIMEOUT, UNKNOWN_FLOW}
│    action per policy registry entry and ADR-010 class rule
├─ emit capture event (metadata always; redacted features/digests; raw body only if the policy, notice-acceptance and
│    watermark allow) to the bounded async queue; emit verdict event (never dropped)
└─ respond:
     ALLOW ─────────────► ICAP/1.0 204 No Content
     WARN  ─────────────► 204 (the warning is delivered out of band: coaching page on the next web navigation,
                           IDE notification channel, or the SIEM; a WARN on a login step is a 200 + interstitial)
     REDACT ────────────► ICAP/1.0 200 OK, Encapsulated: req-hdr, req-body: the rewritten request with the sensitive
                           spans replaced by class tokens ([REDACTED:TCKN], [REDACTED:SECRET]), Content-Length fixed
     BLOCK ─────────────► ICAP/1.0 200 OK, Encapsulated: res-hdr, res-body: HTTP 403 with the Turkish block/coaching
                           page (HTML for browsers, JSON {"error":{"type":"rwsafe_blocked",...}} for API clients by
                           Accept/Content-Type), X-RWSAFE-Reason: <class>, X-RWSAFE-Ref: <correlation id>
     OVERSIZE/MALFORMED/INSPECTION_FAILED/TIMEOUT/UNKNOWN_FLOW ─► the ADR-010 action, same encodings as above
```

A REQMOD decision is made **once**; the engine never issues a second ICAP request or contacts the control plane
synchronously. The compiled snapshot is the only input besides the request.

### 4.4 RESPMOD (the visibility path, sliding window)

```
RESPMOD request: Encapsulated: req-hdr=0, res-hdr=N, res-body=M ; Preview: P
┌─ parse the original request headers and the response headers (status, Content-Type, Transfer-Encoding)
├─ Transfer-Ignore types → 204 immediately (ProxySG does not even send them after OPTIONS)
├─ non-streaming JSON ≤ 64 KiB: whole-body inspection (same classes as REQMOD) → 204 or 200 with redaction
├─ streaming (text/event-stream, or chunked with unknown length, or application/x-ndjson, or anthropic/openai
│    stream formats): SLIDING WINDOW MODE
│     ICAP/1.0 100 Continue after the preview; then for each received chunk:
│       append to window (16 KiB, 2 KiB overlap kept from the previous window)
│       run the high-confidence leak detectors only (secret shapes, TCKN/IBAN with checksum, the estate dictionary,
│         customer-number formats): deterministic, ≤ 200 ms
│       forward the chunk to ProxySG unchanged (ICAP 200 body streamed as it arrives: the engine is a pass-through
│         with inspection, never a store-and-forward)
│       on a HIGH-CONFIDENCE hit: ABORT the stream: send a final SSE event `event: error` with
│         data: {"type":"rwsafe_stream_terminated","reason":"<class>","ref":"<id>"} , close the encapsulated body,
│         verdict STREAM_ABORTED (what already left cannot be recalled: recorded as `bytes_forwarded_before_abort`)
│       every chunk's text is also queued (redacted later by the worker) for the asynchronous full analysis
│         (prompt injection coming back from web content or tools, SEC "responses as an attack path"), whose verdict is
│         recorded after the fact and raises an alert, never a block
├─ WebSocket upgrade responses (101) → 204, flow marked WEBSOCKET_INVISIBLE_AFTER_UPGRADE (SEC-1)
└─ response: 204 when nothing changed and the body fits the window rules; otherwise 200 with the streamed body
```

Why the engine never buffers a whole stream: time-to-first-token for IDE and CLI clients would become the whole response
time (30–120 s) and the memory per concurrent stream would be unbounded (Argon P0-4). The PO question Q-1 ("strict
REQMOD, sliding-window RESPMOD with abort") is this design.

### 4.5 Error mapping

| Condition | ICAP status | ProxySG effect (per its fail setting) |
|---|---|---|
| bad ICAP syntax | 400 | ICAP error → fail setting |
| unknown service URI | 404 | fail setting |
| method not allowed on this service | 405 | fail setting |
| engine overloaded or draining | 503 | fail setting; OPTIONS also 503 so the engine is deselected |
| internal exception | 500 | fail setting; counted; **never** a 204 |

An internal exception on the REQMOD path is **a verdict (`INSPECTION_FAILED`)**, so for fail-closed classes the engine
sends the 403 block page rather than a 500 that ProxySG might fail open (ARCH-6); the 500 row applies only before the
request could be classified.

## 5. Protocol frame fixtures and drift detection

- `fixtures/icap/<platform>/<surface>/<step>.icap`: sanitized, synthetic-body REQMOD and RESPMOD frames per platform flow
  (brief 10.4), replayed by the unit tests and by the in-cluster ICAP e2e Job.
- Each platform's request and response schema is pinned by a **shape fingerprint** (field paths, content types, SSE event
  names); a live frame whose fingerprint is unknown produces `UNKNOWN_FLOW` and an alert within one minute
  (protocol-drift detection). Fingerprints are updated by a reviewed PR, never learned in production.
- Fuzzing: Jazzer targets for the ICAP line/header decoder, `Encapsulated` offsets, chunked decoding, preview and `ieof`
  handling, the SSE parser, the JSON field extractor and the normaliser; the corpus is committed and runs in the ship
  gate; a crash or a timeout is a HIGH finding (AC-3).

## 6. Timeouts negotiated with ProxySG (phase 0 configuration, UNVERIFIED defaults)

ProxySG ICAP connection timeout 2 s, transaction timeout 5 s (REQMOD) and 30 s (RESPMOD streaming), health check every
5 s with 2 failures to mark down, `Preview` honoured, `Allow 204` on, `Transfer-Ignore` from OPTIONS, fail behaviour per
ADR-010, `Secure ICAP` with the client certificate issued by the proxy team's CA. The exact SGOS option names are
recorded in the platform matrix after phase 0.

## 7. Drain (ARCH-5)

On `preStop`: OPTIONS answers 503; no new transactions are accepted (new connections are closed after `ICAP/1.0 503`);
every in-flight response carries `Connection: close`; the engine waits until in-flight transactions reach zero or 20 s
elapse, then exits 0. ProxySG's pooled connections therefore end at a transaction boundary. The AC-2 load test
(`DEPLOY_AND_SHARED_HOST_RUNBOOK.md` §1.2) proves zero dropped transactions.

## 8. Metrics (no raw labels)

`icap_transactions_total{method,service,verdict}`, `icap_fast_path_204_ratio`, `icap_inflight`, `icap_queue_depth{queue}`,
`icap_queue_dropped_total{queue}`, `icap_decision_seconds` histogram, `icap_body_bytes` histogram, `netty_direct_memory_bytes`,
`jvm_gc_pause_seconds`, `icap_connections{state}`, `icap_identity_source_total{source}`, `icap_unknown_flow_total{platform}`.
No label ever carries a user, tenant, host, prompt or URL string (brief 10.4 self-observability).

## 9. Open items for phase 0

ProxySG: Secure ICAP support and client-certificate issuance; WebSocket and HTTP/2 handling (whether the proxy
downgrades to HTTP/1.1 toward ICAP, whether upgrade requests reach REQMOD); maximum ICAP object size and the
`max_file_size_exceeded` error class behaviour (Broadcom KB 167551 describes fail-open on size with the default error
handling; the policy must be set to deny); `X-Authenticated-User` encoding for the estate's authentication realm;
preview size negotiation. Each becomes a row in `PLATFORM_MATRIX.md` §"ProxySG capabilities" with its evidence.
