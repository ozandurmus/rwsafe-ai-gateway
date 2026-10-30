# ADR-005: WebSocket and streaming strategy

Status: PROPOSED
Date: 2026-10-30
Answers: brief 5B (streaming SSE, chunked, WebSocket), 6; council ARCH-4, Argon P0-4, brief 10.6 question 1

## Context

Every target platform streams responses: SSE for web chat and the Anthropic/OpenAI/Google APIs, chunked JSON for some
IDE channels, WebSocket for realtime voice APIs and a few IDE transports. Buffering a response to inspect it whole
destroys time-to-first-token and holds unbounded memory per stream; forwarding without inspection loses visibility.
Requests are not streamed in practice (a prompt is one JSON body), so the asymmetry is natural: block on the way in,
watch on the way out.

## Decision

1. **Requests: strict inline inspection on REQMOD.** The whole request body (up to 4 MiB) is inspected before the
   upstream call; block, redact or allow happens here. This is where enforcement lives.
2. **Streaming responses: sliding-window RESPMOD with abort, one window of delay.** Each 16 KiB window (2 KiB overlap) is
   inspected **before** the previously inspected bytes are forwarded, so an offending window never leaves the engine
   (PLAT-F4); the stream is **aborted** on a high-confidence leak (secret shapes, TCKN/IBAN with checksum, estate
   dictionary, customer-number formats) and, on agentic surfaces (CLI, IDE, MCP), on high-confidence **prompt-injection
   patterns** in returned web content or tool results (OFF2-7; monitor first, then enforce, PO question Q-31). The abort
   is an SSE `error` event with a reference id, written in the stream's encoding; the engine strips `Accept-Encoding` on
   REQMOD for SSE endpoints so streams arrive identity-encoded. Everything is also queued for asynchronous full analysis
   whose verdict raises an alert. Council Q1 recommendation: yes; presented to the PO as OPEN_QUESTIONS Q-1 because the
   brief asked.
3. **Non-streaming responses ≤ 64 KiB with `ieof` in the preview**: whole-body inspection with the same classes; 204 or
   redaction. Anything after `100 Continue` is always an ICAP 200 streamed body (RFC 3507; PLAT-F4).
3a. **Tool results re-enter through REQMOD** (OFF2-7): the next request of an agent loop carries `tool_result`, function
   results and fetched web content; REQMOD runs the injection detectors on those blocks, where blocking is possible
   without any late-abort problem; this is the primary control for response-side injection, RESPMOD abort is the second.
4. **WebSocket**: the upgrade request is a REQMOD decision point (allow/refuse per platform row); after 101 the channel
   is **invisible by protocol** and the flow is marked `WEBSOCKET_INVISIBLE_AFTER_UPGRADE`. Default for AI hosts: refuse
   the upgrade unless the platform matrix row marks the feature sanctioned; the chained proxy (ADR-004) is the only way to
   inspect frames and is not in the MVP.
5. **SSE pass-through correctness**: the engine never re-chunks across SSE event boundaries in a way that merges events;
   it preserves `event:`/`data:` framing, forwards keep-alive comments, honours `Content-Encoding` by inspecting the
   decoded view while forwarding the original bytes when no modification is made, and when it must modify (abort) it
   switches to identity encoding for the remainder.
6. **Gateway streaming**: the LLM API gateway applies the same two rules to its own upstream calls (inspect request fully,
   stream response through a window), so a tool using the gateway and a tool using ProxySG see the same behaviour.

## Alternatives considered

- Full RESPMOD buffering: breaks IDE and CLI usability and bounds nothing (Argon P0-4); rejected.
- No RESPMOD at all: loses response-side visibility and the "responses as an attack path" detection; rejected.
- Inspecting WebSocket frames inline via ICAP: impossible by protocol.

## Consequences

- The RESPMOD path needs a per-stream memory cap and the direct-buffer accounting in the ICAP spec §3.
- A redaction inside a streaming response is **not** offered (only abort): editing already-flushed text is impossible;
  this is stated to the PO. ProxySG's RESPMOD transaction timeout for the streaming service must be 300 s with a 30 s
  inter-chunk idle timeout on the engine, or every long coding-agent response is cut (PLAT-F4).

## Evidence and UNVERIFIED facts

ICAP spec §4.4; Broadcom KBs on WebSocket (259520, 234070). UNVERIFIED: whether ProxySG passes SSE chunks to RESPMOD
incrementally or waits for the full response for `text/event-stream` (phase 0 measurement decides whether RESPMOD can be
used for SSE at all; if ProxySG buffers, RESPMOD for streams is disabled and visibility comes from REQMOD plus the
gateway only).

## Open questions

Q-1.
