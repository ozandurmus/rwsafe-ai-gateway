# ADR-006: Edge SWG and off-net agent strategy

Status: PROPOSED
Date: 2026-10-30
Answers: brief section 2 (Off-network / cloud proxy), 5E; council offensive P1 "agent channel hardening" and "MV3
feasibility spike"; brief 10.5 (MV3 browser-extension feasibility note, included here as §5)

## Context

Users behind Broadcom Edge SWG (cloud) or off the corporate network never pass ProxySG, so ICAP sees nothing. The PO
noted that Edge SWG "probably cannot send ICAP to an on-prem service" and that Check Point uses an agent here. Research
(2026-10-30): no Broadcom document was found describing Cloud SWG as an ICAP **client** toward a third-party on-premises
ICAP server; Broadcom's own cloud DLP integration is the documented path, and the Skyhigh (former Symantec cloud line)
documentation describes the reverse direction (third-party proxy → cloud DLP as the ICAP server). **UNVERIFIED** either
way; phase 0 asks Broadcom support directly. Check Point GenAI Protect is a browser extension (Harmony Browse) that
classifies prompt text in the browser; Microsoft Purview DSPM for AI needs the Purview browser extension on Windows for
third-party AI sites; Prompt Security and others also ship a browser extension deployed by MDM. Chrome Manifest V3 keeps
`webRequestBlocking` only for **policy-installed** (force-installed) extensions (developer.chrome.com migration guide).

## Decision

1. **The agent path is a later phase, designed now, built after the MVP** (ROADMAP). Off-net users are covered until then
   by: vendor tenant settings (ADR-007), the LLM gateway reachable over VPN, and corporate VPN-forced routing where the
   estate already has it (UNVERIFIED).
2. **Agent architecture, in order of preference**:
   - **A. Browser extension, policy-installed (MV3)**, for managed Chrome and Edge profiles: an enterprise force-installed
     extension may use `webRequestBlocking`; request **bodies are not available** to `webRequest` listeners in MV3 (only
     headers), so body inspection uses a content script that wraps `fetch`/`XMLHttpRequest`/`WebSocket` on the allowlisted
     AI origins and submits the outgoing payload to the extension's service worker **before** the request is sent;
     the service worker evaluates a compiled policy snapshot locally (same DLP classes as the data plane, same RE2
     semantics via a WASM build of the detector library) and reports verdicts and metadata to `agent.<corp-domain>`
     over HTTPS with the device's MDM certificate (mTLS). Brittleness is accepted and measured: page-script wrapping
     can be bypassed by a page that captures `fetch` early or uses a worker, so the extension is a **coaching and
     visibility control with best-effort blocking**, never the enforcement of record; enforcement of record stays with
     tenant settings for off-net users. The feasibility spike in §5 settles whether blocking is good enough to call it
     more than that.
   - **B. Endpoint agent (lightweight local proxy)** for IDE and CLI tools off-net: a user-space process on managed
     laptops that sets `HTTPS_PROXY` / `*_BASE_URL` for the AI clients to a loopback listener, terminates TLS with a
     per-device CA installed by MDM for the AI hosts only, runs the same detector library, forwards to the real
     upstream or to the corporate gateway, and reports to the agent channel. No kernel component, no root service beyond
     MDM-installed configuration (offensive P1: no local privilege escalation path).
   - **C. IDE extension hooks**: Claude Code managed settings (`env`, `permissions.deny`, `allowedMcpServers`, hooks),
     Copilot enterprise policies, VS Code `http.proxy` policy: these are configuration, not code, and are the cheapest
     coverage; they are part of ADR-007 and ship in phase 1.
3. **Agent channel hardening** (offensive P1): device attestation through the MDM-issued client certificate (mTLS),
   signed and pinned agent updates (Sigstore-style signature over the package, update server behind the same mTLS),
   per-device short-lived tokens for the reporting API, no shared secret in the extension, server-side rate limits,
   and a kill switch per device. The agent sends **metadata, verdicts and redacted features**, never raw bodies, unless
   the same policy, notice and watermark conditions as ICAP capture hold.
4. **Edge SWG**: phase 0 asks Broadcom whether Cloud SWG can forward the AI category to an on-prem ICAP server or to the
   rwsafe gateway via a cloud-to-on-prem connector; if yes, that becomes the preferred off-net path for browsers and the
   agent stays for pinned and CLI clients. Until answered: UNVERIFIED, and the agent path is the design.
5. **Comparison with vendors** (COMPETITIVE_REFERENCE has the sources): Check Point (browser extension, 700+ data types,
   OCR claimed), Purview (extension + endpoint DLP, Windows-centric), Prompt Security (extension, monitor-then-enforce),
   Netskope and Zscaler (cloud proxy with instance awareness and prompt DLP, no on-prem hop). rwsafe adopts the
   monitor-first rollout and the MDM-deployed extension; it avoids depending on the extension for enforcement.

## 5. Manifest V3 feasibility note (brief 10.5 deliverable)

| Question | Finding | Status |
|---|---|---|
| Can an MV3 extension block requests? | Yes, with `declarativeNetRequest` (declarative, URL/header based) for everyone; with `webRequestBlocking` only when **policy-installed** (Chrome docs) | verified |
| Can it read request bodies in `webRequest`? | `requestBody` is readable in `onBeforeRequest` for form data and raw bytes in MV2; in MV3 the blocking listener for policy-installed extensions still receives `requestBody` when requested (**UNVERIFIED** for current Chrome versions; the spike tests it) | UNVERIFIED |
| Can it modify bodies? | No API modifies a request body; blocking (cancel) is possible, modification only by re-issuing the request from a content script | verified by API surface |
| Content-script interception | wrapping `fetch`, `XMLHttpRequest`, `WebSocket.send`, `navigator.sendBeacon` in the page's main world at `document_start` on allowlisted origins; pages can detect and bypass; service workers of the page are not covered | design |
| Streaming responses | readable via `Response.body` tee in the wrapper; same window logic | design |
| Edge | same Chromium behaviour; Firefox keeps blocking `webRequest` in MV3 (not force-install dependent) | partially verified |
| Verdict | **Feasible as a coaching and visibility control on managed browsers; enforcement of record stays with tenant settings.** The spike (ROADMAP phase 2, 2 weeks) measures block reliability against the BYPASS_CATALOGUE browser rows before the PO decides whether the extension counts as enforcement | — |

## Alternatives considered

- A full endpoint DLP agent with a kernel driver or TLS-intercepting root CA on every laptop: largest attack surface,
  conflicts with the corporate XDR agent (stack matrix), out of proportion for the MVP; rejected for now.
- Relying on Edge SWG's own DLP: a different product's rules, no rwsafe policy registry; kept as a compensating control
  only.

## Consequences

- A third host name `agent.<corp-domain>` and the agent reporting API appear in the architecture as a later component.
- The detector library must compile to WASM (RE2 semantics) to be shared with the extension; this constrains ADR-008.

## Evidence and UNVERIFIED facts

developer.chrome.com "Replace blocking web request listeners" (policy-installed MV3 keeps `webRequestBlocking`);
Check Point GenAI Protect solution brief and Harmony Browse pages; learn.microsoft.com DSPM for AI prerequisites;
help.openai.com 20001323 (pinning). UNVERIFIED: Cloud SWG ICAP-client capability; MV3 `requestBody` availability for
policy-installed extensions; estate VPN routing.

## Open questions

Q-19 (agent path timing and scope: browsers only, or IDE/CLI too), Q-20 (ask Broadcom about Cloud SWG → on-prem ICAP).
