# ADR-004: ICAP versus chained proxy versus agent, per traffic type

Status: PROPOSED
Date: 2026-10-30
Answers: brief section 2 (Inline inspection), 4 rule 3 (optional chained forward proxy), 5B, 5E; council SEC-1, SEC-2,
Argon "protocol coverage" P0; PLATFORM_MATRIX §3

## Context

ProxySG with SSL interception is the PO's primary inline path and ICAP the expected integration. ICAP carries HTTP/1.1
request and response messages; it does not carry WebSocket frames after an upgrade, non-HTTP tunnels or QUIC. Some
clients pin certificates and some users are off the corporate network (Edge SWG). The brief asks for a chained forward
proxy option for WebSocket and an agent option for off-net users.

## Decision

| Traffic type | Primary control | Why | Fallback |
|---|---|---|---|
| Browser HTTPS to AI web apps (chat POST, uploads, logins) | **ICAP REQMOD + RESPMOD** from ProxySG | the designed path; blocks and redacts inline; tenant headers are injected by ProxySG itself where the vendor supports them (ADR-007) | agent (ADR-006) for off-net |
| IDE and CLI HTTPS to AI APIs through the proxy | **ICAP REQMOD + RESPMOD** | same wire shape as the web; client trust store must contain the corporate CA (trust matrix) | gateway as the client's base URL (next row) |
| API-key based tools (SDKs, CLIs with `*_BASE_URL`) | **LLM API gateway** (`ai-api.<corp-domain>`) | corporate keys stay server-side; per-team quota and cost; the gateway inspects without ICAP; also works off-net with the agent or VPN | ICAP catches a tool that still goes direct with a personal key (REQMOD blocks non-corporate keys) |
| WebSocket to AI hosts (Realtime voice APIs, some IDE channels) | **block the upgrade at REQMOD** for AI hosts unless a platform row needs it | the frames are invisible to ICAP by protocol; an invisible channel to an AI vendor is a blind spot, so the default is to refuse it (SEC-1) | **chained forward proxy on 3128** only if phase 0 shows a sanctioned WebSocket need (e.g. a vendor's IDE channel): ProxySG forwards the AI category to rwsafe's proxy, which terminates TLS, inspects frames with the same engine, and forwards upstream; a last resort because it doubles TLS termination and makes rwsafe a transit proxy |
| HTTP/2 | ICAP via ProxySG's HTTP/1.1 encapsulation (UNVERIFIED) | KB 441957 pattern: force HTTP/1.1 for AI domains if needed | — |
| Pinned apps (ChatGPT desktop/mobile, others) | **domain block at ProxySG** or MDM pinning exception, per platform row | vendor guidance (OpenAI) | agent on managed devices |
| Off-net and Edge SWG users | **agent path** (ADR-006) | no inline hop exists | tenant settings (OUT_OF_SCOPE) |
| Cloud-side agents | **tenant settings** | the traffic never crosses the corporate network | — |
| Uncategorised domains and selected broad categories | ProxySG sends them to REQMOD in **header-only metadata mode** (no body capture, 30-day retention of C1): rwsafe fingerprints AI API shapes (`anthropic-version`, `/v1/messages`, `/v1/chat/completions`, SSE accept, `x-api-key`, `Authorization: Bearer sk-`) to detect relays and new AI hosts, which feed the AI-domain list in the policy registry and the shadow-AI inventory (OFF2-5; PO question Q-30). ProxySG itself cannot know that a new domain is AI, so "uncategorised → inspect" is implemented by this mode, not by a category rule | SEC-7, OFF2-5 | — |

The chained forward proxy is therefore **designed but not built in the MVP**: its interface (a CONNECT proxy on 3128
using the same inspection engine and policy snapshot) is specified so it can be added without changing the data model;
phase 0 decides whether any sanctioned WebSocket flow justifies it (OPEN_QUESTIONS Q-18).

## Alternatives considered

- Chained proxy for everything (ProxySG → rwsafe proxy → Internet): rwsafe becomes a second full proxy with its own TLS
  termination, certificate issuance and availability burden; ICAP already gives ProxySG-side fail behaviour, health
  checks and connection pooling; rejected as the primary path.
- Agent for everyone from day one: the largest new attack surface (offensive P1), no ICAP leverage; rejected as primary,
  kept for off-net.
- ICAP RESPMOD only (visibility without enforcement): fails job 3; rejected.

## Consequences

- Phase 0 must measure: the share of AI traffic over WebSocket, the clients that fail with interception, HTTP/2
  behaviour toward ICAP.
- The engine is written once (Netty, RE2/J, policy snapshot) and hosted behind two front ends (ICAP server; later the
  CONNECT proxy and the gateway).

## Evidence and UNVERIFIED facts

Broadcom KBs 259520, 234070, 174021, 441957, 167551, 167742, 169182 (read 2026-10-30, see PLATFORM_MATRIX §1).
UNVERIFIED: HTTP/2 → ICAP encapsulation behaviour; estate QUIC policy.

## Open questions

Q-18 (build the chained proxy after phase 0?).
