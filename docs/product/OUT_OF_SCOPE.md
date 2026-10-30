# Out of scope for the gateway, with compensating controls

**Status:** DRAFT for design freeze. Answers brief 10.4 (non-goals), 10.5, council SEC-2 and the offensive seat's
"gateway cannot see this" list. A row here is a declared blind spot with a named owner of the compensating control, not an
accepted loss.

## 1. Cloud-side agents never pass the proxy (SEC-2)

| Platform surface | What happens | Why the gateway cannot see it | Compensating control (owner) |
|---|---|---|---|
| Devin (cloud) | the agent runs in the vendor's cloud and pulls repositories from GitHub directly | the user's browser session to the console is the only traffic on the corporate network | Devin Enterprise SSO (Okta/Entra/SAML/OIDC) and admin-controlled repository connections; GitHub organisation policy on which apps may be installed and which repositories they may read (platform admins). rwsafe records the console logins and the tenant (ADR-007) and nothing else |
| OpenAI Codex cloud tasks | same model: cloud container, GitHub app | same | ChatGPT Enterprise workspace controls; GitHub app installation policy; the gateway enforces the workspace header on the console (ADR-007) |
| GitHub Copilot coding agent, Copilot in github.com | runs on GitHub's infrastructure | same | Copilot Enterprise policies (content exclusions, data-residency policy, model allowlist) and EMU; rwsafe enforces the enterprise tenant for the IDE and the web console |
| Claude Code on the web / Claude cloud agents | runs in Anthropic's cloud sandbox | same | Claude Enterprise organisation settings, domain capture and "require SSO", GitHub app scope; rwsafe enforces organisation login on claude.ai (ADR-007) |
| Gemini cloud agents (Jules, Code Assist agent mode in cloud) | Google cloud | same | Workspace/Cloud IAM admin controls; the gateway enforces the Workspace domain header |

Rule: for every cloud-side agent the **enforcement point is the vendor tenant**; rwsafe's platform matrix records the
tenant setting that must be on, the evidence that it is on (a quarterly attestation screenshot described, not stored
raw), and the console-login enforcement rwsafe does provide.

## 2. Clients that pin certificates or bypass the proxy

| Client | Behaviour | Compensating control |
|---|---|---|
| ChatGPT desktop and mobile apps | certificate pinning (OpenAI help: header injection needs pinning exceptions via MDM) | block the app domains at the proxy per OpenAI's guidance, or deploy the MDM pinning exception; decided per platform in ADR-007; the phase-0 trust matrix lists each client |
| Mobile apps in general (Android 7+ ignores user CAs) | TLS inspection impossible | managed devices only, app allowlists in MDM, tenant settings; the gateway records that mobile is log-only |
| Claude Code, Codex CLI, Gemini CLI with `NODE_EXTRA_CA_CERTS`, Rust or Go trust stores | inspectable only if the corporate CA is in that client's trust store | the per-client trust matrix (ROADMAP phase 0) and the managed settings that pin `ANTHROPIC_BASE_URL`-style variables to the rwsafe gateway (ADR-007, UNVERIFIED per client) |
| Direct API use with a personal key from a laptop off VPN | never touches ProxySG | the off-net agent (ADR-006), the gateway as the only sanctioned base URL, DLP on egress is impossible: declared |
| Bedrock, Vertex, third-party relays (`*_BASE_URL` pointed at a relay) | bypass the vendor's org login entirely | tenant check at the Authorization level where visible, a relay blocklist in the policy registry (offensive P1), and the gateway as the only allowed base URL in managed settings |
| QUIC/HTTP/3 | ProxySG does not inspect QUIC | QUIC is blocked at the proxy (UDP 443) so browsers fall back to TCP (standard SWG practice; UNVERIFIED for the estate's ProxySG policy) |

## 3. Traffic ICAP cannot carry (SEC-1 summary; details in PLATFORM_MATRIX.md)

WebSocket frames after the upgrade (the upgrade request is inspectable, the frames are not), HTTP/2-specific features
(ProxySG speaks HTTP/1.1 toward ICAP; UNVERIFIED whether every HTTP/2 client request reaches REQMOD), bodies above
ProxySG's ICAP size limit (configured to **deny** rather than fail open, Broadcom KB 167551), gRPC trailers, and uploads
of archives or images (inspected only as far as `BYPASS_CATALOGUE.md` says: no OCR in the MVP).

## 3a. Storage-integrated and embedded AI (OFF2-13)

Content reaches AI through integrations the ICAP category does not see: Drive attachments to Gemini, SharePoint and
OneDrive to M365 Copilot, repositories to Copilot and Codex cloud, Slack to Devin; and Gemini in Workspace apps or Copilot
in Office share domains with the non-AI product. Compensating controls: the vendors' own DLP (Workspace DLP, Purview,
GitHub app installation policy), tenant settings, and an explicit phase-0 decision on which collaboration domains join
the ICAP category. These surfaces are marked T or L in the platform matrix.

## 4. People and use outside scope (PO decision Q-6)

Contractors on unmanaged devices, BYOD, and personal AI use on personal devices are outside the gateway unless the PO
brings them in through the agent path; the privacy seat's recommendation is "personal use blocked on corporate network,
nothing captured about it beyond the block event".

## 5. Explicit non-goals of the product

- Not a general web DLP or CASB for non-AI SaaS (the ICAP service applies to the AI category only).
- Not an AI model host, not a vector store, not a RAG platform.
- Not a replacement for vendor tenant administration.
- Not a code-scanning tool for repositories at rest.
- Not an endpoint agent for every laptop in the MVP; the agent path is a later phase (ADR-006).
