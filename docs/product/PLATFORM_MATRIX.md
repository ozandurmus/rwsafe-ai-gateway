# Platform matrix: domains, auth flows, controls, blind spots, evidence

**Status:** DRAFT for design freeze. Answers brief 5A (per-platform matrix), 5B (surfaces), 10.4 (per-client trust),
council SEC-1 (blind-spot matrix), SEC-2 (cloud-side agents), PRIV-3 (data region, DPA, zero retention), ADR-004,
ADR-005, ADR-007. Every vendor fact carries its evidence; **UNVERIFIED** means no primary source was read for it and the
phase-0 task that verifies it is named. Domain lists are vendor-published endpoints, not estate identifiers. Dates:
evidence read 2026-10-30.

Legend for enforcement: **E** enforceable inline (REQMOD can block or rewrite), **L** log-only (visible, cannot be
changed in time), **I** invisible to ICAP (compensating control named), **T** tenant-side setting (vendor admin).

## 1. ProxySG capabilities that bound every row (phase 0 verifies against the installed SGOS)

| Capability | What the evidence says | Status |
|---|---|---|
| ICAP REQMOD/RESPMOD with Preview, 204, fail open/closed per service | Broadcom KB 167742: RESPMOD fail_open applies on connection error, 4xx/5xx and health-check failure; KB 169182: `fail_open` catches every ICAP error unless `icap_error_code` triggers (e.g. `max_file_size_exceeded`) are matched; KB 167551: with "continue without further ICAP processing" an oversize file is served, so the rule must be deny | verified from KB; exact VPM/CPL for the estate: phase 0 |
| Secure ICAP (TLS) | Symantec TECH248146: ICAPS supported; certificate imported as CA, service switched from plain to Secure ICAP; port 11344 convention; performance overhead noted | verified from KB; **mTLS client certificate from ProxySG: UNVERIFIED** |
| WebSocket | KB 259520: WebSocket over HTTP/1.1 supported in SGOS 7.3.x without extra configuration; the session is labelled WebSocket only when intercepted; KB 234070: WebSocket over HTTP/2 is **not** supported, browsers fall back to HTTP/1.1 or a CPL rule disables HTTP/2 for the domain | ICAP sees the **upgrade request** (REQMOD) and the 101 response; frames after the upgrade are **not** ICAP traffic by protocol → I |
| HTTP/2 | KB 174021: HTTP/2 supported on 7.x; 7.3.19.x release notes: `http2.server.request(preserve)`; KB 441957: parse errors during interception fixed by forcing HTTP/1.1 or excluding from interception | whether every HTTP/2 client request reaches REQMOD as HTTP/1.1 encapsulation: **UNVERIFIED** (phase 0 measurement with a fixture client) |
| QUIC / HTTP/3 | not inspected by ProxySG (standard SWG posture) | block UDP 443 so clients fall back: **UNVERIFIED** for the estate's policy |
| Large bodies | ICAP max object size is a ProxySG setting; default behaviour fail-open with the default error handling (KB 167551) | set to deny for the AI category; rwsafe's own 4 MiB REQMOD limit is below it |
| Identity to ICAP | `X-Authenticated-User`, `X-Authenticated-Groups`, `X-Client-IP` (ICAP extensions) | header encoding for the estate's realm: **UNVERIFIED** |
| SSL interception bypass list | the estate's list is read-only audited in phase 0 (SEC-7); the offensive seat expects googleapis, GitHub and M365 exemptions that would blind Gemini and Copilot | phase 0 deliverable |

## 2. Per-platform matrix

Columns: surfaces; domains (vendor-published); auth flow; tenant control (the best available, in brief 5A's order: proxy
header → ICAP on the login flow → endpoint/managed settings); content inspection (REQMOD/RESPMOD by surface); streaming
and protocol; pinning and CA trust; cloud-side execution; data region and DPA; evidence.

### 2.1 Claude (claude.ai, Claude Code, Anthropic API)

| Aspect | Finding |
|---|---|
| Surfaces | claude.ai web; Claude desktop app; Claude Code CLI and IDE extensions; Anthropic API (SDKs); Claude Code on the web (cloud) |
| Domains | `claude.ai`, `api.anthropic.com`, `console.anthropic.com`, `statsig.anthropic.com` (telemetry); `code.claude.com` (docs) — list to be confirmed from the vendor's egress documentation (**UNVERIFIED** completeness) |
| Auth flow | claude.ai: OAuth/SSO session cookie; Claude Code: `claude.ai` OAuth (subscription) or Console API key; API: `x-api-key` header |
| Tenant control | **No proxy header for tenant restriction is documented** (UNVERIFIED: none found). Vendor-side: Enterprise **domain capture** (claim and migrate personal accounts on a verified domain; new accounts on the domain go through SSO only), **Require SSO**, and "prevent users from creating new Claude or Console organizations using any of your verified domains" (support.claude.com 14625619, 10276682). Endpoint: Claude Code managed settings `forceLoginMethod` (`claudeai`/`console`), `forceLoginOrgUUID`, `allowedProviders`, `env` (lockable per variable), `allowedMcpServers`/`allowManagedMcpServersOnly`, `permissions.deny`, `disableBypassPermissionsMode`, `strictKnownMarketplaces`; login keys are taken from the device policy ahead of server-managed settings (code.claude.com managed-settings, read 2026-10-30). rwsafe inline: **ICAP on the login flow** can block a sign-in whose identity is not on the corporate domain (E for web, UNVERIFIED for the OAuth device flow of the CLI); **API-key requests whose key is not a corporate key are blocked at the gateway** (ADR-007): the gateway is the only allowed `ANTHROPIC_BASE_URL`, set and locked through managed settings `env` |
| Content inspection | web chat: JSON POST to the conversation endpoints → E (REQMOD), SSE response → L (RESPMOD window); Claude Code: `POST /v1/messages` with `stream: true` → E/L; API through the gateway → E (gateway inspects before forwarding) |
| Streaming | SSE (`text/event-stream`) on both web and API; HTTP/1.1 and HTTP/2 |
| Pinning and CA | web and CLI (Node) accept the system/`NODE_EXTRA_CA_CERTS` trust; desktop app pinning **UNVERIFIED**; the CLI honours `HTTPS_PROXY` |
| Cloud-side | Claude Code on the web and cloud agents run in Anthropic's cloud → T (OUT_OF_SCOPE §1) |
| Data region, DPA, retention | Enterprise/API: zero data retention available on request; regions: **UNVERIFIED** (PRIV-3 row to be filled from the enterprise contract) |
| Evidence | support.claude.com articles 14625619 and 10276682; code.claude.com/docs/en/managed-settings (fetched 2026-10-30) |

### 2.2 GitHub Copilot (VS Code, JetBrains, CLI, github.com)

| Aspect | Finding |
|---|---|
| Surfaces | IDE extensions (VS Code, JetBrains, Visual Studio, Neovim), Copilot CLI, github.com chat, Copilot coding agent (cloud) |
| Domains | `github.com`, `api.github.com`, `copilot-proxy.githubusercontent.com`, `api.githubcopilot.com`, `*.githubcopilot.com`, `default.exp-tas.com`; data-residency enterprises: `<subdomain>.ghe.com`, `api.<subdomain>.ghe.com` (docs.github.com data residency; completeness **UNVERIFIED**) |
| Auth flow | GitHub OAuth device flow from the IDE, then Copilot session tokens; github.com session cookie |
| Tenant control | **No proxy header documented** (UNVERIFIED: none found). Vendor-side: **Enterprise Managed Users** (identity provider controls accounts; managed users cannot buy Copilot Individual), GHE.com data-residency tenancy, Copilot policies (content exclusions GA for app and CLI per changelog 2026-09-02, "Restrict Copilot to data residency compliant models", model allowlists). rwsafe inline: the IDE's OAuth login to `github.com` is inspectable → ICAP can block a device-flow completion for a user not in the enterprise (E, **UNVERIFIED** exact endpoint shape); Copilot API calls carry a token whose enterprise membership is not visible on the wire → L. For GHE.com tenants, **routing by host** is decisive: allow `*.ghe.com` for the corporate subdomain and block Copilot API hosts for github.com personal use (E by domain) |
| Content inspection | completions and chat: JSON over HTTPS to `api.githubcopilot.com` → E (REQMOD); SSE responses → L |
| Streaming | SSE; HTTP/2 commonly (IDE clients) |
| Pinning and CA | VS Code and the Copilot extension honour `http.proxy` and the OS trust store (`http.proxyStrictSSL`); JetBrains uses the JVM `cacerts` (corporate CA must be imported) → per-client trust matrix in phase 0 |
| Cloud-side | Copilot coding agent and Copilot in github.com run on GitHub → T |
| Data region, DPA, retention | data-residency policy keeps inference in the US or EU region (docs.github.com); Copilot Business/Enterprise: prompts not retained for training (vendor claim, **UNVERIFIED** against the contract) |
| Evidence | docs.github.com data-residency pages; github.blog changelog 2026-09-02 (content exclusions) |

### 2.3 OpenAI: ChatGPT and Codex

| Aspect | Finding |
|---|---|
| Surfaces | chatgpt.com web; desktop and mobile apps; Codex CLI and IDE extension; Codex cloud tasks; OpenAI API |
| Domains | `chatgpt.com`, `chat.openai.com` (redirect), `auth.openai.com`, `api.openai.com`, `platform.openai.com`, app domains per OpenAI's network article |
| Auth flow | ChatGPT: OpenAI login/SSO session; Codex CLI: ChatGPT sign-in or API key; API: `Authorization: Bearer` |
| Tenant control | **Proxy header exists**: `ChatGPT-Allowed-Workspace-Id: <id>[,<id>]` injected on `chatgpt.com` requests; requests for other workspaces (personal included) are filtered, 403 when none remains; anonymous use blocked by blocking the `backend-anon` URL prefix; desktop and mobile apps use **certificate pinning**, so either block the app domains or deploy MDM pinning exceptions (help.openai.com 20001323). → **E (header on ProxySG)**, verified from the vendor article. API: corporate keys only through the gateway (ADR-007); `OPENAI_BASE_URL` locked to the gateway where the client allows (Codex CLI config **UNVERIFIED**) |
| Content inspection | web: JSON POST → E; SSE → L; Codex CLI: API JSON → E via gateway or REQMOD |
| Streaming | SSE; the Responses API also streams; WebSocket is used by the Realtime API (voice) → I after upgrade |
| Pinning and CA | web: none; **apps pinned** (vendor statement); Codex CLI (Rust) trust store: **UNVERIFIED** |
| Cloud-side | Codex cloud tasks → T |
| Data region, DPA, retention | ChatGPT Enterprise: no training on business data (vendor claim); EU data residency option exists (**UNVERIFIED** for Türkiye-relevant terms) |
| Evidence | help.openai.com/articles/20001323 (read 2026-10-30) |

### 2.4 Devin

| Aspect | Finding |
|---|---|
| Surfaces | web console (app.devin.ai), Slack/IDE integrations; execution in Devin's cloud |
| Domains | `app.devin.ai`, `api.devin.ai`, `docs.devin.ai` (**UNVERIFIED** completeness) |
| Auth flow | Devin Enterprise SSO: Okta, Entra ID, SAML, generic OIDC; JIT account creation; no SCIM (docs.devin.ai enterprise SSO guide) |
| Tenant control | no proxy header (none documented). → **T** (SSO-only enterprise, admin-controlled repository connections) plus **ICAP on the console login**: a login that does not go through the corporate IdP can be blocked (E for the web login step, **UNVERIFIED** flow shape) |
| Content inspection | console chat → E/L for what the browser sends; **the agent's work happens in Devin's cloud against GitHub** → I (OUT_OF_SCOPE §1) |
| Cloud-side | yes, entirely |
| Data region, DPA | **UNVERIFIED** |
| Evidence | docs.devin.ai (enterprise getting started, SSO guide) |

### 2.5 Windsurf (Codeium)

| Aspect | Finding |
|---|---|
| Surfaces | Windsurf editor, JetBrains plugin; now documented under docs.devin.ai (Windsurf is part of Cognition) |
| Domains | `windsurf.com`, `codeium.com` legacy, `server.codeium.com` / `*.codeium.com` API (**UNVERIFIED** completeness) |
| Auth flow | Windsurf account or enterprise SSO (Admin Portal: SSO, SCIM, RBAC, IdP group → team mapping, MCP access toggles) |
| Tenant control | no proxy header; **T** (SSO + SCIM + Admin Portal policies) plus ICAP on the login step (E, UNVERIFIED flow); enterprise plans offer self-hosted or dedicated deployments → the API host itself can be allowlisted (E by domain) |
| Content inspection | editor to API: gRPC-over-HTTP/2 or JSON (**UNVERIFIED**: Codeium's language-server protocol); if gRPC with trailers → L or I (SEC-1) |
| Pinning and CA | the language server binary's trust store: **UNVERIFIED** |
| Evidence | docs.devin.ai/windsurf/plugins/guide-for-admins; docs.windsurf.com |

### 2.6 Google Gemini (Gemini app, Gemini Code Assist, Gemini API)

| Aspect | Finding |
|---|---|
| Surfaces | gemini.google.com web and app; Gemini in Workspace apps; Gemini Code Assist (VS Code, JetBrains, Cloud Shell); Gemini CLI; Gemini API / Vertex AI |
| Domains | `gemini.google.com`, `accounts.google.com`, `*.googleapis.com` (incl. `generativelanguage.googleapis.com`, `cloudcode-pa.googleapis.com`, `aiplatform.googleapis.com`), `oauth2.googleapis.com` |
| Auth flow | Google account session (accounts.google.com); Code Assist: Google Cloud OAuth; API: API key or OAuth |
| Tenant control | **Proxy header exists**: `X-GoogApps-Allowed-Domains: <domain>[,<domain>]` on traffic to `*.google.com` with SSL interception; omitting `consumer_accounts` blocks Gmail-type accounts; Google recommends a proxy policy so users cannot insert their own header; blocked users see "This account is not allowed to sign in within this network"; Google states it blocks sign-in to consumer services other than Search but does not necessarily prohibit anonymous access (support.google.com/a/answer/1668854). Whether the header governs `gemini.google.com` specifically: **UNVERIFIED** (phase 0 test). Code Assist: Google Cloud IAM / Workspace policies → T. API keys: gateway only (ADR-007) |
| Content inspection | web: JSON/batchexecute POSTs → E (the request format is proprietary; shape fingerprint needed); SSE/chunked responses → L; Code Assist and CLI: JSON to googleapis → E |
| Streaming | SSE and chunked JSON; HTTP/2 (googleapis) |
| Pinning and CA | browsers: none; Gemini CLI (Node): `NODE_EXTRA_CA_CERTS`; Code Assist in JetBrains: JVM cacerts |
| Cloud-side | Jules and agent mode in cloud → T |
| Data region, DPA | Workspace/Cloud DPA; regions: **UNVERIFIED** for Gemini app |
| Evidence | support.google.com/a/answer/1668854 (read 2026-10-30) |

### 2.7 Microsoft Copilot (M365) — in scope by implication of the tenant-header requirement

| Aspect | Finding |
|---|---|
| Tenant control | **Proxy headers exist**: `Restrict-Access-To-Tenants: <tenant list>` and `Restrict-Access-Context: <directory id>` on `login.microsoftonline.com`, `login.microsoft.com`, `login.windows.net`; exclude `device.login.microsoftonline.com` and `enterpriseregistration.windows.net` from interception; the proxy must overwrite a client-supplied header; Entra ID P1/P2 required; `sec-Restrict-Tenant-Access-Policy: restrict-msa` on `login.live.com` blocks consumer accounts; Android 7+ clients ignore user CAs so tenant restrictions do not work there (learn.microsoft.com tenant-restrictions, read 2026-10-30). → **E (header on ProxySG)** |
| Note | tenant restrictions v2 (cross-tenant access settings, universal tenant restrictions) replace header injection for Entra-joined devices; **UNVERIFIED** whether the estate uses them; both can coexist |
| Evidence | learn.microsoft.com/entra/identity/enterprise-apps/tenant-restrictions |

### 2.8 Later candidates (not designed, listed for the shadow-AI inventory)

Cursor (own API hosts, pinned client **UNVERIFIED**), Amazon Q Developer (AWS SigV4, Bedrock), Mistral Le Chat, DeepSeek,
Perplexity, Replit, Lovable: all start as **category-blocked** by the uncategorised-AI rule (SEC-7) until a row exists.

## 3. Blind-spot matrix (SEC-1)

| Flow | ICAP sees | Mark | Compensating control |
|---|---|---|---|
| Browser chat POST (all platforms) | request and response headers and bodies | E / L | — |
| SSE response | chunks as they pass | L (sliding window, abort on high-confidence leak) | async full analysis; REQMOD is where blocking happens |
| WebSocket after upgrade (Realtime APIs, some IDE channels) | nothing after 101 | I | block the upgrade for AI hosts where the feature is not needed (REQMOD can refuse the upgrade request → E on the upgrade itself); optional chained proxy (ADR-004) if phase 0 shows demand; agent path |
| HTTP/2 streams | as HTTP/1.1 encapsulation if ProxySG converts | E / L, **UNVERIFIED** | force HTTP/1.1 for AI domains by CPL (Broadcom KB 441957 pattern) |
| gRPC (Windsurf?) | request bodies yes, trailers unknown | L or I | allowlist the vendor's enterprise host; agent path |
| Body above ProxySG ICAP max size | nothing (ProxySG decides) | I unless the policy denies | ProxySG rule set to deny for the AI category (KB 167551); rwsafe's 4 MiB limit is below |
| File uploads (documents, images, archives) | the multipart body | E for text, archives expanded to depth 2; images: **no OCR in MVP** → L | BYPASS_CATALOGUE rows; upload size cap per platform policy |
| Pinned desktop and mobile apps | nothing | I | block app domains or MDM pinning exceptions (OpenAI's own guidance); managed-device policy |
| Direct API with a personal key from the corporate network | request and response | E (the gateway is the only allowed base URL; a non-corporate key on `api.*` hosts is blocked at REQMOD by the Authorization-header class) | relay blocklist |
| Off-net laptops, Edge SWG users | nothing | I | ADR-006 agent path; tenant settings |
| Cloud-side agents | console login only | T | OUT_OF_SCOPE §1 |
| QUIC | nothing | I | block UDP 443 (UNVERIFIED estate policy) |

## 4. Per-client trust matrix (phase 0 fills the measured column)

| Client | Trust store | Proxy settings | Pinning | Measured (phase 0) |
|---|---|---|---|---|
| Chrome, Edge, Firefox | OS store (Firefox: enterprise roots policy) | PAC/system | no | |
| VS Code + Copilot | OS store, `http.proxy`, `http.proxyStrictSSL` | yes | no | |
| JetBrains IDEs + plugins | JVM `cacerts` (import required) | IDE proxy settings | no | |
| Claude Code (Node) | `NODE_EXTRA_CA_CERTS`, `HTTPS_PROXY` | yes | no (UNVERIFIED) | |
| Codex CLI (Rust) | **UNVERIFIED** | `HTTPS_PROXY` (UNVERIFIED) | UNVERIFIED | |
| Gemini CLI (Node) | `NODE_EXTRA_CA_CERTS` | yes | no | |
| Windsurf language server | **UNVERIFIED** | UNVERIFIED | UNVERIFIED | |
| ChatGPT desktop/mobile | pinned (vendor statement) | n/a | **yes** | |
| Claude desktop | UNVERIFIED | UNVERIFIED | UNVERIFIED | |
| Python/Node SDKs (API) | `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS` | `HTTPS_PROXY` | no | |

## 5. Data region, DPA and zero-retention (PRIV-3) — to be completed from the enterprise contracts

| Platform | Region options | Enterprise DPA | Zero retention / no training | Classes that may never leave (policy registry) |
|---|---|---|---|---|
| Claude | UNVERIFIED | UNVERIFIED | ZDR available on request (UNVERIFIED for this contract) | customer data, banking secret, special-category: **blocked for every platform** regardless of contract until the PO's model/region allowlist (Q-7) says otherwise |
| GitHub Copilot | US or EU inference region (docs.github.com) | enterprise agreement | no training on Business/Enterprise prompts (vendor claim) | same |
| OpenAI | EU residency option (UNVERIFIED) | UNVERIFIED | no training on Enterprise (vendor claim) | same |
| Devin, Windsurf, Gemini | UNVERIFIED | UNVERIFIED | UNVERIFIED | same |

The sector rule that primary systems and their backups stay in Türkiye (BDDK information-systems regulation, 2020; see
REGULATORY_MAPPING) applies to rwsafe itself (it runs on HOST-A) and frames the "never leaves" classes for the vendors.
