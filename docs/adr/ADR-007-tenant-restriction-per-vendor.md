# ADR-007: Tenant restriction per vendor

Status: PROPOSED
Date: 2026-10-30
Answers: brief 5A (first priority), 10.4 (agentic and MCP governance: managed settings); council offensive P1 "tenant
headers do not revoke existing sessions", SEC-3; PLATFORM_MATRIX §2

## Context

Job 1 is "enterprise tenants, never personal accounts". Three vendors publish a proxy-injected header for exactly this
(Microsoft, Google, OpenAI); the others rely on tenant-side settings and endpoint configuration. A header restricts new
sign-ins; an existing session, a refresh token, a personal API key or a relay (`*_BASE_URL`) bypasses it.

## Decision

### 1. Control per vendor (brief 5A order: header → ICAP on login → endpoint)

| Vendor | Control of record | ProxySG does | rwsafe does | Residual |
|---|---|---|---|---|
| Microsoft (Entra sign-in, M365 Copilot) | **header** | injects `Restrict-Access-To-Tenants` and `Restrict-Access-Context` on the three Entra login hosts, overwrites a client-supplied header, excludes the device-registration hosts from interception; `sec-Restrict-Tenant-Access-Policy: restrict-msa` on `login.live.com` | REQMOD verifies the header is present on those hosts (a missing header is a **coverage fault** alert, SEC-6), records the login as `tenant_enforced_by=proxy_header` | Android and pinned clients (vendor-documented); existing sessions |
| Google (Gemini app, Workspace, Code Assist) | **header** | injects `X-GoogApps-Allowed-Domains: <corporate domains>` on `*.google.com` without `consumer_accounts` | same verification; phase 0 tests that the header governs `gemini.google.com` sign-in (UNVERIFIED); `googleapis.com` API keys handled by the gateway rule | anonymous use (Google: not necessarily prohibited) → REQMOD blocks unauthenticated prompt POSTs to the Gemini app |
| OpenAI (ChatGPT) | **header** | injects `ChatGPT-Allowed-Workspace-Id: <ids>` on `chatgpt.com`; blocks the `backend-anon` prefix; blocks the desktop/mobile app domains or the MDM deploys pinning exceptions | verification as above; Codex CLI and API: gateway rule | apps if neither block nor pinning exception is deployed |
| Anthropic (claude.ai, Claude Code) | **tenant settings + endpoint** | no header exists (UNVERIFIED: none documented) | **ICAP on the login flow**: REQMOD inspects the claude.ai sign-in and OAuth completion; an identity whose e-mail domain is not corporate, or an organisation id not on the allowlist (visible in the session bootstrap response, UNVERIFIED shape), is blocked with the coaching page; `forceLoginMethod`, `forceLoginOrgUUID`, `env` (`ANTHROPIC_BASE_URL` → gateway, `CLAUDE_CODE_USE_BEDROCK`/`VERTEX` unset and locked), `allowedProviders`, `allowManagedMcpServersOnly` + `allowedMcpServers`, `permissions.deny`, `disableBypassPermissionsMode` through managed settings on managed devices; vendor-side domain capture and Require SSO | personal account with a non-corporate e-mail on a device without managed settings → caught only at the login step inspection |
| GitHub Copilot | **tenant settings + routing** | for GHE.com tenants: allow `*.<subdomain>.ghe.com`, block Copilot API hosts for github.com personal use; otherwise allow github.com | REQMOD on the IDE device-flow login (UNVERIFIED endpoint shape): block completion for a non-enterprise identity; EMU makes personal accounts structurally impossible inside the enterprise | personal Copilot on github.com if the estate is not on GHE.com and the login flow cannot be classified → L |
| Devin, Windsurf | **tenant settings (SSO)** | allow the vendor's hosts | REQMOD on the console login: corporate IdP redirect expected, direct password login blocked (UNVERIFIED flow); Windsurf enterprise dedicated host allowlisted | cloud-side work (OUT_OF_SCOPE) |
| Any API host (`api.anthropic.com`, `api.openai.com`, `generativelanguage.googleapis.com`, `api.githubcopilot.com`, Bedrock, Vertex, known relays) | **gateway + REQMOD key class** | sends the category to ICAP | REQMOD classifies the `Authorization`/`x-api-key` value by **shape and HMAC digest** against the corporate key digests held in the policy snapshot (never the keys): a non-corporate key is **blocked**; Bedrock/Vertex hosts are blocked unless on the allowlist; a known relay host is blocked | a tool off-net with a personal key |

### 2. Sessions already open (offensive P1)

Headers do not revoke sessions. rwsafe adds two measures: (a) on the day enforcement starts, the pilot group's users are
asked to sign out and in (coaching banner), and the policy flags sessions whose first sight predates enforcement; (b)
REQMOD validates tenant at the **cookie or token level** where the vendor exposes it: Entra `x-ms-client-request-id` and
tenant ids in token endpoints, Google's account chooser responses, OpenAI's workspace id in the session response,
Anthropic's organisation id (each **UNVERIFIED** until phase 0 captures the sanitized frame fixtures). Where it cannot be
read, the record says `tenant_check=NOT_EVALUABLE` and the coverage metric counts it.

### 3. Identity is a proxy claim (SEC-3)

The user behind a tenant decision is `X-Authenticated-User` from ProxySG, labelled `proxy_claim`; the tenant decision
does not depend on it (it depends on the vendor-side identity in the login flow), but the audit record does, so a
spoofed claim could only mislabel who, never which tenant. Secure ICAP with mTLS and the source allowlist make the
claim trustworthy enough for audit; VDI and terminal-server addresses are labelled shared.

### 4. Staged rollout

Monitor-only first (verdicts recorded, nothing blocked), then the pilot AD group, then all; exceptions with an expiry
(brief 10.4 policy lifecycle). The ProxySG header injection itself is a phase-1 quick win and is **not** staged by rwsafe:
the proxy team applies it to the pilot group's policy layer first.

## Alternatives considered

- Blocking the AI domains for everyone and allowlisting enterprise URLs only: the vendors share hosts between personal
  and enterprise use; impossible for most.
- Relying on headers alone: no header for Anthropic, GitHub, Devin, Windsurf; sessions and API keys bypass; rejected.
- Relying on endpoint settings alone: unmanaged devices and web use escape; rejected.

## Consequences

- Phase 0 must capture sanitized login-flow fixtures per platform to classify the steps (`login`, `oauth_callback`,
  `session_bootstrap`); until then the login-step rules are monitor-only.
- The corporate key digests live in the policy snapshot; the keys themselves live only in the gateway's Secret.

## Evidence and UNVERIFIED facts

learn.microsoft.com tenant restrictions; support.google.com/a/answer/1668854; help.openai.com 20001323;
support.claude.com 14625619, 10276682; code.claude.com managed settings; docs.github.com data residency; docs.devin.ai.
UNVERIFIED: every login-flow frame shape; Gemini app coverage by the Google header; Codex CLI base-URL configuration.

## Open questions

Q-21 (which vendors' headers the proxy team can deploy in phase 1), Q-7 (model/region allowlist), Q-6 (personal use policy).
