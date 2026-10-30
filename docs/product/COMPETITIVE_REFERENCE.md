# Competitive and reference products: what to adopt, what to avoid

**Status:** FROZEN by `docs/design/PO_DECISION_RECORD_2026_10_30_DESIGN_FREEZE.md` (2026-10-30); amended only through a PO decision record or an ADR
that quotes one.

**History:** DRAFT for design freeze. Answers brief section 3 (study list) and 9 item 7. Sources are vendor pages and
documentation read on 2026-10-30; marketing claims are labelled as such; where no primary documentation was found the row
says UNVERIFIED. rwsafe's position on each is in the last column.

| Product | What it is | How it enforces | Adopt | Avoid | Evidence |
|---|---|---|---|---|---|
| **Lakera Guard** | hosted guardrail API (`/v2/guard`) returning category flags (prompt_injection, jailbreak, PII, etc.) with scores; integrations (LangChain, Portkey) | the application calls the API per prompt | the **category taxonomy** and the flag + score response shape for rwsafe's own verdict model; the idea of a "guard" API that the LLM gateway can expose internally | **calling a hosted detector inline**: content would leave HOST-A (PRIV-3), adds network latency, third-party dependency for fail-closed classes | docs.lakera.ai API reference; lakera.ai product updates; ownership change reported by a secondary source (UNVERIFIED) |
| **Check Point GenAI Protect / Harmony Browse / Harmony DLP** | browser extension on managed and unmanaged devices; AI-powered classification of prompt text; 700+ data types; copy/paste/upload/download control; OCR claimed by a secondary source | in-browser inspection without rerouting; cloud DLP service for policy | the **extension-based off-net path** (ADR-006), monitor paste/upload events, the "classify conversational data" framing | relying on the extension as the enforcement of record; a cloud DLP service for content classification (data leaves) | Check Point solution briefs and community posts (vendor claims) |
| **Prompt Security (SentinelOne)** | platform for employee GenAI use and homegrown LLM apps; browser extension as the primary employee control; monitor-then-enforce rollout; shadow-AI reports | extension + platform policies | **monitor-only mode before enforce**, shadow-AI inventory and risk scoring, MDM deployment of the extension | no primary documentation found (UNVERIFIED feature claims) | directories and reviews only |
| **Netskope (Next Gen SWG, AI Security)** | cloud SWG/CASB with **app instance awareness** (corporate vs personal instance), 1 800+ GenAI apps identified, DLP on upload/post, activity-level controls | inline cloud proxy | **instance awareness as a concept**: rwsafe's tenant verdict is the on-prem equivalent; activity-level policies (upload, post, paste); per-app risk scores for discovery | a cloud proxy hop (the PO's path is on-prem ProxySG); instance awareness for every app is not available (Netskope itself notes limits) | Netskope community guides and docs (vendor) |
| **Zscaler (ZIA GenAI controls, AI Guard)** | cloud proxy with prompt visibility and classification, inline DLP on prompts, app control (block/warn/isolate), browser isolation for paste/download control; AI Guard as runtime guardrails for AI apps | inline cloud proxy; isolation | **prompt visibility + classification as a product feature**, warn/block/isolate action set, DLP applied to the prompt itself | browser isolation as a dependency; cloud residency of prompt logs | Zscaler product pages, data sheet, blog (vendor claims); AI Guard details from a partner blog |
| **Microsoft Purview DSPM for AI** | posture and DLP for AI: enterprise apps (Copilot, ChatGPT Enterprise via Entra registration) with prompt/response capture through one-click policies; third-party AI sites via the Purview browser extension (Windows) and endpoint DLP; Insider Risk policies for browsing to AI sites | extension + endpoint DLP + Entra/Graph | **the two-tier model**: deep capture for enterprise tenants, detection-only for third-party sites; the "allow 24 h for policies to populate" operational honesty; Entra tenant restrictions as the M365 enforcement | Windows-only parts; dependency on the Microsoft estate for non-Microsoft platforms | learn.microsoft.com DSPM for AI (read 2026-10-30) |
| **Google Workspace / Gemini controls** | `X-GoogApps-Allowed-Domains` header, admin console account restrictions, Workspace/Cloud IAM for Code Assist | proxy header + tenant settings | the header (ADR-007) | assuming the header covers every Google AI surface (UNVERIFIED for the Gemini app) | support.google.com/a/answer/1668854 |
| **GitHub Enterprise controls** | EMU, GHE.com data residency, Copilot policies (content exclusions GA in app and CLI 2026-09, residency-compliant models, model allowlists) | tenant settings + routing | EMU and residency as the tenant control of record; content exclusions as a complementary data control | expecting a proxy header (none) | docs.github.com; github.blog changelog |
| **OpenAI corporate network controls** | `ChatGPT-Allowed-Workspace-Id` header, anonymous-prefix blocking, app pinning guidance | proxy header | the header and the pinning-exception guidance | — | help.openai.com 20001323 |
| **Anthropic enterprise controls** | domain capture, Require SSO, prevent new organisations on verified domains; Claude Code managed settings (`forceLoginOrgUUID`, `forceLoginMethod`, `env`, `allowedMcpServers`, `permissions.deny`, marketplaces) | tenant settings + endpoint policy | all of them in ADR-007 | expecting a proxy header (none found) | support.claude.com; code.claude.com |
| **OWASP Top 10 for LLM Applications 2025** | the risk taxonomy | — | the taxonomy as the threat-model backbone (THREAT_MODEL §9) | — | genai.owasp.org |

## What rwsafe does that none of these do for this estate

On-prem, inline at the existing ProxySG via ICAP with neXus-grade administration, masking for AI agents, trigger-enforced
audit, a policy registry with simulation and approvals, Turkish identifiers as first-class detectors, and KVKK/sector
controls designed into the data model (fail-closed classes, redaction before persistence, provable deletion). The
vendors' ideas adopted: instance/tenant awareness, prompt visibility with classification, monitor-first rollout, the
extension for off-net, the category taxonomy, the two-tier capture model.

## What rwsafe deliberately does not copy

Cloud-hosted detection or logging of prompt content; browser isolation as a control; an extension as the enforcement of
record; blanket blocking of AI sites instead of tenant enforcement.
