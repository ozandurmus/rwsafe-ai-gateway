<!-- Fable consultation 2026-10-30T08:07:50Z, model claude-fable-5-1, exit 0; unaltered output -->

Not: Koltuk talimatı çıktının yalnızca İngilizce olmasını istediği için (depo artefaktı, `docs/reviews/`), inceleme aşağıda İngilizce verilmiştir.

# Design-freeze council, seat: offensive-security (second pass)

Role: REVIEWER. Read: AGENTS.md and the 16 listed files only. No edits, no shell.

## 1. CONSENT

| Area | Verdict |
|---|---|
| Secure ICAP with mTLS, source allowlist in NetworkPolicy and engine, `identity_source=proxy_claim`, shared-address label (ICAP spec §2, SR-ICAP-1..3) | Accept |
| RE2/J only, explicit body/decompression/nesting limits, Jazzer corpus in the ship gate, parse failure is a verdict never a 204 (spec §3, §4.5, SR-DP-1..4) | Accept |
| Stateless inline path, bounded queues, verdict/audit never dropped, snapshot-signed policy (ARCH-1, SR-DP-6..8) | Accept |
| REQMOD fail-closed / RESPMOD fail-open split with every degraded event as a SIEM record (ADR-010 §1, §3) | Accept |
| WebSocket upgrade refused by default for AI hosts; chained proxy designed, not built (ADR-004, ADR-005 §4) | Accept |
| Sliding-window RESPMOD with abort, no whole-stream buffering, abort limitation stated (ADR-005 §2, §6) | Accept |
| Cloud-side agents declared out of gateway scope with the vendor tenant as enforcement point and quarterly attestation (OUT_OF_SCOPE §1) | Accept |
| Pinned apps, mobile, QUIC, off-net declared with compensating controls (OUT_OF_SCOPE §2, PLATFORM_MATRIX §3) | Accept |
| Tenant control per vendor in brief order; key-class REQMOD block by HMAC digest; relay blocklist; session-level checks where visible, `NOT_EVALUABLE` counted (ADR-007) | Accept |
| Stored prompts as hostile input: inert rendering, CSV escaping, syslog control-char stripping, untrusted framing and no bodies to AI consumers (THREAT_MODEL §4, §6, SR-ADM-4, SR-SIEM-1, SR-PRIV-3) | Accept |
| Redaction of detected secrets and PII before persistence; capture sink re-runs detectors (SR-PRIV-11) | Accept |
| Gateway: fixed upstream allowlist, no client URLs, no shared cache, keys only in gateway pods (THREAT_MODEL §3) | Accept |
| Models and rule packs: safetensors/ONNX only, hash-pinned, signed; Gradle lockfiles; image digests and provenance (THREAT_MODEL §8, SR-SC-1..3) | Accept |
| k3s Secrets encryption verified on, PSA restricted, no hostPath, caps dropped, cross-namespace isolation in the pentest (SR-HOST-3, PENTEST §2) | Accept |
| Phase 0 read-only SSL-bypass audit; protocol-drift `UNKNOWN_FLOW` blocks the login step (SEC-7, ADR-010 §2) | Accept |
| Independent pre-pilot pentest before REQMOD fail-closed; HIGH blocks the pilot (PENTEST §1, §4) | Accept with the additions in OFF2-17 |

## 2. DISSENT

| Id | Document, section | What is wrong | Concrete correction |
|---|---|---|---|
| OFF2-1 | ICAP spec §4.3 (Preview branch) | "decide early when possible (allow → 204 within the preview)" allows a 204 on a 4 KiB preview when the body is larger; everything after the preview is never inspected. Padding 4 KiB of benign text before the secret is a complete REQMOD bypass. | ALLOW on the preview only when `ieof` is present. Otherwise always `100 Continue` and decide on the full body. Add fixture: 4 KiB benign prefix + secret after the preview boundary → must be BLOCK. Add to SR-DP-3. |
| OFF2-2 | ADR-010 §2 (OVERSIZE row); ICAP spec §3 (REQMOD body row) | OVERSIZE is "allow with warn" unless the body is an upload, and the decision is "made on the first 4 MiB". A chat body padded past 4 MiB carries the secret in the uninspected tail. ADR-010 also names a 16 MB upload limit that the spec does not have. | OVERSIZE = UNINSPECTABLE. In `enforce` mode the action is block for every flow whose policy entry contains any fail-closed class; allow only by an explicit expiring exception. One body limit in the spec and the ADR (or state both limits and which applies to multipart). |
| OFF2-3 | BYPASS_CATALOGUE BY-ENC-2, BY-ENC-8, BY-ENC-9; ICAP spec §3 (nested decoding row) | Depth 3+ encoding, a 2 MiB decoded cap and unrecognised encodings produce `PARTIAL_INSPECTION` plus warn, which is an allow. The residual blob is uninspected content on the same footing as OVERSIZE. REDACT on a finding inside a decoded layer cannot be mapped back into the encoded bytes. | A residual undecodable or high-entropy blob above a small threshold (for example 256 bytes) in a prompt field → UNINSPECTABLE with the OFF2-2 rule. A finding inside a decoded layer → replace the whole encoded field with the class token or block. Move BY-ENC-8 to MVP as "encoded blob → UNINSPECTABLE". |
| OFF2-4 | ADR-010 §2 (INSPECTION_FAILED, OVERSIZE, UNINSPECTABLE rows); BY-FILE-2 | "block for fail-closed classes" cannot be evaluated when inspection failed: the class is unknown. "Fail-closed platforms" is used but never defined. ADR-010 §6 references SR-DLP-* ids that do not exist in SECURITY_REQUIREMENTS. | Define fail behaviour by flow policy, not by detected class: "block when the matched policy entry for platform × surface × step × group contains any fail-closed class in enforce mode". Define the term once in ADR-010 and reuse it in the bypass catalogue. Add SR-DLP-1 (definition and test of the fail-closed class set). |
| OFF2-5 | COUNCIL_RESPONSE SEC-6, SEC-7; ADR-004 (uncategorised row); SR-DET-4 | Numerator and denominator of the coverage ratio both derive from the ProxySG AI category, so the metric measures ICAP plumbing, not coverage. "Uncategorised new AI domain → inspect" is not decidable by ProxySG: it cannot know a domain is AI. Relays on arbitrary hosts never reach REQMOD because only the AI category is sent. | State the metric's limit in CAPACITY and SR-DET-4. Add a second signal: all uncategorised domains (and chosen broad categories) go to REQMOD in a header-only metadata mode (no body capture, short retention) that fingerprints AI API shapes (`anthropic-version`, `/v1/chat/completions`, `/v1/messages`, SSE accept, `x-api-key`). Maintain an AI-domain feed in the policy registry. PO question Q-B. |
| OFF2-6 | ICAP spec §4.3 (field extraction), §5 (shape fingerprint); BY-PROTO-5 | Inspection is described by known field paths; the fingerprint is on field paths. Either unknown fields are uninspected (smuggling in `metadata`, custom fields the vendor ignores) or every vendor schema addition fires `UNKNOWN_FLOW` and pressures operators to loosen it. Base64 document blocks inside JSON (PDF attachments) hit the 2 MiB text-decode cap, not the file pipeline. | Inspect every string leaf of the JSON regardless of schema; route base64 leaves that decode to a known file magic into the file pipeline (BY-FILE-*). Fingerprint only on required fields and content types; unknown extra fields are inspected and counted, not UNKNOWN_FLOW. Add a fixture with a secret in an unknown field. |
| OFF2-7 | ADR-005 §2; COUNCIL_RESPONSE "responses as an attack path"; THREAT_MODEL §9 LLM01 | Response-side injection is alert-only, but for Claude Code, Codex CLI, Copilot agent mode and MCP the next tool call executes within seconds; a late alert is not a control. The design misses that tool results re-enter through REQMOD as `tool_result` content in the next request, where blocking is possible. | REQMOD: run injection detectors on `tool_result`, `function` and web-fetch result blocks; high-confidence deterministic patterns may block on CLI/IDE surfaces (policy-configurable, monitor first). RESPMOD: add high-confidence injection patterns to the abort set for agentic surfaces. Record in ADR-005 and ADR-008 §2. PO question Q-C. |
| OFF2-8 | THREAT_MODEL §4, §6; SR-PRIV-3; SR-SIEM-1 | "Metadata" fields chosen by the client are free text: file names, tool and MCP server names, `model`, URL path and query, user-agent, SSE event names, upstream error messages, and the coaching-page justification text. They reach the masked view, the SIEM and AI reviewers as metadata, so the untrusted framing and the "no bodies" rule do not cover them. | Classify these fields as content-grade in DATA_CLASSES: length-capped, control characters stripped, untrusted framing applied, digests or enums in SIEM where possible. Add the justification free text to STRIDE §4 as hostile input with inert rendering. Add a leak-probe and injection fixture per field. |
| OFF2-9 | ADR-008 §2 (estate names "keyed digests at runtime"); THREAT_MODEL §1 | Substring matching (Aho-Corasick) over HMAC digests is not possible. Either the data plane holds the estate's real host, project and user names in memory (an asset absent from §1, exposed by memory disclosure) or matching is whole-token over digests with a documented limitation. | Choose and document: recommended whole-token digest matching with normalised tokens (documented limitation: partial names undetected inline, full match in the worker) or plaintext dictionary in data-plane memory listed as an asset with heap dump off, no core dumps, and a memory-disclosure row in §2. |
| OFF2-10 | ICAP spec §3 (connections per source, in-flight cap); THREAT_MODEL §2 D rows | Per-source limits are meaningless behind ProxySG connection pooling: every transaction arrives from the proxy addresses. One user sending slow `100 Continue` bodies occupies the 1 000 in-flight slots → 503 → estate-wide AI outage under REQMOD fail-closed, or uninspected traffic during the pilot fail-open window. | Per-identity in-flight cap (claimed user, falling back to `X-Client-IP`), minimum body receive rate and a body-receive timeout separate from the 2 s decision time; exceeding identities get the ADR-010 action and a SIEM event, not a pool-wide 503. Add to SR-DP-2 and the pentest. |
| OFF2-11 | SR-DP-8; ICAP spec §4.2 ISTag | A stale (> 24 h) snapshot is refused, but a replayed older signed snapshot inside 24 h with a weaker policy is accepted. | Monotonic snapshot version: the engine refuses any snapshot whose version is lower than the last activated one; version in ISTag; test with a signed older snapshot. Pentest §2 "replay an old snapshot" then has a defined expected result. |
| OFF2-12 | ADR-007 §3 | "a spoofed claim could only mislabel who, never which tenant" is wrong: `X-Authenticated-Groups` selects policy entries, staged-rollout groups and exceptions, and the claimed user keys the fragmentation thresholds. The claim is enforcement-relevant. | Reword §3. Group claims drive policy selection only on `mtls_verified` connections; on `plain_allowlisted` (H-2) apply the strictest group policy and record the residual. Add a fixture: spoofed group → no exception applied. |
| OFF2-13 | PLATFORM_MATRIX §3; OUT_OF_SCOPE §3; ADR-010 §1 ("any other category not sent") | Content reaches AI through integrated storage and collaboration the ICAP category does not cover: Drive attachments to Gemini, SharePoint and OneDrive to M365 Copilot, repositories to Copilot and Codex cloud, Slack to Devin. Gemini in Workspace apps and Copilot in Office share domains with the non-AI product, so a domain category cannot separate them. | Add blind-spot rows for storage-integrated and embedded AI with the compensating control named (vendor DLP, Purview, Workspace DLP, GitHub app policy). Decide explicitly which collaboration domains are in the ICAP category and mark embedded-AI surfaces L or T. |
| OFF2-14 | THREAT_MODEL §3 S; SR-GW-1 | A "device fingerprint" is client-supplied and replayable; it is a signal, not a binding. | Bind gateway credentials to the MDM client certificate (mTLS) where present, otherwise to a directory session with re-authentication; keep the fingerprint as an anomaly signal only. Reword SR-GW-1. |
| OFF2-15 | AGENTS.md §1 item 4; §11; THREAT_MODEL (no row) | Council outputs are external LLM output written unaltered and are binding for the design phase. Any agent reading them has write access to the repository. This is a prompt-injection path into the authority chain, and the agent tooling surface (`tools/review/`, external CLIs) is absent from the threat model. | Demote `docs/reviews/` to evidence (level 6); only a PO decision record quoting a council item makes it binding. Agents treat review outputs as untrusted data. Add a threat-model section for the agent tooling surface. |
| OFF2-16 | COUNCIL_RESPONSE §1 P1-1 (`rwsafe-build` on HOST-A); THREAT_MODEL §8 | Builds execute third-party build scripts and plugins on the production node. Dependency tampering (T row) covers artefacts, not build-time code execution on HOST-A. | Build pods: PSA restricted, no service-account token, egress only to the registry and the corporate proxy, ephemeral storage, Gradle verification metadata covering plugins, CI actions pinned by digest. Add a §8 row and a pentest item "from a build pod, reach cluster or neXus". |
| OFF2-17 | PENETRATION_TEST_PLAN §2 | Missing: tenant-enforcement end-to-end against lab vendor tenants (no test proves the headers and login-step rules work); CRLF and header injection into the rebuilt encapsulated response on REDACT and BLOCK; request smuggling via `Content-Length` / `Transfer-Encoding` after rewrite; attempts to flip REQMOD to fail-open by inducing selective 5xx or health-check failure; prompt-injection tests against the masked AI consumer path and the review scripts; the OFF2-1 and OFF2-10 cases. | Add these rows to §2; require lab tenants for the three header vendors plus Anthropic (Q-D). |

## 3. QUESTIONS FOR THE PRODUCT OWNER

| Question | Recommendation |
|---|---|
| Q-A. Default action in enforce mode for OVERSIZE, UNINSPECTABLE and residual encoded blobs on every AI flow: block, or allow with warn? | Block for every flow whose policy contains a fail-closed class; expiring exceptions by group. Padding and encoding bypasses are otherwise free. |
| Q-B. May all uncategorised domains (and selected broad categories) go to REQMOD in header-only metadata mode to detect relays and new AI hosts, given the privacy seat's scope concern? | Yes, metadata only, no body capture, 30-day retention, documented in DATA_CLASSES; without it relays and shadow AI are invisible by construction. |
| Q-C. Response-side and tool-result prompt-injection: alert-only (current), or block on high-confidence deterministic patterns for CLI/IDE surfaces? | Monitor for the pilot, then enforce high-confidence patterns on agentic surfaces; the gateway and REQMOD can both do it without ML. |
| Q-D. Procure lab tenants (ChatGPT Enterprise, Google Workspace, Entra, Anthropic) for the pentest and the ICAP e2e tenant fixtures? | Yes, at least the three header vendors; without them tenant enforcement ships untested. |
| Q-E. The pilot runs plain ICAP (H-2) and REQMOD fail-open at the same time for two weeks. Accept both residuals together? | No. Secure ICAP first, then the fail-open measurement window; or shorten the window to one week with the coverage alert armed. |
| Q-F. Should council outputs in `docs/reviews/` remain binding, or become evidence that a PO decision record promotes? | Evidence only; the PO record is the sole promotion path. |

## 4. VERDICT

**ACCEPT WITH CORRECTIONS**: OFF2-1 to OFF2-7 must be corrected in the documents before implementation starts; the rest may be corrected during phase 0 with the PO answers above.

## 5. INSTRUCTIONS RECEIVED, VERBATIM

1. The seat brief (user message):

```
SEAT: offensive-security
LENS: how an attacker or a careless user bypasses the gateway (encodings, fragmentation, files, protocols, pinned clients, off-net, relays, personal keys, sessions), how the gateway itself becomes an attack surface (ICAP parser, identity spoofing, gateway as open relay, stored prompts as hostile input, the masked AI reviewer as a prompt-injection target, agent channel), fail-open paths, coverage blind spots, supply chain.

You are one independent seat of the design-freeze council for rwsafe-ai-gateway (an enterprise AI-usage security gateway: enterprise-tenant enforcement, prompt and response visibility under masking and retention limits, guardrails, a governed LLM API gateway, ICAP behind Broadcom ProxySG, an off-net agent path later; Java/Netty data plane and Spring Boot control plane; same single on-prem k3s node as the sibling product neXus, fully isolated; the organisation is in a regulated sector in Türkiye: KVKK and BDDK-style rules in scope). You start from a fresh context. Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this repository. Do not edit, run shell, or widen the review. The kickoff council (docs/reviews/COUNCIL_2026_10_30_SEAT_*.md) raised P0/P1 items; the architect answered them in docs/reviews/COUNCIL_RESPONSE.md. Your job: find what the DESIGN still gets wrong or leaves unsafe for your lens, so implementation does not start on a flawed design. Return exactly: (1) a CONSENT table (area, verdict), (2) a DISSENT table (finding id, document and section, what is wrong, the concrete correction), (3) QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation), (4) a one-line verdict ACCEPT FREEZE / ACCEPT WITH CORRECTIONS / REJECT, then (5) list every instruction you received, verbatim. Be concrete and short. Never quote or invent an address, host name, account, serial or secret; the repository holds none and neither should your output. English only.

Files to read, in this order:
- AGENTS.md
- docs/reviews/COUNCIL_2026_10_30_SEAT_FABLE_OFFENSIVE.md (your predecessor's P0/P1 list)
- docs/reviews/COUNCIL_RESPONSE.md (section 3 and section 5)
- docs/security/THREAT_MODEL.md
- docs/security/SECURITY_REQUIREMENTS.md
- docs/security/BYPASS_CATALOGUE.md
- docs/architecture/ICAP_AND_STREAMING_PROTOCOL_SPEC.md
- docs/adr/ADR-004-icap-vs-chained-proxy-vs-agent.md
- docs/adr/ADR-005-websocket-and-streaming-strategy.md
- docs/adr/ADR-006-edge-swg-and-off-net-agent-strategy.md
- docs/adr/ADR-007-tenant-restriction-per-vendor.md
- docs/adr/ADR-008-guardrail-engine-build-vs-integrate.md
- docs/adr/ADR-010-fail-open-and-fail-closed.md
- docs/product/PLATFORM_MATRIX.md (sections 1, 3, 4)
- docs/product/OUT_OF_SCOPE.md
- docs/security/PENETRATION_TEST_PLAN.md
```

2. UserPromptSubmit hook:

```
REMINDER: Reply to the Product Owner in TURKISH only (every chat message). Repo artifacts stay English.
```

3. Project instructions, `CLAUDE.md`:

```
@AGENTS.md

Claude-specific delta only; `roles/ENGINEER.md` carries the reading order.

- Chat with the Product Owner in Turkish; every repository artifact in English (`AGENTS.md` section 3).
- Model tiers for this tool: `docs/reference/MODEL_TIER_MAP.md`.
- HOST-A: read-only, masked, no `sudo` (`AGENTS.md` section 8). Inventory through `tools/hosta/inventory_readonly.sh`;
  root-only listings through `tools/hosta/po_sudo_readonly.sh` run by the PO in a terminal.
- External reviews only through `tools/review/consult_*.py` (`AGENTS.md` section 11); never a simulated persona.
- Argon development lanes only through `tools/review/argon_task.py` in a `~/Codo/rwsafe-*` worktree.
- Never read `kickoff/` raw traffic or prompt samples if any are ever added; sanitize first (`AGENTS.md` section 4.1).
```

4. Global user instructions, `~/.claude/CLAUDE.md`:

```
# graphify
- **graphify** (`~/.claude/skills/graphify/SKILL.md`) - any input to knowledge graph. Trigger: `/graphify`
When the user types `/graphify`, use the installed graphify skill or instructions before doing anything else.
```

5. `AGENTS.md` (sections 1 to 14), supplied in full as project instructions; it is the committed file at the repository root and is not reproduced here. The roles file `roles/REVIEWER.md` was not on the allowed read list and was not read.

6. Harness system instructions (Claude Agent SDK operating rules, memory directory rules, writing rules, autonomy rules) were received; they are not repository material and are not reproduced.
