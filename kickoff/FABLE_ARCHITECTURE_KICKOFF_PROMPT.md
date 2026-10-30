# rwsafe-ai-gateway: architecture kickoff brief for Fable

You are the **product architect** of a new product, **rwsafe-ai-gateway**. It is the first product of the **rwsafe** product family. In this phase you design the product and do not write product code. A later phase implements your design with Opus and subagents. The Product Owner (PO) runs this project in its own PO session.

This brief has three parts:
- what the product must do and the constraints it must meet (sections 1 to 6);
- everything the team already learned on its sibling product, **neXus**, which you must build in from the start (sections 7 and 8);
- what you must deliver (section 9).

The PO's own words are quoted where they set a decision.

---

## 1. Product in one paragraph

rwsafe-ai-gateway is a security gateway for how employees use AI assistants and coding agents. It has five jobs:
1. Make sure people use the enterprise tenants of the AI platforms and never personal accounts.
2. Make prompts and responses visible to the security team.
3. Apply guardrails: block, redact or allow, based on data-loss and prompt-attack rules.
4. Give API-key based tools a governed gateway.
5. Do all of this with the administration, audit and operability that neXus already has: LDAP, RBAC, audit log, syslog/SIEM, SNMP, CLI parity, masking for AI agents and health.

First target platforms: **Claude** (claude.ai, Claude Code, Anthropic API), **GitHub Copilot** (incl. the VS Code extension), **OpenAI Codex / ChatGPT**, **Devin**, **Windsurf/Codeium**, **Google Gemini** (incl. Gemini Code Assist). Cursor and others are later candidates.

## 2. PO decisions already taken (do not reopen)

| Topic | Decision |
|---|---|
| Product and repository | Product family **rwsafe**. This product's repo is `github.com/ozandurmus/rwsafe-ai-gateway`. Later products are added as `rwsafe-<name>` repos; a shared `rwsafe-platform` repo may come later. |
| Hosting | Same single server as neXus (HOST-A, below). There is no other server. rwsafe gets **its own infrastructure on it**: its own namespace, database instance, secrets, images and quotas. It must **never conflict** with neXus. |
| Browser access | A **reverse proxy in front** routes by **host name** on 443: `nexus.<corp-domain>` to neXus and `rwsafe.<corp-domain>` to rwsafe. Nobody types a port. Cookies, sessions and CSP stay separate per product. |
| Prompt content | Legal/KVKK approval exists. **Prompt and response capture is on from the start**, but always role-restricted, masked in AI-agent and masked views, retention-bounded and audited. |
| Inline inspection | Broadcom **ProxySG** with **SSL interception on**, or on for a restricted pilot group, is the primary inline path. ICAP from ProxySG to rwsafe is the expected integration. |
| Off-network / cloud proxy | Broadcom **Edge SWG (cloud)** also does SSL interception, but it probably **cannot send ICAP to an on-prem service**. That path needs a **different design**, likely **agent-based**. The PO notes Check Point appears to use an agent here. You must propose it. |
| Language and stack | **Java**, as in neXus. The same framework discipline from day one (section 7). |
| Governance | A **security council** works from the first design step. The product has its **own** markdown rule set (AGENTS.md, CLAUDE.md, roles, decision records) and its **own privacy gates**. These mirror neXus's critical rules. |
| UI | Same visual language and interaction model as neXus (`docs/design/UI_DESIGN_LANGUAGE.md` in the neXus repo). An operator moving between the two products must feel at home. |

## 3. Reference material you must read first

The neXus repository is checked out at `~/Codo/nexus-ship` (main branch of `github.com/ozandurmus/neXus`). Read at least:

- `AGENTS.md`, `CLAUDE.md`, `roles/` (operating rules, reading order, model tiers)
- `docs/design/SECURE_SDLC_SSDF_MAPPING.md` and `docs/design/PO_DECISION_RECORD_2026_09_30_SECURE_SDLC_DAILY_SCANS.md`
- `docs/design/UI_DESIGN_LANGUAGE.md`
- the `docs/design/PO_DECISION_RECORD_*` pattern (how a PO decision is recorded, quoted and ratified)
- `deploy/ui2/*.yaml` (namespace, Postgres StatefulSet, Deployments, Ingress `ui2.nexus.local`, secrets layout, ConfigMap usage, `README-failover-pilot.md`)
- `tools/delivery/standalone_orchestrate.py`, `tools/delivery/hosta_deploy.sh`, `tools/delivery/module_deploy.py`, `tools/e2e/`, `tools/security/` (ship pipeline, preview e2e, security gate, deploy, drain)
- `scripts/consult_*.py`, `scripts/argon_task.py` (external reviews and Argon/Antigravity worker lanes)
- the gate registry concept (`ui2/capability-registry/.../gate_registry_fixture.yaml`): every device command is pre-approved, exact and versioned. rwsafe needs the same idea for **policies and enforcement actions**.
- the privacy/DLP gate, the masking and `replay_viewer` model, and the `.gitleaks.toml` + `security/baseline.yaml` acceptance model with owner and review date.

Competitive and reference products to study (cite sources; prefer vendor docs):
- **Lakera Guard** (API guardrails, prompt-injection detection)
- **Check Point AI security** (GenAI Protect, browser/endpoint-agent approach, AI security posture)
- **Prompt Security**
- **Netskope** and **Zscaler** AI/GenAI controls
- **Microsoft Purview** for AI, Google and GitHub enterprise controls
- the **OWASP Top 10 for LLM Applications**

## 4. Hosting constraints: HOST-A

What we know (verify read-only; see the end of this section):
- One on-prem Linux server, already **hardened**, running **k3s**.
- neXus runs in namespace `ui2`. Its Postgres is the StatefulSet `ui2-db` (port 5432, cluster-internal only). Its service listens on 8080 and its internal services on 8084, 8085, 8086 and 8087. The Ingress `ui2.nexus.local` serves 443 through the k3s ingress controller.
- There are separate namespaces for builds (`ui2-build`) and security scanners (`ui2-security`).
- The local image registry is at `registry.kube-system.svc.cluster.local`. Images are digest-pinned.
- Disk was about 60% used in October 2026.

Hard rules:
1. **Own namespace** (e.g. `rwsafe`), with its own ResourceQuota and LimitRange sized so that neXus can never be starved. NetworkPolicies deny cross-namespace traffic by default; open only what is required.
2. **Own database instance**: a separate Postgres StatefulSet, PVC and credentials. Never a schema inside neXus's database.
3. **No port conflicts.** Inventory the ports actually listening on HOST-A (host network, NodePorts, hostPorts, syslog and other receivers) before choosing any. Propose explicit ports:
   - ICAP: 1344 is the standard; propose and justify;
   - the LLM API gateway;
   - the optional chained forward proxy for WebSocket;
   - SNMP;
   - syslog out.
4. **Reverse proxy:** prefer the existing k3s ingress controller with host-based routing over a new component. Any change to the neXus ingress, for example its host name, is a **separate neXus change** delivered through neXus's own PR pipeline with zero downtime. Say exactly what it is.
5. **Hardening exceptions** must be minimal, each listed with reason, source and destination and duration, for PO approval. Example: inbound ICAP only from the ProxySG addresses. If an exception is not needed, say so.
6. All runtime configuration lives in **manifests and ConfigMaps/Secrets in the repo**, never in one-off `kubectl set env`. neXus learned that the hard way (section 8).

**Access.** You work on HOST-A the way the neXus engineering session does: SSH to the host named in the first line of `~/.config/nexus/hosta`, then `export KUBECONFIG=$HOME/.kube/config`. Inspection is read-only (`kubectl get/describe/logs`, `ss -ltnp`, `df`, read-only SQL) and always follows the masking rules of section 4A. Ask the PO before anything that changes or deletes something on the host. HOST-A is never used as a jump server.

## 4A. Privacy and masking: the most important rule set

This applies both to how you work and to what the product does.

The PO's standing rule: an AI agent may work on real systems **only if it never sees raw identifying data**. It works on masked data, sees masked views, and reports relationships and counts, never values. This rule is what lets Fable, Opus and the subagents work on rwsafe the same way the neXus session works on neXus. Every point below is a hard requirement.

**How you, and every agent on this project, work**

1. **Never read raw production data before it is anonymised.** Raw data means traffic captures, logs, prompts, customer files, device output and screenshots with real names. Pass it through the sanitizer first: neXus `ui2/sanitizer` (local runner in `~/Codo/ops-scripts/sanitize/`), plus a second pass for host names, account names and long numbers. Read only the sanitized copy. If a raw export is needed, write it to a file you do not read.
2. **Never write real identifiers anywhere.** That covers host names, IP addresses, serials, account names, domain names, cluster names and e-mail addresses, in chat, commits, PR text, docs, tests or code. Use pseudonyms (`<masked-address>`, `FW-<WORD>-NN`) and counts. Real names that must exist at runtime live in Kubernetes ConfigMaps or Secrets that are never committed.
3. **Mask HOST-A output before you look at it.** Filter out IPs, host names and account names; print shapes and counts, not values. Read-only SQL selects counts and classes, never identifying columns.
4. **Do not pass on material with real names.** Screenshots or text from the PO that show real names are never forwarded to other agents or external reviewers. Describe them in words instead.
5. **Build secret-shaped test values at runtime.** A literal that matches a secret pattern blocks the deploy (gitleaks).
6. **External reviewers get masked material only.** Argon, Codex, Copilot and Fable receive it only through the authorised scripts.

**What the product must do: design it in, do not bolt it on**

1. **Masked role for AI agents and auditors.** This is a `replay_viewer`-style role. Every API response for it passes through a masking layer, keyed by an HMAC key Secret. In neXus that layer is `PrivacyMaskingResponseBodyAdvice`, `TopologyNamePseudonymizer`, `SubnetPreservingIpMasker`, `PseudonymRegistry` and `ReportProjectionMasker`.
   - Pseudonyms are stable per estate, so an agent can correlate records without ever seeing the real value.
   - Operators see real names; the masked role never does.
2. **Prompt and response content is the most sensitive data the product holds.** For the masked role and every AI-facing path, mask content in layers, the way neXus log masking does (logmask-v1 to v4):
   - sanitizer text rules (IPs, e-mails, URLs);
   - identity fields in JSON;
   - an estate dictionary of known names (hosts, users, domains, projects);
   - a heuristic free-text pass (host-shaped tokens, the word after "host", "user", "from" or "to");
   - secret detectors.

   Return the rule-set version with every masked page.
3. **Fail closed.** If the masking dictionary or key is unavailable, refuse the masked request (neXus returns 503). Never serve it unmasked.
4. **Leak probe in CI.** An automated canary probe walks every screen and tab as the masked role and checks that no canary value appears. It compares token digests and reports only the class of the location, never the value (neXus `tools/e2e/e2e_canary_digests.py` and `canary.js`). A leak blocks the release.
5. **Exports follow the same masking.** CSV, XLSX, PDF and SIEM output for masked roles are masked too, including spreadsheet cells by column meaning (neXus masks XLSX serial columns by header).
6. **Raw capture handling.** Raw prompts and payloads are encrypted at rest (artefact store with a key Secret) and kept only for a set retention period. Every read of raw content is audited with actor and reason.
7. **Repository privacy gate.** A pre-merge check rejects real IPs, host names, serials and secret-shaped literals in any committed file. Exceptions go on a small allowlist where every entry has an owner and a date.

Before designing this part, read in the neXus repo:
- `docs/design/UI2_0_PRODUCTION_REPLAY_ROLE_ANONYMIZED_VIEW_DESIGN.md`
- `ui2/service/src/main/java/com/securityexpert/nexus/ui2/service/privacy/`
- `ui2/sanitizer/`
- the log masking code (`LogMasking`, `FreeTextIdentityRules`)
- `tools/e2e/e2e_canary_digests.py`

Produce `docs/security/MASKING_AND_PRIVACY.md` as a separate deliverable.

## 5. Functional requirements (to be refined in the design)

**A. Enterprise-account enforcement (first priority)**
- Per platform, the best control:
  1. tenant-restriction headers injected by ProxySG, where the vendor supports them (verify each from vendor docs: Microsoft, Google Workspace, GitHub Enterprise, OpenAI workspace, Anthropic organisation);
  2. otherwise ICAP inspection of the login/OAuth flow, allowing only corporate identities and tenants;
  3. otherwise an endpoint agent or managed IDE/CLI settings. Examples: Claude Code managed settings that force the organisation login; Copilot enterprise policies.
- Produce a **per-platform matrix**: domains, auth endpoints, which control applies, what can and cannot be enforced, and the evidence.

**B. Prompt and response visibility**
- Parse requests and responses per platform (web UI, IDE extension, CLI, API), including streaming (SSE, chunked) and **WebSocket** traffic.
- Store per policy: who, platform, tool, tenant, model, time, size, risk verdict, and content (masked, retention-bounded).
- Search and review UI. Export to SIEM.

**C. Guardrails**
- Detect secrets (keys, tokens), PII, customer data, internal IPs/hostnames, and source-code exfiltration patterns; use the classifiers you find to be standard.
- Detect prompt injection and jailbreak attempts in tool/agent traffic.
- Actions: allow, warn, redact, block. Every action and policy change is audited.
- Policy registry: versioned, exact and approval-gated, like neXus's gate registry.

**D. LLM API gateway**
- An OpenAI/Anthropic-compatible endpoint for API-key based tools, for example `ANTHROPIC_BASE_URL` and `OPENAI_BASE_URL`.
- Corporate keys are held server-side. Personal keys are blocked at the proxy.
- Per-team quotas and cost reporting.

**E. Off-network / Edge SWG path**
- Design the agent-based option (browser extension, endpoint agent and/or IDE extension) for users behind Edge SWG or off-net, and for clients that pin certificates.
- Compare it with how Check Point and the others do it.

**F. Administration parity with neXus, from day one**
- LDAP/AD login with group-to-role binding, plus local break-glass.
- RBAC with at least security_admin, operation_admin, operator, auditor/viewer, and a **masked replay-viewer role for AI agents**.
- Audit log enforced by database triggers (actor and action set per transaction).
- Syslog/SIEM out, SNMP, SMTP notifications.
- System health and change-feed screens.
- **CLI parity for every UI action.**
- Backup and restore of its own configuration.
- Business-hours confirmation for admin actions where it applies.

## 6. Non-functional requirements

- **Performance:** inline latency budget per request for the ICAP path (propose a number), fail-open or fail-closed per policy with an explicit default and the reason, and horizontal scaling within the namespace quota.
- **Availability:** what happens to ProxySG traffic when rwsafe is down or being deployed.
- **Privacy:** masking in every AI-facing view, retention, access review, and data minimisation per KVKK.
- **Security:** threat model (STRIDE) for every external interface: ICAP, gateway, admin UI, agent channel, SIEM out.

## 7. Engineering discipline required from the first commit (mirrors neXus)

- **Stack:** Java 21, Spring Boot, jOOQ, Flyway; Gradle with lockfiles and dependency verification metadata; React + TypeScript + MUI frontend; Vitest; Playwright e2e. Justify any deviation.
- **Changes:**
  - every change goes through a GitHub PR;
  - nobody pushes to main;
  - the orchestrator merges after checks.
- **Tests before every ship:**
  - unit tests, architecture tests, frontend tests and tsc;
  - Postgres integration tests run **against the branch** in a cluster Job;
  - preview e2e;
  - post-deploy e2e.
- **Security gate in the ship pipeline:**
  - Semgrep (Java/TS), gitleaks (tree and history), trivy (filesystem, config, image, SBOM);
  - weekly ZAP;
  - a new unaccepted HIGH/CRITICAL stops the rollout;
  - acceptances carry a reason, owner and review date, with daily review of "fix available / review due".
- **Privacy gate in the repo:**
  - no real IPs, host names, serials or account names in code, tests, docs or commits;
  - secret-shaped test fixtures are built at runtime, never as literals.
- **Migrations:** every migration is dry-run in BEGIN/ROLLBACK on the live database before deploy.
- **Decision records:** the PO's words are quoted; status RATIFIED or DRAFT.
- **SSDF:** a NIST SSDF (SP 800-218) mapping from day one. The gaps neXus still has must be closed here from the start:
  - threat model;
  - security requirements catalogue mapped to tests;
  - vulnerability SLA;
  - root-cause log;
  - a rule limiting when preview e2e may be skipped;
  - mandatory second independent review for security-sensitive PRs;
  - signed images and provenance (SLSA level 2 target).
- **Security council:** independent review seats at design freeze and for every security-sensitive decision. Use neXus's council process as the model.
- **Multi-agent work:**
  - the repo must let Claude subagents, Codex, GitHub Copilot and Antigravity/Argon work in it;
  - reuse neXus's orchestration and APIs (standalone ship orchestrator, `argon_task.py`, `consult_*` review scripts) rather than reinventing them. Decide whether rwsafe vendors a copy or a shared tooling package is extracted, and justify;
  - external reviews always run through the authorised scripts, never as simulated personas.
- **Chat and artifacts:** chat with the PO is in Turkish; every repository artifact is in English.

## 8. Lessons from neXus to design in, so they never recur

- **Configuration drift:** env vars set by hand with kubectl were silently dropped by the next manifest apply, and the deploy refused a manifest that conflicted with them. Keep all config in versioned manifests and ConfigMaps; put real names (cluster lists, hosts) in ConfigMaps that are not committed.
- **The deploy updates only images.** Design the deploy to apply manifests and config consistently and to report drift.
- **Drains and stale locks:** a quarantined lease left by a stopped operation blocked a module drain, so nightly jobs piled up. Design leases to be released on terminal states, and make the deploy say exactly which condition it is waiting on.
- **Protected windows:** scheduled work runs in fixed windows (neXus: 00/06/12/18); deploys avoid them; admin manual actions are never blocked, only confirmed during business hours.
- **Device-facing sessions:** one session, not a burst of logins. Gaia logged every SSH exec channel as a separate log-in; neXus moved to a framed single shell. Any rwsafe component that talks to devices or proxies must keep audit noise minimal.
- **Base-image CVEs:** they arrive weekly with no fix available. Have a policy for time-boxed acceptance, daily review and base-image update cadence. Never accept silently.
- **Helper scripts and logs** kept in `/tmp` were wiped. Keep operational scripts versioned in the repo.
- **Branch tests:** an integration script once tested main instead of the branch. Make the CI prove which commit it tested.
- **Raw data:** never read raw production data (traffic, logs, prompts) before it is anonymised or masked. AI agents only see masked views.
- **Screens:** they are judged by the purpose they serve, not by feature count. Errors show the server's reason, never a bare "Request failed".

## 9. Deliverables of this design phase

Create the repository skeleton for `rwsafe-ai-gateway` locally. The PO creates the GitHub repo. It should contain:

1. `docs/architecture/ARCHITECTURE.md`: C4 context, container and component views; data flows for ICAP, the LLM gateway, the agent channel and admin; sequence diagrams for login enforcement, prompt capture with redaction, and a blocked request.
2. `docs/adr/` with ADRs for at least:
   - hosting and namespace isolation;
   - the separate database instance;
   - the reverse proxy and host-based routing (including the exact neXus change);
   - ICAP vs chained proxy vs agent per traffic type;
   - the WebSocket/streaming strategy;
   - the Edge SWG / off-net agent strategy;
   - tenant restriction per vendor;
   - the guardrail engine (build vs integrate);
   - data model, retention and privacy;
   - fail-open/fail-closed;
   - shared tooling with neXus.
3. `docs/security/THREAT_MODEL.md` (STRIDE per interface), `docs/security/SECURITY_REQUIREMENTS.md` (each requirement with the test that will prove it) and `docs/security/MASKING_AND_PRIVACY.md` (section 4A: the agent rules and the product design).
4. `docs/operations/PORTS_AND_RESOURCES.md`: the port plan and resource quotas, with the conflict check against neXus, from your own read-only inventory of HOST-A; `docs/operations/HARDENING_EXCEPTIONS.md` for PO approval.
5. Governance files mirroring neXus:
   - `AGENTS.md`, `CLAUDE.md`, `roles/`;
   - a decision-record template;
   - `docs/design/SECURE_SDLC_SSDF_MAPPING.md`;
   - privacy gate and gitleaks/baseline configuration;
   - the ship pipeline plan (what is reused from neXus and how).
6. `docs/product/PLATFORM_MATRIX.md`: per AI platform, the domains, auth flow, controls, limits and evidence links.
7. `docs/product/COMPETITIVE_REFERENCE.md`: Lakera, Check Point, Prompt Security, Netskope, Zscaler and Microsoft; what to adopt and what to avoid, with sources.
8. `docs/product/ROADMAP.md`:
   - phase 0 discovery: measure proxy logs, verify vendor headers, ProxySG ICAP/WebSocket capability, with no production change;
   - phase 1 quick wins: tenant headers on ProxySG;
   - MVP: ICAP enforcement, prompt capture, admin baseline;
   - then the LLM gateway, then the agent path and advanced guardrails.

   Each phase has acceptance criteria and a size and risk estimate.
9. `docs/product/OPEN_QUESTIONS.md`: what the PO must decide, batched, with your recommendation for each.
10. A **security council review** of the frozen design, run through the authorised review scripts, recorded in `docs/reviews/`. Implementation starts only after the PO accepts it.

Rules for this phase:
- **Do not** change HOST-A, neXus, ProxySG or any production system.
- Mark every vendor-specific fact you could not verify from a primary source as **UNVERIFIED**.
- Where you need a PO decision, put it in OPEN_QUESTIONS.md instead of assuming.

---

## 10. Council review of this brief (2026-10-30): binding additions

Before handing this brief over, a three-seat council reviewed it:
- privacy and compliance (Fable);
- offensive security (Fable);
- platform and architecture (Argon).

Their unaltered outputs are in `council/` next to this file. Copy them to `docs/reviews/` in the repo. Your design must answer **every P0 below explicitly**, by ID, in `docs/reviews/COUNCIL_RESPONSE.md`. Answer the P1 items or defer them with a reason. Where a council recommendation conflicts with a PO decision in section 2, do not overrule the PO: present the conflict in OPEN_QUESTIONS.md with both options.

### 10.1 Architecture and platform (P0)

- **ARCH-1 Separate the data plane from the control plane.** The inline ICAP and LLM-gateway path is stateless:
  - it decides from an in-memory, compiled policy snapshot;
  - it never makes a synchronous database write, trigger call or blocking disk I/O on the request thread;
  - capture and audit events leave through a bounded asynchronous queue with an explicit overflow policy.

  Inline p99 latency must not depend on Postgres. neXus's single-replica, Recreate, trigger-heavy service pattern is not acceptable for the hot path.
- **ARCH-2 Real isolation on the shared node, beyond ResourceQuota.**
  - rwsafe pods get a PriorityClass strictly lower than neXus (neXus uses `system-cluster-critical`) and no disk-pressure toleration.
  - There is a hard byte cap on rwsafe storage, and a disk-free watermark circuit breaker that stops persisting raw bodies first.
  - Coding-agent contexts repeat the same repository content on every turn, so store it content-addressed and deduplicated.
  - Show the sum of neXus and rwsafe requests and limits plus system overhead against HOST-A's real capacity, with at least 25% headroom. HOST-A disk is already at 80%, mostly neXus backups.
- **ARCH-3 Ingress facts.**
  - `deploy/ui2/60-ingress.yaml` has a host-less catch-all rule as well as `ui2.nexus.local`.
  - `tools/delivery/hosta_deploy.sh` health-checks `https://127.0.0.1/` without a Host header.

  Give the exact neXus diff for both files and the per-SNI TLS certificate binding. Prefer to route the LLM API gateway over 443 by host name (for example `ai-api.<corp-domain>`) instead of a new port. A request with an unknown Host or a bare IP gets an explicit 404 default backend. Use `__Host-` cookies, host-only CSP and HSTS, and keep ingress snippet annotations off.
- **ARCH-4 The Java ICAP engine is a protocol design of its own.**
  - Spring has no RFC 3507 server, so use a Netty-based engine.
  - Specify the OPTIONS / Preview / 100-Continue / 204 state machine, direct-buffer caps, and maximum in-flight bytes per connection.
  - RESPMOD on SSE must never buffer the whole stream (that breaks IDEs and CLIs): use sliding-window inspection with abort on a high-confidence leak, and audit the rest asynchronously.
- **ARCH-5 Zero-downtime rollout on a single node.**
  - No `hostPort` and no `Recreate` for ICAP or the gateway; at least 2 replicas, RollingUpdate with `maxUnavailable: 0`, and a PodDisruptionBudget.
  - Expose port 1344 through a Service, not hostPort.
  - A preStop drain closes ProxySG's pooled ICAP connections gracefully. Prove it with 0 dropped requests during `kubectl rollout restart` under load.
- **ARCH-6 Linear-time inspection.**
  - No backtracking `java.util.regex` on the inline path; use RE2/J or equivalent.
  - Set explicit body, decompression and recursion limits.
  - Fuzz the ICAP and HTTP parsers (Jazzer) in CI.
  - A parse failure produces an explicit verdict; it never silently allows.
- **ARCH-7 Classifier CPU budget.** HOST-A has no GPU. Split classifiers into tiers:
  - deterministic rules inline, within a measured CPU-ms budget per 4 KB and 64 KB prompt;
  - ML classifiers asynchronous or bounded, with a circuit breaker.

### 10.2 Privacy and compliance (P0)

- **PRIV-1 Legal basis per data class**, mapped to KVKK articles and the VERBIS inventory. The classes are: metadata, verdict, redacted content, raw content, special-category data that appears inside prompts (art. 6), DLP findings, audit, SIEM copies, exports, backups and the evaluation corpus.
- **PRIV-2 Notice is part of the product (art. 10).** Show it in the coaching/block page, the first-use banner and on first IDE use, and record acceptance. Recommendation: content capture stays off for a user who has no acceptance record. End-user texts are in **Turkish** (i18n); the repository stays in English.
- **PRIV-3 Cross-border transfer (art. 9) and banking secrecy.** For each platform, the matrix records:
  - data region;
  - enterprise DPA and zero-retention status, with evidence;
  - which data classes may never leave.

  The "customer data / banking secret" DLP class is fail-closed. Assess the sector regulator's information-systems and secrecy-sharing rules (BDDK-style): primary system location, audit-trail retention and outsourcing notification.
- **PRIV-4 Data classes and retention matrix**, with how deletion reaches backups, SIEM and exports. Use crypto-shredding for raw content. Legal hold.
- **PRIV-5 Data-subject requests (art. 11).** An authorised, audited, reason-coded search path that can find a person's records, separate from the masked-only search.
- **PRIV-6 Pseudonymisation is not anonymisation.** By default, prompt bodies **never** go to external reviewers or to the masked role; they see derived features only. Any exception is a signed residual risk.
- **PRIV-7 Never store matched sensitive values.** DLP findings store class, offset and digest; detected secrets and PII are redacted **before** anything is persisted, so the prompt store does not become the organisation's largest secret archive.
- **PRIV-8 No secondary use.** Captured content is never used to train models, for productivity analytics or for other products.
- **PRIV-9 Raw access.**
  - No single admin can open raw content: just-in-time access, four eyes, reason code, time limit and a notice to the DPO;
  - an out-of-band audit copy goes to the SIEM immediately;
  - add a separate `privacy_officer` role, and decide who may change masking and retention rules.
- **PRIV-10 Bodies never in logs.** Request bodies never appear in logs, stack traces or heap dumps (heap dumps off or encrypted), and a log-scanner test proves it.

P1 for privacy:
- privacy impact assessment;
- 72-hour breach runbook;
- 5651 logging obligations versus ProxySG logs;
- contractors, BYOD and personal profiles;
- for blocked personal logins, store the event and not the content;
- encrypted backups whose restore does not bring back expired data;
- quarterly access review;
- synthetic prompt bodies in test corpora;
- small-team aggregation thresholds in analytics.

### 10.3 Offensive security (P0)

- **SEC-1 Blind-spot matrix.** For each platform flow, the matrix says whether ProxySG can hand it to ICAP: WebSocket after upgrade, HTTP/2, bodies above the ICAP max size (fail-open by default), gRPC trailers, file uploads. Each flow is marked enforceable, log-only or invisible, with the compensating control.
- **SEC-2 Cloud-side agents never pass the proxy.** Devin, Codex cloud, Copilot coding agent, Claude Code on the web and Gemini cloud agents pull code into their own clouds. Their enforcement point is the vendor tenant settings. Declare them out of gateway scope and name the compensating control.
- **SEC-3 ICAP identity spoofing.** `X-Authenticated-User` is only ProxySG's claim. Require:
  - Secure ICAP with mTLS;
  - a source-IP allowlist;
  - a "claimed by proxy" trust label on every identity.

  Handle VDI, terminal servers and NAT, where surrogate identities mix users.
- **SEC-4 DLP evasion.** Cover:
  - normalisation (Base64, zero-width, homoglyphs, Unicode tag characters) and nested decoding depth;
  - archives and images (whether OCR is in the MVP);
  - splitting across many small prompts, using per-user volume thresholds.

  Produce a bypass catalogue with an expected result and a test per technique. Pilot acceptance depends on these tests.
- **SEC-5 Stored prompts are hostile input.** The review UI renders them inert, to prevent:
  - stored XSS;
  - CSV formula injection;
  - CR/LF and ANSI injection into syslog and SIEM;
  - **prompt injection against any AI agent that reads the masked view**. Frame the content as untrusted.
- **SEC-6 Coverage metric.** Continuously compare the AI requests ProxySG saw with the requests rwsafe saw, and alert below a threshold. ProxySG fail-open events go to the SIEM.
- **SEC-7 SSL-interception bypass audit (phase 0, read-only).** Existing bypass lists often exempt googleapis, GitHub and M365, which blinds Gemini and Copilot. New, uncategorised AI domains are inspected by default.

P1 for offensive security:
- **Per-client trust matrix:** Claude Code `NODE_EXTRA_CA_CERTS`, JetBrains JVM cacerts, Rust/Electron/mobile trust stores, and which clients pin.
- **Tenant headers do not revoke existing sessions.** Personal API keys, Bedrock/Vertex routing and third-party relays bypass org login; validate tenant at the cookie and Authorization level, and block known relays.
- **Re-identification through stable pseudonyms in the masked role.** No raw-value filters there. rwsafe gets its own HMAC key, separate from neXus.
- **LLM gateway as an open relay:** short-lived client credentials bound to user and device; a fixed upstream list (no SSRF); cache isolation.
- **Agent channel hardening:** device attestation and mTLS with the MDM certificate, signed updates, no local privilege escalation. A Manifest V3 browser-extension feasibility spike is a design deliverable, because MV3 cannot read request bodies directly.
- **Model and rule-pack supply chain:** safetensors only, signed packs, licence and provenance records.
- **k3s Secrets encryption at rest:** Pod Security Admission restricted, no hostPath, CAP_NET_RAW dropped.
- **Responses as an attack path:** RESPMOD detection of injection coming back from web content or MCP tools.

### 10.4 Additions from the engineering session (also binding)

- **Scope.** Non-goals, personas (security analyst, privacy officer, platform admin, end user, AI-agent reviewer) and success metrics:
  - share of AI traffic on enterprise tenants;
  - personal logins blocked;
  - DLP incidents and their false-positive rate;
  - inline p95/p99;
  - coverage ratio (SEC-6).
- **Policy lifecycle.** Policy as code with versioning and approval:
  - a **monitor-only/simulation mode** before enforce;
  - staged rollout by AD group, starting with a pilot group;
  - exceptions with an expiry date;
  - break-glass;
  - an end-user coaching/block page with a justification flow.
- **Shadow-AI discovery** from aggregated proxy metadata: inventory and risk scoring of AI services, and new-domain detection.
- **Agentic AI and MCP governance:**
  - inspection of coding agents' tool calls where they are visible;
  - an MCP server allowlist;
  - secrets in agent context;
  - managed settings and hooks for Claude Code, and Copilot agent policies.
- **Integrations.** SIEM in CEF/LEEF/Splunk format, an alert taxonomy and incident workflow, SOAR hooks; integration with neXus without coupling (shared LDAP source and SIEM only).
- **Testing.**
  - Sanitized protocol-frame replay fixtures for each platform, with synthetic bodies.
  - **Protocol-drift detection**: when a vendor changes its API, the parser fails loudly.
  - Production canary prompts, synthetic and excluded from statistics, that continuously prove enforcement.
  - An in-cluster post-deploy ICAP e2e Job.
- **Self-observability.** Metrics and traces never carry raw prompt, user or tenant strings as labels. Track JVM GC, direct memory, ICAP queue depth and the 204 fast-path ratio.
- **Shared delivery tooling.** neXus scripts hard-code `nexus-*` worktrees, `~/nexus.git`, `/tmp/nexus_build.log` and the `ui2` namespace. Design a per-repo delivery manifest so both products share one engine without collisions, including a build lock so builds never overlap neXus deploys or the protected windows, and registry garbage-collection rules.
- **Portability.** The OpenShift rules neXus follows (`PORT-1`, `PORT-3` in `deploy/ui2/00-namespace.yaml`): arbitrary UID, read-only root filesystem, no ResourceQuota/LimitRange/Ingress in the base manifests (they go in a k3s overlay), and digest-pinned images.

### 10.5 Additional deliverables and design-freeze acceptance criteria

Add to section 9:
- `docs/architecture/ICAP_AND_STREAMING_PROTOCOL_SPEC.md`
- `docs/operations/CAPACITY_AND_SLO_MODEL.md`, sized from HOST-A's real CPU, RAM and disk
- `docs/operations/DEPLOY_AND_SHARED_HOST_RUNBOOK.md`
- `docs/security/PRIVACY_IMPACT_ASSESSMENT.md`
- `docs/security/DATA_CLASSES_AND_RETENTION.md`
- `docs/security/RAW_CONTENT_ACCESS.md`
- `docs/compliance/REGULATORY_MAPPING.md`: KVKK articles, the sector regulator's information-systems and secrecy rules, 5651, ISO 27001 / 42001, NIST AI RMF, OWASP LLM Top 10
- `docs/security/BYPASS_CATALOGUE.md`
- `docs/product/OUT_OF_SCOPE.md` (cloud-side agents, pinned clients, with compensating controls)
- Turkish end-user text templates
- the MV3 browser-extension feasibility note
- a pre-pilot independent penetration test plan covering ICAP fuzzing and agent tampering

Design freeze is accepted only when all of the following hold:
- **AC-1:** the capacity sum against HOST-A shows at least 25% headroom, and the rwsafe PriorityClass is below neXus.
- **AC-2:** the rollout design gives 0 dropped requests and no hostPort deadlock.
- **AC-3:** no backtracking regex, blocking JDBC or unbounded allocation on the inline path, and payload limits are stated.
- **AC-4:** the workloads pass the OpenShift portability checklist.
- **AC-5:** the masking leak probe includes Turkish identifiers (TCKN with checksum, TR IBAN, phone numbers, customer numbers, Turkish names) and the prompt-body screens.
- **AC-6:** each of the following is a designed test:
  - a raw read without a reason returns 403 and is audited;
  - a missing masking dictionary returns 503;
  - exports are masked;
  - the log scanner finds no bodies;
  - the DSAR search works;
  - after deletion, nothing remains in backups or the SIEM;
  - external review scripts send no content.
- **AC-7:** the bypass catalogue and the coverage metric exist, each with a target.
- **AC-8:** every council P0 has a written answer in `COUNCIL_RESPONSE.md`.

### 10.6 Open questions already known (put them first in OPEN_QUESTIONS.md, with your recommendation)

1. **SSE responses.** Strict inline blocking on REQMOD plus sliding-window RESPMOD with abort, instead of buffering? Council: yes.
2. **LLM API gateway on 443** through its own host name? Council: yes.
3. **Disk watermark.** Above it (for example 75% disk used), stop persisting raw bodies but keep enforcing and keep metadata? Council: yes.
4. **MVP capture mode.** The PO decided capture is on from day one. The privacy seat recommends starting with metadata, verdict and redacted content, with raw content behind a separate key and an approval record. Present both options.
5. **Raw-content access.** Who approves it, the identity of the DPO, and the retention days per data class.
6. **Scope of people and use.** BYOD and contractor scope, and the personal-AI-use policy: blocked, or allowed but not captured.
7. **Models and regions.** The allowlist per data class.
8. **Cloud-side agents.** Accept them as out of gateway scope, governed by tenant settings?
