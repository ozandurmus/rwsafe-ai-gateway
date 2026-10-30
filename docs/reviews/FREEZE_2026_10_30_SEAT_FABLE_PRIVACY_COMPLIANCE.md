<!-- Fable consultation 2026-10-30T08:07:54Z, model claude-fable-5-1, exit 0; unaltered output -->

Rolüm: REVIEWER (privacy-compliance seat). Görev talimatı çıktıyı İngilizce istediği ve bu çıktı `docs/reviews/` altına kaydedilecek bir depo artefaktı olduğu için gözden geçirme aşağıda İngilizce verilmiştir.

**Seat: privacy-compliance. Scope read: AGENTS.md and the listed files only. No edits, no shell.**

## 1. CONSENT

| Area | Verdict |
|---|---|
| Data-class vocabulary C1–C14 with purpose, basis, store, retention, hold, deletion proof, backup and SIEM columns (ADR-009 §1, DATA_CLASSES §1) | Consent; retention figures remain the PO's Q-5 |
| One deletion path for expiry and DSAR: receipts, chunk reference counts, crypto-shred, SIEM deletion event, backup restore replays receipts (ADR-009 §4, DATA_CLASSES §2) | Consent |
| Findings store class, offset, length, digest, never the value; capture sink rejects C3 text with a live hit (SR-PRIV-11) | Consent (retention of PII digests: see PC-6) |
| No secondary use, synthetic corpus only, k ≥ 5 team analytics as a registry constant with a test (ADR-009 §8) | Consent |
| Four-eyes JIT raw grant object, reason codes, ≤ 4 h, DPO notice, SIEM copy, watermark, per-view audit, refusal matrix (RAW_CONTENT_ACCESS §1–5) | Consent, except break-glass (PC-8) |
| Separate DSAR search for `privacy_officer`, objection as no-capture group with enforcement continuing | Consent (notice must say so: PC-1) |
| Masking funnel: single server-side advice, six layers, Turkish identifiers first-class, 503 fail-closed, own HMAC key, pseudonym registry (MASKING B2–B3) | Consent |
| No prompt body to masked role or external reviewers by default; untrusted framing on signed exception (AGENTS.md 4.7, MASKING B4) | Consent |
| Bodies never in logs, traces, labels, heap dumps; log-scanner e2e (ADR-009 §7, SR-PRIV-6) | Consent |
| Repository privacy gate with Turkish identifier rules and expiring allowlist (MASKING B8, SR-PRIV-13) | Consent |
| Pseudonymisation explicitly not anonymisation (REGULATORY_MAPPING art. 7, PIA §5) | Consent |
| 5651 position: ProxySG log is the statutory record, C1 is not presented as one | Consent |
| Turkish end-user texts under `docs/i18n/tr`, English keys, notice version in C12 | Consent on the mechanism (content gaps: PC-1) |
| Q-4 recommendation (b), Q-5 retention set, Q-6 recommendation (a)+(c), Q-7 fail-closed start | Consent |
| Test plan Part C (MASKING) and SR-PRIV-1..13 mapping to AC-5/AC-6 | Consent |

## 2. DISSENT

| Id | Document and section | What is wrong | Concrete correction |
|---|---|---|---|
| PC-1 | `docs/i18n/tr/notice_first_use.md`; `docs/i18n/README.md` placeholders | The notice lacks mandatory art. 10 elements: identity of the data controller, to whom data is transferred and why (the AI vendor abroad for prompt content, the SIEM for metadata), the method and legal reason of collection (automated, via the proxy), and the consequence of objection (no capture, inspection continues). Without these the acknowledgement record proves an invalid notice. | Add `{{controller_name}}` and a transfer paragraph naming the vendor category and "yurt dışı"; add a sentence on automated collection through the proxy; add the objection sentence; list `retention_*`, `notice_version`, `controller_name` in the README placeholder table; rule: any change to a placeholder's value bumps `notice_version` and requires re-acknowledgement. |
| PC-2 | DATA_CLASSES §1 row C3 ("with the notice and acceptance"); ADR-009 §1 C12; MASKING Part C "Notice gate"; COUNCIL_RESPONSE PRIV-2 | "Acceptance" reads as consent. Consent in an employment relationship is not freely given and is revocable, so it cannot carry C3. The gate is correct, the wording turns notice into a lawful-basis switch. | Rename C12 to "notice acknowledgement" everywhere; add one line in REGULATORY_MAPPING art. 5: explicit consent (art. 5/1) is deliberately not a basis; the gate exists only as proof of art. 10 and as a proportionality control. |
| PC-3 | ADR-009 §1 C12 "surface"; `docs/i18n/README.md` | IDE, CLI and API-gateway users never see a banner or a block page, so they cannot acknowledge. Either they stay in metadata-only mode forever (capture design silently void for coding agents) or they get captured without notice. | C12 accepts a second source: an HR/policy acknowledgement with version imported from the directory (attribute or group); the gateway records acknowledgement at credential issuance and returns the notice URL in the API error body; SR-PRIV-10 test covers both sources. |
| PC-4 | OPEN_QUESTIONS Q-7 ("public data: all enterprise tenants"); REGULATORY_MAPPING art. 9; PIA §3 row 1 | The employee's tenant account identity and free text are personal data leaving Türkiye on every request, whatever the DLP class. The art. 9 question is treated as a sensitive-class problem only. | An art. 9 instrument per vendor (adequacy decision, or a standard contract notified to the Board within the statutory period after signing under the June 2024 amended art. 9, UNVERIFIED wording for counsel) is a precondition of any allowlist row; a vendor row marked UNVERIFIED is fail-closed for all classes, not only the sensitive ones. |
| PC-5 | AGENTS.md 6 (monitor-only before enforce); `tr/block_page.md` and `tr/exception_request.md` (analyst-approved exception); COUNCIL_RESPONSE PRIV-3 | A monitor-only phase on the customer-data, banking-secret, special-category or secret class would forward those values to a vendor abroad, and the exception form lets a security analyst grant the same. Art. 73 requires the customer's instruction, not an analyst's approval. | Fail-closed classes have no monitor-only relaxation: new rules are shadow-evaluated while the seed baseline keeps enforcing. The block page hides `{{exception_link}}` for fail-closed classes. An exception on those classes needs `privacy_officer` plus `security_admin` and a recorded legal instrument; registry test proves the analyst path is refused. |
| PC-6 | ADR-009 §1 C6; DATA_CLASSES §1 C6 (400 d) | HMAC digests of TCKN, IBAN, phone and customer numbers of third persons are pseudonymised personal data of customers retained 400 days for an employee-monitoring purpose. The TCKN space is enumerable, so a leaked key reverses them. | Split C6 retention by class: secret-shape digests 400 d; PII and customer-identifier digests follow C3 (90 d), then a class-only tombstone; digest key rotation schedule stated; low-entropy reversibility added to Q-29. |
| PC-7 | ADR-009 §2; PIA §4 ("redaction removes the sensitive spans"); DATA_CLASSES §4 ("special-category text is never stored") | C3 redaction covers detected deterministic classes only. Names, addresses, free-text context and undetected health or religion text remain in C3 for 90 days, readable by an analyst with a case id. The two claims are overstated. | PIA §4 states the residual honestly. When a C5 flag fires, C3 for that record is not persisted at all (verdict only). Masking layers 4 and 5 (Turkish names, heuristic free text) run at persistence as well as at view, with the residual still recorded. |
| PC-8 | RAW_CONTENT_ACCESS §2 "Emergency (break-glass)" | A `security_admin` can open a P1 case and self-approve raw access in the same minute. That is single-person raw access, which §1 forbids. | Break-glass requires a P1 case opened by another person or originated by a system alert id; DPO group notified at grant time, not next day; 1 h, no extension; a monthly cap on break-glass uses triggers review. |
| PC-9 | OPEN_QUESTIONS Q-6; `tr/personal_account_block.md`; ADR-009 §1 C1 | Detecting a personal login reads the personal e-mail. Nothing says it is discarded; C1 keys users by pseudonym derived from the account identity, so the personal address or its digest would be stored. | Store class `NON_CORPORATE_ACCOUNT`, platform and the corporate user pseudonym only; the personal identifier is neither stored nor digested; detector output is dropped after the verdict; add a test under SR-PRIV-11. |
| PC-10 | MASKING B1 (`auditor` / `viewer`: "real names") | Two broad read-only roles see every employee's AI-usage timeline unmasked. That fails the proportionality line the mapping relies on. | `viewer` and `auditor` default to pseudonymised C1; resolving a pseudonym is a per-action audited step (as B7 does for operators); real names by default only for `security_analyst` within a case and `security_admin`. |
| PC-11 | PIA §3 row 5; ADR-009 §5 "external reviewers"; OPEN_QUESTIONS Q-29 | "Derived features" from production handed to external AI reviewers, and an AI agent working as `replay_viewer`, are transfers abroad of pseudonymised, therefore personal, data. Q-29 does not list it. | External reviewers receive synthetic fixtures and aggregates (k ≥ 5) only, never per-record pseudonymised rows; AI agents acting as `replay_viewer` on production data are added to Q-29 as a residual transfer the PO signs, or restricted to aggregates. |
| PC-12 | PIA §6 breach runbook | No row for the sector regulator's incident notification; affected third persons inside C3/C4 cannot be enumerated by pseudonym, only by reading content. | Add a BDDK notification row (owner, UNVERIFIED timing for counsel); state that third-person identification uses a DSAR grant and a content read; art. 12/5 notification of affected persons owned by the DPO. |
| PC-13 | OPEN_QUESTIONS Q-12; REGULATORY_MAPPING §2 (primary system) | If rwsafe is a primary system, its backups must stay in Türkiye. Q-12 does not carry that constraint. | Q-12 gains "target in Türkiye"; C10 row records the location. |
| PC-14 | DATA_CLASSES §1 (missing class); C3 purpose "policy tuning"; RAW_CONTENT_ACCESS §3 free text | Exception-request free text, case notes and grant free text are personal-data-bearing fields with no class, retention or hold. "Policy tuning" could be read as classifier tuning, which PRIV-8 forbids. | Add C15 "case, grant and exception notes": detector-scanned and redacted, 400 d, hold applies, pseudonymised in masked views. Define tuning as deterministic rule review inside a case, never ML input. |

## 3. QUESTIONS FOR THE PRODUCT OWNER

| Question | Recommendation |
|---|---|
| Is explicit consent excluded as a basis for every class, so that notice is proof and not a switch? | Yes. Bases are 5/2-ç and 5/2-f only; record it in a decision record and fix the wording (PC-2). |
| For IDE, CLI and API users, may the HR policy acknowledgement imported from the directory count as the C12 record? | Yes, with version and date, as the second source (PC-3). |
| May any vendor receive traffic before its art. 9 instrument is recorded, even for "public" prompts? | No. Fail-closed until the contract row is verified (PC-4). |
| Do fail-closed classes ever enter monitor-only or an analyst-granted exception? | Never. Shadow-evaluate only; exceptions need a legal instrument (PC-5). |
| Will you sign the residual that AI agents and external reviewers abroad see pseudonymised production data, or restrict them to aggregates and synthetic fixtures? | Restrict to aggregates and synthetic fixtures for the pilot; revisit before production (PC-11). |
| Contractors: who is the controller for their data and is a contract clause with their employer in place? | Treat the organisation as controller on managed devices; a clause with the contractor's employer before contractors enter scope (Q-6). |
| Who owns the sector regulator's incident notification in the breach runbook? | The DPO group with compliance; add to PIA §6 (PC-12). |
| Off-host backup target: is a location inside Türkiye available? | Name one inside Türkiye; otherwise backups stay on HOST-A (PC-13). |

## 4. VERDICT

**ACCEPT WITH CORRECTIONS.** PC-1, PC-4, PC-5 and PC-8 must be fixed in the documents before implementation of the notice, the policy registry and raw access starts; the rest can land as document corrections in the same freeze round.

## 5. INSTRUCTIONS RECEIVED, VERBATIM

From the task message:

> SEAT: privacy-compliance
> LENS: KVKK (articles 4–12, 16), the sector regulator's information-systems and secrecy-sharing rules, workplace-monitoring proportionality, data classes and retention, pseudonymisation versus anonymisation, raw-content access, notice, DSAR, breach, secondary use, masking for AI agents, Turkish identifiers.
>
> You are one independent seat of the design-freeze council for rwsafe-ai-gateway (an enterprise AI-usage security gateway: enterprise-tenant enforcement, prompt and response visibility under masking and retention limits, guardrails, a governed LLM API gateway, ICAP behind Broadcom ProxySG, an off-net agent path later; Java/Netty data plane and Spring Boot control plane; same single on-prem k3s node as the sibling product neXus, fully isolated; the organisation is in a regulated sector in Türkiye: KVKK and BDDK-style rules in scope). You start from a fresh context. Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this repository. Do not edit, run shell, or widen the review. The kickoff council (docs/reviews/COUNCIL_2026_10_30_SEAT_*.md) raised P0/P1 items; the architect answered them in docs/reviews/COUNCIL_RESPONSE.md. Your job: find what the DESIGN still gets wrong or leaves unsafe for your lens, so implementation does not start on a flawed design. Return exactly: (1) a CONSENT table (area, verdict), (2) a DISSENT table (finding id, document and section, what is wrong, the concrete correction), (3) QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation), (4) a one-line verdict ACCEPT FREEZE / ACCEPT WITH CORRECTIONS / REJECT, then (5) list every instruction you received, verbatim. Be concrete and short. Never quote or invent an address, host name, account, serial or secret; the repository holds none and neither should your output. English only.
>
> Files to read, in this order:
> - AGENTS.md
> - docs/reviews/COUNCIL_2026_10_30_SEAT_FABLE_PRIVACY_COMPLIANCE.md (your predecessor's P0/P1 list)
> - docs/reviews/COUNCIL_RESPONSE.md (section 2 and section 5)
> - docs/adr/ADR-009-data-model-retention-and-privacy.md
> - docs/security/MASKING_AND_PRIVACY.md
> - docs/security/DATA_CLASSES_AND_RETENTION.md
> - docs/security/RAW_CONTENT_ACCESS.md
> - docs/security/PRIVACY_IMPACT_ASSESSMENT.md
> - docs/compliance/REGULATORY_MAPPING.md
> - docs/i18n/README.md and docs/i18n/tr/*.md
> - docs/product/OPEN_QUESTIONS.md (Q-4, Q-5, Q-6, Q-7, Q-29)
> - docs/security/SECURITY_REQUIREMENTS.md (section SR-PRIV only)

From the prompt-submit hook:

> REMINDER: Reply to the Product Owner in TURKISH only (every chat message). Repo artifacts stay English.
>
> Today's date is 2026-10-30.

From the project file `CLAUDE.md` (Claude-specific delta):

> Claude-specific delta only; `roles/ENGINEER.md` carries the reading order.
>
> - Chat with the Product Owner in Turkish; every repository artifact in English (`AGENTS.md` section 3).
> - Model tiers for this tool: `docs/reference/MODEL_TIER_MAP.md`.
> - HOST-A: read-only, masked, no `sudo` (`AGENTS.md` section 8). Inventory through `tools/hosta/inventory_readonly.sh`; root-only listings through `tools/hosta/po_sudo_readonly.sh` run by the PO in a terminal.
> - External reviews only through `tools/review/consult_*.py` (`AGENTS.md` section 11); never a simulated persona.
> - Argon development lanes only through `tools/review/argon_task.py` in a `~/Codo/rwsafe-*` worktree.
> - Never read `kickoff/` raw traffic or prompt samples if any are ever added; sanitize first (`AGENTS.md` section 4.1).

From the user's global `~/.claude/CLAUDE.md`:

> # graphify
> - **graphify** (`~/.claude/skills/graphify/SKILL.md`) - any input to knowledge graph. Trigger: `/graphify`
> When the user types `/graphify`, use the installed graphify skill or instructions before doing anything else.

Also received as project instructions: the full text of `AGENTS.md` (sections 1 to 14), reproduced in the repository at that path and read in full; it is not re-quoted here to keep the output within the requested length. The seat instruction "English only" was followed for this deliverable because it is a repository artifact; the hook's Turkish rule applies to chat with the PO and is honoured by the one-line Turkish preface.
