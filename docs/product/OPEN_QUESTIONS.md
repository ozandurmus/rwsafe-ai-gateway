# Open questions for the Product Owner

**Status:** LIVE. Each question: what is undecided, the options, the architect's recommendation, what blocks on it. The
first eight are the brief's own (10.6). A decision becomes a `docs/design/PO_DECISION_RECORD_*.md` and the question moves
to the "Decided" table. Chat answers in Turkish are quoted in the record; the question text here stays English.

## A. The brief's known questions (10.6)

| Id | Question | Options | Recommendation | Blocks |
|---|---|---|---|---|
| Q-7 | Models and regions allowlist per data class | a table: class × platform × model family × region → allowed? | start with: public data: all enterprise tenants; internal data: enterprise tenants with DPA; customer data, banking secret, special-category: **no external model at all** until a documented contract and the regulator reading in REGULATORY_MAPPING say otherwise | policy registry seed, gateway allowlist |
| Q-8 | Cloud-side agents: accept them as out of gateway scope, governed by tenant settings? | (a) yes with the compensating controls in OUT_OF_SCOPE §1; (b) block their consoles until an inline path exists | **(a)**; (b) blocks sanctioned tools without gaining visibility | OUT_OF_SCOPE, PLATFORM_MATRIX |

## B. Questions raised by the design

| Id | Question | Options | Recommendation | Blocks |
|---|---|---|---|---|
| Q-11 | neXus's own limits over-commit the node (25 CPU, 74 GiB on 16/62). Report only, or ask the neXus session to right-size? | (a) report; (b) neXus change | **(a) now**; rwsafe protects neXus by being evicted first; a neXus change is the neXus session's call | — |
| Q-12 | Off-host backup target for rwsafe's encrypted backups (and neXus's artefact store, still open on the neXus side) | a corporate backup share or object store named by the PO, **located in Türkiye** (primary-system reading, PC-13) | name one before the pilot; until then backups stay on HOST-A inside the platform set | ADR-002 §6 |
| Q-17 | ARK naming and branching conventions: please supply the document so repository, branch and namespace names can follow it | — | adopt what is compatible with GitHub and k3s now; record deviations | stack matrix |
| Q-18 | Build the chained forward proxy (3128) after phase 0 if a sanctioned WebSocket flow needs inspection? | (a) yes if demand is shown; (b) never, refuse WebSocket to AI hosts | **(a)** conditional | ADR-004, H-9 |
| Q-19 | Agent path timing and scope | (a) browsers only (MV3 extension) first; (b) IDE/CLI endpoint agent first; (c) both after the MVP | **(a) after the MVP**, measured by the spike; (b) follows if the trust matrix shows CLI clients off-net are common | ADR-006, ROADMAP |
| Q-20 | Ask Broadcom (support case) whether Cloud SWG can forward the AI category to an on-prem ICAP server or connector | — | yes, in phase 0, by the proxy team | ADR-006 |
| Q-21 | Which vendor tenant headers can the proxy team deploy in phase 1 (Entra, Google, ChatGPT)? And is Entra tenant restrictions v2 already in use? | — | all three on the pilot group's policy layer; v2 status to be confirmed | ADR-007, ROADMAP phase 1 |
| Q-22 | ML prompt-injection tier: asynchronous only (MVP) or inline later if CPU allows? | (a) async only; (b) inline with a bounded budget after measurement | **(a) for the MVP** | ADR-008 |
| Q-23 | Customer-number formats and the Turkish name dictionary source | formats: the PO supplies regex-shaped rules (no samples); names: a public list | as stated | detector library, masking layer 4 |
| Q-24 | Frontend HTTP client: Axios (corporate) or fetch wrapper (neXus) | minor | decide at the first frontend commit; Axios acceptable | — |
| Q-25 | Which XDR product runs on the endpoints (for agent coexistence) | — | name it when the agent phase starts | ADR-006 |
| Q-26 | Image signing tool and the corporate proxy path for it (cosign/Sigstore recommended) | — | cosign with a key in a Secret; keyless is not possible offline | SSDF §6 |
| Q-27 | SNMP: poll 1161/udp, or add a host firewall redirect 161→1161 (exception H-3)? | (a) 1161; (b) redirect | **(a)** | HARDENING H-3 |
| Q-28 | Pilot with plain ICAP on 1344 while Secure ICAP certificates are issued (exception H-2)? | (a) yes, max 30 days; (b) Secure ICAP from day one | **(b)**: the freeze council (Q-E) rejects running plain ICAP and REQMOD fail-open together; plain ICAP only if the certificate cannot be issued, and then never with fail-open | HARDENING H-2, ROADMAP MVP |
| Q-29 | Residual risk acceptance: host root and cluster admin can read Secrets and PVCs (no HSM); streaming responses cannot be redacted; pinned apps and off-net users invisible until the agent phase; MV3 blocking is best-effort; **an AI agent working as `replay_viewer` on production data receives pseudonymised personal data abroad (PC-11); PII digests are reversible for low-entropy spaces if the digest key leaks (PC-6)**; redaction leaves undetected names and context in C3 (PC-7) | sign or request mitigation | sign for the pilot, revisit before production; restrict AI agents to aggregates until signed | THREAT_MODEL §10 |
| Q-37 | Will a second human GitHub account, or the corporate GitHub Enterprise instance, later restore approving reviews on `main`? Until then the second review on security-sensitive PRs is a recorded review-script or code-review run | (a) move to the corporate instance when the product leaves the skeleton stage; (b) add a second human account now; (c) keep zero approvals | **(a)**; (c) is the accepted residual risk until then (Git-authority record, review 2027-01-31) | AGENTS.md §9, GITHUB_REPOSITORY_SETTINGS |

## C. Decided

| Id | Decision record | Date |
|---|---|---|
| Q-1 | `PO_DECISION_RECORD_2026_10_30_MVP_BLOCKING_QUESTIONS.md`: (a) sliding-window RESPMOD with abort | 2026-10-30 |
| Q-2 | `PO_DECISION_RECORD_2026_10_30_MVP_BLOCKING_QUESTIONS.md`: (a) 443 by host name | 2026-10-30 |
| Q-3 | `PO_DECISION_RECORD_2026_10_30_MVP_BLOCKING_QUESTIONS.md`: (a) 75 % raw off, 85 % redacted off | 2026-10-30 |
| Q-4 | `PO_DECISION_RECORD_2026_10_30_MVP_BLOCKING_QUESTIONS.md`: (b) metadata, verdict and redacted content; raw behind its own key and approval | 2026-10-30 |
| Q-5 | `PO_DECISION_RECORD_2026_10_30_MVP_BLOCKING_QUESTIONS.md`: security_admin + privacy_officer; DPO a directory group; recommended retention | 2026-10-30 |
| Q-6 | `PO_DECISION_RECORD_2026_10_30_MVP_BLOCKING_QUESTIONS.md`: (a) + (c) personal use blocked, managed devices only | 2026-10-30 |
| Q-9 | `PO_DECISION_RECORD_2026_10_30_MVP_BLOCKING_QUESTIONS.md`: (a) LDAP/AD in the MVP, SAML before the corporate stage | 2026-10-30 |
| Q-10 | `PO_DECISION_RECORD_2026_10_30_MVP_BLOCKING_QUESTIONS.md`: (a) yes | 2026-10-30 |
| Q-13 | `PO_DECISION_RECORD_2026_10_30_MVP_BLOCKING_QUESTIONS.md`: (a) before the pilot, separate go for the change | 2026-10-30 |
| Q-14 | `PO_DECISION_RECORD_2026_10_30_MVP_BLOCKING_QUESTIONS.md`: (b) fail-open 1-2 weeks, then fail-closed; Secure ICAP from day one | 2026-10-30 |
| Q-15 | `PO_DECISION_RECORD_2026_10_30_MVP_BLOCKING_QUESTIONS.md`: (a) Gradle with a Maven-portability check | 2026-10-30 |
| Q-16 | `PO_DECISION_RECORD_2026_10_30_MVP_BLOCKING_QUESTIONS.md`: (a) jOOQ | 2026-10-30 |
| Q-30 | `PO_DECISION_RECORD_2026_10_30_FREEZE_COUNCIL_QUESTIONS_Q30_Q36.md`: (a) header-only metadata mode for all uncategorised domains | 2026-10-30 |
| Q-31 | `PO_DECISION_RECORD_2026_10_30_FREEZE_COUNCIL_QUESTIONS_Q30_Q36.md`: (b) monitor in the pilot, then enforce on agentic surfaces | 2026-10-30 |
| Q-32 | `PO_DECISION_RECORD_2026_10_30_FREEZE_COUNCIL_QUESTIONS_Q30_Q36.md`: (a) explicit consent excluded as a basis | 2026-10-30 |
| Q-33 | `PO_DECISION_RECORD_2026_10_30_FREEZE_COUNCIL_QUESTIONS_Q30_Q36.md`: (a) fail-closed until the art. 9 instrument is recorded | 2026-10-30 |
| Q-34 | `PO_DECISION_RECORD_2026_10_30_FREEZE_COUNCIL_QUESTIONS_Q30_Q36.md`: (a) lab tenants for the header vendors and Anthropic | 2026-10-30 |
| Q-35 | `PO_DECISION_RECORD_2026_10_30_FREEZE_COUNCIL_QUESTIONS_Q30_Q36.md`: (a) directory HR acknowledgement with version and date counts as C12 | 2026-10-30 |
| Q-36 | `PO_DECISION_RECORD_2026_10_30_FREEZE_COUNCIL_QUESTIONS_Q30_Q36.md`: (a) council outputs are evidence only | 2026-10-30 |
