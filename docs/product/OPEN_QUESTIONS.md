# Open questions for the Product Owner

**Status:** LIVE. Each question: what is undecided, the options, the architect's recommendation, what blocks on it. The
first eight are the brief's own (10.6). A decision becomes a `docs/design/PO_DECISION_RECORD_*.md` and the question moves
to the "Decided" table. Chat answers in Turkish are quoted in the record; the question text here stays English.

## A. The brief's known questions (10.6)

| Id | Question | Options | Recommendation | Blocks |
|---|---|---|---|---|

## B. Questions raised by the design

| Id | Question | Options | Recommendation | Blocks |
|---|---|---|---|---|
| Q-17 | ARK naming and branching conventions: please supply the document so repository, branch and namespace names can follow it | — | adopt what is compatible with GitHub and k3s now; record deviations; working assumption ratified 2026-10-30, information pending (`PO_DECISION_RECORD_2026_10_30_REMAINING_OPEN_QUESTIONS.md`) | stack matrix |
| Q-23 | Customer-number formats and the Turkish name dictionary source | formats: the PO supplies regex-shaped rules (no samples); names: a public list | as stated; working assumption ratified 2026-10-30, information pending (`PO_DECISION_RECORD_2026_10_30_REMAINING_OPEN_QUESTIONS.md`) | detector library, masking layer 4 |
| Q-25 | Which XDR product runs on the endpoints (for agent coexistence) | — | name it when the agent phase starts; working assumption ratified 2026-10-30, information pending (`PO_DECISION_RECORD_2026_10_30_REMAINING_OPEN_QUESTIONS.md`) | ADR-006 |

## C. Decided

| Id | Decision record | Date |
|---|---|---|
| Q-7 | `PO_DECISION_RECORD_2026_10_30_REMAINING_OPEN_QUESTIONS.md`: class-based allowlist; customer data, banking secret, special-category to no external model | 2026-10-30 |
| Q-8 | `PO_DECISION_RECORD_2026_10_30_REMAINING_OPEN_QUESTIONS.md`: (a) out of scope, tenant settings and compensating controls | 2026-10-30 |
| Q-11 | `PO_DECISION_RECORD_2026_10_30_REMAINING_OPEN_QUESTIONS.md`: (a) report only | 2026-10-30 |
| Q-12 | `PO_DECISION_RECORD_2026_10_30_REMAINING_OPEN_QUESTIONS.md`: backups stay on HOST-A for now; residual risk in Q-29 | 2026-10-30 |
| Q-18 | `PO_DECISION_RECORD_2026_10_30_REMAINING_OPEN_QUESTIONS.md`: (a) only if demand is shown, own ADR | 2026-10-30 |
| Q-19 | `PO_DECISION_RECORD_2026_10_30_REMAINING_OPEN_QUESTIONS.md`: (a) after the MVP, browser first | 2026-10-30 |
| Q-20 | `PO_DECISION_RECORD_2026_10_30_REMAINING_OPEN_QUESTIONS.md`: PO opens the Broadcom case in phase 0 with the session's guidance | 2026-10-30 |
| Q-21 | `PO_DECISION_RECORD_2026_10_30_REMAINING_OPEN_QUESTIONS.md`: PO deploys the three headers in phase 1; checks Entra v2 in phase 0 | 2026-10-30 |
| Q-22 | `PO_DECISION_RECORD_2026_10_30_REMAINING_OPEN_QUESTIONS.md`: (a) asynchronous only in the MVP | 2026-10-30 |
| Q-24 | `PO_DECISION_RECORD_2026_10_30_REMAINING_OPEN_QUESTIONS.md`: decide at the first frontend commit; Axios acceptable | 2026-10-30 |
| Q-26 | `PO_DECISION_RECORD_2026_10_30_REMAINING_OPEN_QUESTIONS.md`: cosign, key in a Secret | 2026-10-30 |
| Q-27 | `PO_DECISION_RECORD_2026_10_30_REMAINING_OPEN_QUESTIONS.md`: (b) redirect 161→1161, H-3 approved | 2026-10-30 |
| Q-28 | `PO_DECISION_RECORD_2026_10_30_REMAINING_OPEN_QUESTIONS.md`: plain ICAP max 30 days with REQMOD fail-closed; fail-open only after Secure ICAP | 2026-10-30 |
| Q-29 | `PO_DECISION_RECORD_2026_10_30_REMAINING_OPEN_QUESTIONS.md`: signed for the pilot, incl. HOST-A backups and the plain-ICAP window | 2026-10-30 |
| Q-37 | `PO_DECISION_RECORD_2026_10_30_REMAINING_OPEN_QUESTIONS.md`: (a) at the move to the corporate GitHub instance | 2026-10-30 |
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
