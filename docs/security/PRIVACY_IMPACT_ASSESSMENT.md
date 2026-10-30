# Privacy impact assessment

**Status:** FROZEN by `docs/design/PO_DECISION_RECORD_2026_10_30_DESIGN_FREEZE.md` (2026-10-30); amended only through a PO decision record or an ADR
that quotes one.

**History:** DRAFT for the DPO and the PO. Answers council privacy P1 "privacy impact assessment" and PRIV-1 to PRIV-10 as a
whole; brief 6 (Privacy). Structure: inventory, flows, basis per class, risks and residuals, breach runbook, open legal
questions. Companion documents: `DATA_CLASSES_AND_RETENTION.md`, `RAW_CONTENT_ACCESS.md`, `MASKING_AND_PRIVACY.md`,
`docs/compliance/REGULATORY_MAPPING.md`.

## 1. Processing description

rwsafe-ai-gateway inspects employees' use of AI assistants and coding agents on the corporate network to (1) ensure
enterprise tenants are used, (2) make prompts and responses visible to the security team under role, masking and
retention limits, (3) apply data-loss and prompt-attack guardrails, (4) govern API-key based access. Data subjects:
employees and contractors using AI tools on the corporate network; incidentally, third persons whose data appears inside
prompts (customers, colleagues). Controller: the organisation; processor relationships: AI vendors (for the content that
is allowed to reach them), the SIEM (metadata), HOST-A operations (the organisation itself).

## 2. Data inventory

The 14 classes of DATA_CLASSES §1 with purpose, basis, store, retention. Highest sensitivity: C4 raw content (may contain
anything an employee typed, including special-category data of third persons), C3 redacted content, C5 flags.

## 3. Data flows and transfers

| Flow | Personal data | Leaves the organisation? | Control |
|---|---|---|---|
| Employee → ProxySG → rwsafe ICAP → AI vendor | prompt content, identity (proxy claim) | **every request to a vendor is a transfer abroad of personal data** (the account identity and free text), whatever the DLP class (PC-4); a vendor receives traffic only after its KVKK art. 9 instrument is recorded (ADR-007 §3a); customer data, banking secret and special-category never (fail-closed) | ADR-007, ADR-010, Q-7, Q-33 |
| rwsafe → capture store (HOST-A) | C3, C4 | no (HOST-A in Türkiye, treated as a primary system) | ADR-009 |
| rwsafe → SIEM | C1, C2, C6, C7 (pseudonyms, classes, digests) | no (corporate SIEM) | SR-SIEM-2 |
| rwsafe → mail relay | notification digests (no content) | no | SR-NOT-1 |
| rwsafe → external reviewers (AI models used by the engineering team) | **synthetic fixtures and aggregates (k ≥ 5) only** (PC-11); never per-record pseudonymised rows, never bodies | yes, under the engineering team's own tooling rules | AGENTS.md 4.6, 4.7 |
| AI agent working as `replay_viewer` on production data | pseudonymised per-record data, which is still personal data | yes (the model is operated abroad) | residual the PO signs (Q-29) or the agent is restricted to aggregates (PC-11) |
| gateway → AI vendor | prompt content for API tools | yes, within the allowlist | SR-GW-3 |

## 4. Necessity and proportionality (per class, for the DPO's balancing)

| Class | Why necessary | Lighter alternative considered | Why rejected | Residual |
|---|---|---|---|---|
| C1/C2/C6 | enforcement and audit are impossible without who/what/when and the verdict | none that enforces | — | pseudonymised for most viewers |
| C3 redacted | incident investigation needs the text around a finding; deterministic rule review needs examples | verdicts only | analysts cannot judge a block without context; false positives cannot be corrected | 90-day limit, case-bound access; **redaction removes only what a detector matched: names, addresses and free-text context that no detector caught remain readable in C3 for 90 days** (PC-7). Mitigation: masking layers 4 and 5 run at persistence; a record with a C5 flag has no C3 at all |
| C4 raw | only for a confirmed incident where the redacted text is insufficient (e.g. to prove what exactly left) | C3 only | evidence quality in a serious incident | off by default (Q-4b), JIT grant, 30 days, crypto-shred |
| C5 flag | to block special-category exfiltration | none | — | flag only, no text |
| C12 | legal proof of notice | none | — | — |

## 5. Risks and mitigations

| Risk | Likelihood | Impact | Mitigation | Residual |
|---|---|---|---|---|
| Honeypot: the capture store becomes the richest secret archive | medium | high | redaction before persistence; no matched values; raw off by default; encryption; JIT access | low |
| Insider reads prompts out of curiosity | medium | high | four eyes, reason codes, DPO notice, SIEM copy, watermark, audit per view | low |
| Re-identification through pseudonyms | medium | medium | masked search over pseudonyms only, no raw filters, k ≥ 5, own HMAC key | medium (pseudonymised data remains personal data) |
| Special-category data of third persons inside prompts | high (it will happen) | high | C5 flag, no text stored, blocked for external models | low |
| Cross-border transfer without basis | medium | high | allowlist per class, fail-closed classes, vendor DPA records | medium until contracts are read (PLATFORM_MATRIX §5) |
| Monitoring without notice | low | high | notice gate (C12), Turkish texts | low |
| Over-retention | medium | medium | per-class retention, deletion receipts, backup replay | low |
| Secondary use (analytics, training) | low | high | design rule and test | low |
| Host root reads the store | low | high | encryption at rest, envelope keys; **residual: no HSM** | medium, PO signature (Q-29) |
| Breach of the capture store | low | high | §6 runbook | — |

## 6. Breach runbook (72 hours to the Board, art. 12)

T+0: detection (SIEM alert, audit anomaly, scanner); the `security_admin` opens a P1 case; raw-access break-glass rules apply.
T+2 h: scope: which classes, which record ids, which time window; the DSAR search enumerates affected **employees** by
pseudonym; **third persons inside C3/C4 can only be identified by reading content under a DSAR grant** (PC-12);
`privacy_officer` and the DPO group are notified automatically by the case type.
T+24 h: containment (revoke grants, rotate keys: capture KEK rotation re-wraps data keys; pseudonym key rotation is
avoided unless the key itself leaked), evidence preserved under legal hold.
T+48 h: the DPO drafts the Board notification from the case record (counts, classes, persons, measures); affected
persons' notification prepared where required.
T+72 h: submission; the root-cause log entry; retrospective within two weeks.
Sector regulator: the DPO group with compliance owns the BDDK incident notification (timing UNVERIFIED for counsel;
PC-12); the notification of affected persons under art. 12/5 is owned by the DPO.
The runbook is drilled annually with synthetic data.

## 7. Open legal questions for the DPO and counsel

Legitimate-interest balancing for C3; C5 flags as special-category processing; the sector audit-trail figure; primary-
system classification of rwsafe; outsourcing notification for the AI vendors; 5651 applicability; VERBIS entries;
the objection path (no-capture group) versus the enforcement obligation; contractor and BYOD scope (Q-6).

## 8. Conclusion for the design freeze

With capture in redacted mode by default, raw behind a grant, fail-closed sensitive classes, notice before capture,
bounded retention with provable deletion and no secondary use, the residual risks are the no-HSM host root risk and the
re-identification risk inherent to pseudonymisation; both are presented to the PO for signature (Q-29) rather than
hidden.
