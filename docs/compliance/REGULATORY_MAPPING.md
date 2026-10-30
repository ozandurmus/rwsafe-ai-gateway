# Regulatory mapping

**Status:** DRAFT for DPO and PO review. Answers brief 10.5 (this document), council PRIV-1, PRIV-3, privacy P1 (5651,
ISO 27001/42001, NIST AI RMF), OWASP LLM Top 10. The architect maps requirements to controls; legal readings marked
UNVERIFIED need counsel or the DPO. Turkish statute names are kept in Turkish where they are proper names.

## 1. KVKK (Law 6698) article by article

| Article | Requirement | rwsafe control | Evidence |
|---|---|---|---|
| 4 General principles (lawfulness, purpose limitation, minimisation, retention limits, accuracy) | process only what the purpose needs, for a bounded time | data classes with purposes and retention (DATA_CLASSES §1); minimisation rules §4; no secondary use | class matrix, tests SR-PRIV-8..11 |
| 5 Conditions for processing | a basis per class | 5/2-ç legal obligation (sector IS rules) for C1/C2/C6/C7; 5/2-f legitimate interest with balancing for C3. **Explicit consent (5/1) is deliberately not a basis for any class**: in an employment relationship it is neither freely given nor stable; the C12 acknowledgement exists only as proof of art. 10 and as a proportionality control, never as a lawful-basis switch (PC-2) | DPO balancing record (PIA §4) |
| 6 Special-category data | avoid or protect | special-category text is never stored; C5 flag only; blocked for every external model (Q-7) | SR-PRIV-11; policy seed |
| 7 Erasure, destruction, anonymisation | delete when the purpose ends | deletion path with receipts, crypto-shredding, backup replay; pseudonymisation is **not** treated as anonymisation (privacy seat) | SR-PRIV-8; restore drill |
| 8 Transfer within Türkiye | third parties (the SIEM, the DPO group) | SIEM receives no content; internal transfers listed in the PIA | SR-SIEM-2 |
| 9 Transfer abroad | adequacy, standard contract (notified to the Board within the statutory period under the 2024 amendment, wording UNVERIFIED for counsel) or the law's exceptions | **every request to a vendor is a transfer of personal data** (account identity, free text), whatever the DLP class (PC-4): a vendor row is fail-closed for all classes until its art. 9 instrument is recorded (ADR-007 §3a); then the model/region allowlist per data class applies; customer data, banking secret and special-category never leave until the contract and the regulator reading allow (Q-7); PLATFORM_MATRIX §5 records region, DPA, zero-retention and the instrument per vendor | policy registry, SR-GW-3 |
| 10 Notice (aydınlatma) | inform before processing | Turkish notice texts (docs/i18n) shown on the coaching/block page, first-use banner, first IDE use; acceptance recorded (C12); content capture off for a user without acceptance | SR-PRIV-10 |
| 11 Rights of the data subject | access, rectification, erasure, objection | DSAR search for `privacy_officer`, erasure path, objection handled as scope exclusion (user placed in a no-capture group; enforcement continues) | SR-PRIV-9 |
| 12 Security obligations and breach notification (72 h to the Board) | technical and organisational measures; notify | the whole security design; breach runbook (PIA §6) with employee identification via the DSAR path and third-person identification by a content read under a grant; the sector regulator's incident notification owned by the DPO group with compliance (PC-12) | THREAT_MODEL, runbook drill |
| 16 VERBIS | inventory | each class mapped to an inventory entry by the DPO (DATA_CLASSES §5) | DPO |

Workplace monitoring (Constitutional Court line of decisions on employer monitoring, UNVERIFIED citations): prior notice,
purpose limitation, proportionality, no lighter means. Controls: notice before capture, redacted-first capture, raw only
on a confirmed incident with a grant, retention limits, no productivity analytics.

## 2. Sector rules (BDDK) — UNVERIFIED readings, for counsel

| Rule | Requirement | rwsafe position |
|---|---|---|
| Bankaların Bilgi Sistemleri ve Elektronik Bankacılık Hizmetleri Hakkında Yönetmelik (OG 31069, 15 March 2020, in force 1 July 2020): primary and secondary systems and their backups are kept in Türkiye; outsourced information-system services that fall within primary/secondary systems are treated the same | is rwsafe a primary system? It processes prompts that may contain customer data and produces security records; **recommendation: treat rwsafe as a primary system** (on HOST-A, in Türkiye, backups on-site) and treat the AI vendors as external services whose data flows are governed by art. 9 and the allowlist | PIA §3; Q-7 |
| Same regulation: audit trails (iz kayıtları), access authorisation, segregation of duties | trigger-enforced audit, roles, four-eyes raw access, 10-year audit retention (UNVERIFIED figure) | SR-AUD-*, RAW_CONTENT_ACCESS |
| Same regulation: outsourcing (dış hizmet) notification and risk assessment | the gateway's upstream vendors are outsourced services for the data that reaches them; whether a notification is due is for compliance (UNVERIFIED) | OPEN (compliance team) |
| Sır Niteliğindeki Bilgilerin Paylaşılması Hakkında Yönetmelik (2021) and Bankacılık Kanunu art. 73: customer secrets may not be shared with third parties abroad without the customer's instruction/consent (exceptions aside) | the **customer-data / banking-secret DLP class is fail-closed** and blocked for every external AI platform (ADR-010, Q-7); detection is deterministic (customer-number formats, IBAN, card, account patterns) plus the estate dictionary | SR-DET-2, policy seed |

## 3. Law 5651 (collective use providers) — UNVERIFIED reading

The obligation to keep time-stamped access logs for the statutory period rests on the access/collective-use provider;
ProxySG's access logs are the natural record. rwsafe's C1 is not designed as the 5651 record (different purpose and
retention) and should not be presented as one; if compliance decides otherwise, C1 retention and integrity (hash chain)
would be extended. Privacy P1 item: decided by compliance.

## 4. ISO/IEC 27001:2022 and 27002 controls touched

A.5.10 acceptable use (the AI-use policy the product enforces), A.5.12/5.13 classification and labelling (data classes),
A.5.15–5.18 access control (roles, grants), A.5.23 cloud services (vendor matrix), A.5.28 evidence collection (capture
with chain of custody: hashes, audit), A.5.31/5.34 legal and privacy (this mapping), A.8.10 information deletion, A.8.11
data masking (masking funnel), A.8.12 DLP (the product itself), A.8.15/8.16 logging and monitoring, A.8.24 cryptography
(envelope encryption, key separation), A.8.25–8.29 secure development (SSDF mapping, tests), A.8.32 change management
(PR gates, policy approvals).

## 5. ISO/IEC 42001 (AI management system) and NIST AI RMF

rwsafe is a control over the organisation's AI use, not an AI system in the 42001 sense, except for its own ML classifier
tier (ADR-008). For that tier: GOVERN (owner, policy for models, supply chain), MAP (purpose: detection assist, never a
sole blocker), MEASURE (synthetic corpus, FN/FP targets, drift), MANAGE (circuit breaker, async, human review). The
organisation's broader 42001 inventory lists the sanctioned AI platforms; rwsafe's shadow-AI discovery feeds it.

## 6. OWASP Top 10 for LLM Applications (2025)

Mapping in THREAT_MODEL §9. Primary sources: the OWASP GenAI Security Project list (LLM01 prompt injection to LLM10
unbounded consumption).

## 7. What this mapping does not claim

No certification, no legal opinion. Every UNVERIFIED row is a question for the DPO or counsel, collected in the PIA §7.
