# Raw content access: just-in-time, four eyes, reason codes, notice

**Status:** DRAFT for PO decision (approver roles and DPO identity: OPEN_QUESTIONS Q-5). Answers council PRIV-9, brief 4A
product rule 6, AC-6 ("a raw read without a reason returns 403 and is audited").

## 1. Principle

No single person can open a raw prompt or response (class C4) or a redacted body (C3) outside a case. Access is a
**grant**, not a role: time-boxed, reason-coded, approved by a second person of a different role, notified to the DPO
group at grant time, copied to the SIEM immediately, and audited per page view.

## 2. Who

| Step | Role |
|---|---|
| Request | `security_admin` or `security_analyst` (C3 with a case id needs no grant beyond the case; C4 always needs a grant) or `privacy_officer` (DSAR) |
| Approve | a different person holding `privacy_officer` (for security requests) or `security_admin` (for DSAR requests); never the requester; never the same person twice in a row for the same case (rotation) |
| Notified | the DPO directory group (mail route `raw_access`), the SIEM (immediate CEF event), the requester's manager group if configured |
| Emergency (break-glass) | never single-person (PC-8): requires an `INCIDENT_P1` case **opened by another person** or originated by a **system alert id**; the `security_admin` then grants to themself for **1 hour, no extension**, with a mandatory reason; the DPO group is notified **at grant time**, the SIEM copy is immediate, the `privacy_officer` reviews next business day and can mark it abusive (locks the requester's grant ability); a monthly cap on break-glass uses (3) triggers a review |

## 3. Grant object

`raw_access_grant`: id, requester, approver, case id, reason code (`INCIDENT_INVESTIGATION`, `DSAR`, `LEGAL_HOLD_REVIEW`,
`FALSE_POSITIVE_REVIEW`, `REGULATOR_REQUEST`, `BREAK_GLASS`), free text (no personal data by instruction, scanned by the
detectors anyway), scope (record ids or a query of pseudonymised fields, never a raw-value filter), classes (C3, C4),
start, end (≤ 4 h, extensions re-approved), state, revoked by/at. All columns trigger-audited.

## 4. The view

- Server-side decryption per record under the grant; the UI shows text in an inert, sandboxed panel with a visible
  watermark (requester fingerprint, grant id, time); copy and download are disabled in the UI (a determined user can
  still screenshot: the watermark and the audit are the deterrent, stated as residual).
- Every record opened writes a `raw_access_view` audit row (grant id, record id, time) through the trigger.
- Content is framed as untrusted (SEC-5): no rendering of HTML, Markdown links are inert, control characters shown as
  symbols.
- No export of C4; C3 export only within a case, masked for masked roles, watermarked.

## 5. Refusals (tests)

| Attempt | Result |
|---|---|
| Raw read without a grant | 403 `RAW_ACCESS_GRANT_REQUIRED`, audit row, SIEM event (AC-6) |
| Grant requested and approved by the same person | 409 `FOUR_EYES_REQUIRED` |
| Grant beyond 4 h | 400 `GRANT_TOO_LONG` |
| Read after expiry or revocation | 403 `GRANT_EXPIRED` |
| Masked role (`replay_viewer`) requests a grant | 403 `ROLE_NOT_PERMITTED` (the masked role never reaches raw) |
| Break-glass without an active P1 case | 403 |

## 6. Reporting

Monthly report to the DPO group: grants by reason code, duration, records viewed (counts), break-glass uses, revocations,
abusive marks. Quarterly access review of who holds the requesting and approving roles (privacy P1).
