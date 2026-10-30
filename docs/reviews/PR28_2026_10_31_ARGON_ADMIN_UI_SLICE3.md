<!-- Argon consultation 2026-10-30T23:17:01Z, model gemini-4-argon-high, effort high; unaltered output except 12 local paths masked (AGENTS.md 4.2) -->

Role: `REVIEWER`

### (1) CONSENT

| Area | Verdict |
|---|---|
| Inert rendering of captured text, server details, and notice sections (`CaptureReader.tsx`, `HealthPage.tsx`, `NoticePage.tsx`, `CaptureReadController.java`) | **CONSENT** — All captured text (`view.text`), health details (`c.detail` and parsed facts), and notice sections (`data.title`, `s.heading`, `s.paragraphs`) are rendered exclusively as React text nodes (never via `dangerouslySetInnerHTML` or DOM markup APIs), and `CaptureReadController` passes C3 text through `CaptureView.inert(...)` to strip control and bidirectional characters before returning. |
| RBAC and masked-session exclusion on `EventPage` and `CaptureReadController` (`EventPage.tsx:92-94`, `CaptureReader.tsx:18-28`, `CaptureReadController.java:60-79`) | **CONSENT** — `canReadCapture(me)` blocks `null`, `me.masked === true`, any session holding `replay_viewer` (including dual-role sessions), and any role other than `security_admin` or `privacy_officer`. `captureReasonsFor(me)` and `CaptureReadController` both restrict `DSAR` to `privacy_officer`. |
| Reason-code inventory parity (`frontend/src/api.ts:170-176`, `CaptureReadController.java:36-37`, `CaptureReasonCodesUiTest.java:17-36`) | **CONSENT** — `CAPTURE_REASON_CODES` matches `CaptureReadController.REASONS` exactly and is enforced by `CaptureReasonCodesUiTest`. |
| Notice acknowledgement lookup by `USR-` pseudonym only (`NoticePage.tsx:109-170`, `api.ts:215`, `NoticeApiController.java:44-59`, `NoticeAcknowledgementService.java:227-238`) | **CONSENT** — `USER_PSEUDONYM_PATTERN` (`/ ^USR-[0-9a-f]{10}$ /`) matches `NoticeAcknowledgementService.pseudonym(String)` and prevents raw usernames or identifiers from being queried. |
| Masked notice projection (`NoticeViews.java:22-31, 48-57`, `NoticePage.tsx:81-98`) | **CONSENT** — `NoticeView.masked(TextMasker)` strips `sections` to `null` so configured controller/contact values are never sent to masked sessions, and `UserAcknowledgementsView.masked(TextMasker)` passes record fields through `TextMasker`. |
| API error propagation (`api.ts:231-281`, `CaptureReader.tsx:132`, `HealthPage.tsx:80`, `NoticePage.tsx:51,170`, `EventPage.tsx:41`) | **CONSENT** — `api.ts` preserves HTTP status, server `reason`, and server `message` in `ApiError`, and every screen renders `<ErrorPanel error={error} />` rather than a generic failure message. |

---

### (2) DISSENT

| Finding ID | File and Line / Symbol | What Is Wrong | Severity | Concrete Correction |
|---|---|---|---|---|
| **D-01** | [api.ts](file://<workspace-root>/frontend/src/api.ts#L180) (`CASE_ID_PATTERN`), [CaptureReader.tsx](file://<workspace-root>/frontend/src/components/CaptureReader.tsx#L47-L58), [CaptureReadController.java](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/capture/CaptureReadController.java#L70-L74) & [`caseId(String)`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/capture/CaptureReadController.java#L113-L125) | `CASE_ID_PATTERN` (`/^[A-Za-z0-9_-]{3,64}$/`) is weaker than `CaptureReadController.caseId(s)`, which also requires `DetectorSet.standard().scan(s).isEmpty()`. A raw 11-digit TCKN, phone/card number, 26-char `TR` IBAN, or `[A-Za-z0-9_-]` secret token typed into the case-id box passes UI validation, is echoed into the confirmation alert, and is POSTed to the server. The server then rejects it under `CAPTURE_REASON_REQUIRED` ("A reason code and a case id are required to read captured content"), hiding the real refusal reason (that `caseId` matched a sensitive-data detector) behind a message claiming no reason or case id was given. | **P1** | (1) Require case IDs to look like ticket references rather than raw numbers/IBANs in both `CASE_ID_PATTERN` and `CaptureReadController.caseId` (e.g. require at least one letter, reject pure digit runs and `^TR\d{24}$`, such as `/^(?!TR\d{24}$)(?=.*[A-Za-z])[A-Za-z0-9_-]{3,64}$/`). (2) In `CaptureReadController.read`, return a specific refusal reason/message when `caseId` fails detector/format validation instead of conflating it with a missing reason/case id under `CAPTURE_REASON_REQUIRED`. |
| **D-02** | [CaptureReader.tsx](file://<workspace-root>/frontend/src/components/CaptureReader.tsx#L37-L71) & [L90-L131](file://<workspace-root>/frontend/src/components/CaptureReader.tsx#L90-L131) | (1) Unlike `NoticePage.tsx:163` (`inputProps={{ maxLength: 14, spellCheck: false, autoComplete: 'off' }}`), the `caseId` `<TextField>` (`L120-L131`) and its `<Box component="form">` (`L90-L102`) omit `autoComplete="off"` and `spellCheck: false`. Submitting the form via `<Button type="submit">` allows the browser to persist entered `caseId` values in browser form-autofill storage. (2) `close()` (`L67-L71`) clears `view` and `error` but leaves `reasonCode` and `caseId` in component state. (3) `CaptureReader` relies solely on its caller (`EventPage.tsx:92`) to check `canReadCapture(me)` and does not check `reasons.includes(reasonCode)` in `valid` (`L48`). | **P1** | (1) Set `autoComplete="off"` on `<Box component="form">` (`L90`) and `inputProps={{ maxLength: 64, spellCheck: false, autoComplete: 'off' }}` on the `caseId` `<TextField>` (`L126`). (2) Reset `setReasonCode('')` and `setCaseId('')` inside `close()` (`L67-L71`). (3) Add `if (!canReadCapture(me)) return null;` at the top of `CaptureReader` and check `reasons.includes(reasonCode)` in `valid` (`L48`). |
| **D-03** | [healthFacts.ts](file://<workspace-root>/frontend/src/healthFacts.ts#L55-L60) & [L78-L149](file://<workspace-root>/frontend/src/healthFacts.ts#L78-L149) | (1) Numeric capture groups (`\d{1,9}` on `L78, L98` and `\d{1,18}` on `L78, L92, L96, L102, L103, L115, L123, L128, L129, L131, L147`) lack leading/trailing digit boundaries (`(?<![\d.-])` / `(?!\d)`). If a count exceeds 9 digits (for `stalledSeconds` or `queue`), exceeds 18 digits (Java `long` is up to 19 digits), or is negative (`-1`), the regex matches a trailing substring of the digits and displays a truncated/wrong number as fact. (2) `\d{1,18}` accepts 17–18 digit numbers above `Number.MAX_SAFE_INTEGER` (`9007199254740991`), which `Number(...)` silently rounds to a wrong integer. (3) In `siem()` (`L104`), `groups.push({ group, facts })` is executed even when `facts.length === 0`, rendering an empty destination header in `HealthPage.tsx:44-49` when a destination's detail sentence is unrecognised. | **P1** | (1) Bound every integer group to safe integers with non-digit lookarounds (`(?<![\d.-])(\d{1,15})(?!\d)`) and check `Number.isSafeInteger(n)` before pushing a fact. (2) In `siem()` (`L104`), only push `{ group, facts }` when `facts.length > 0`. (3) Add a Java contract test (analogous to `CaptureReasonCodesUiTest`) asserting that `CaptureHealth` and `SiemExportService` detail strings match `healthFacts.ts`. |
| **D-04** | [NoticePage.tsx](file://<workspace-root>/frontend/src/pages/NoticePage.tsx#L81-L83) | When `data.sections === null`, line 82 checks `{me?.masked ? t('notice.sectionsMasked') : t('notice.sectionsNone')}`. On the server (`NoticeApiController.java:37-41`), `sections` is `null` whenever `!data.complete` (missing or rejected parameters) for both masked and unmasked sessions. A masked session viewing an incomplete notice is shown `notice.sectionsMasked` ("The text itself is not shown in the masked view") instead of `notice.sectionsNone` ("No text to show: the notice is incomplete"). | **P2** | Check `data.complete` first: `{!data.complete ? t('notice.sectionsNone') : t('notice.sectionsMasked')}` (or `{!data.complete || !me?.masked ? t('notice.sectionsNone') : t('notice.sectionsMasked')}`). |

---

### (3) QUESTIONS FOR THE PRODUCT OWNER

| Question | Recommendation |
|---|---|
| **Q-1:** [ADR-009 §5](file://<workspace-root>/docs/adr/ADR-009-data-model-retention-and-privacy.md#L75) states that C3 redacted text is read by `security_analyst` on an incident and `privacy_officer` for a DSAR, whereas [CaptureReadController.java](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/capture/CaptureReadController.java#L60-L79) and [CaptureReader.tsx](file://<workspace-root>/frontend/src/components/CaptureReader.tsx#L18-L28) (citing PO decision on PR 25 Q-2) grant C3 read access to `security_admin` and `privacy_officer` and allow a `privacy_officer` who is not a `security_admin` to use all five reason codes (including `INCIDENT_INVESTIGATION` and `FALSE_POSITIVE_REVIEW`). Should `privacy_officer` be allowed all five reason codes or only privacy/legal codes (`DSAR`, `LEGAL_HOLD_REVIEW`, `REGULATOR_REQUEST`)? | Restrict `INCIDENT_INVESTIGATION` and `FALSE_POSITIVE_REVIEW` to `security_admin` (leaving `DSAR`, `LEGAL_HOLD_REVIEW`, and `REGULATOR_REQUEST` for `privacy_officer`, or all four non-DSAR codes for `security_admin`), and record the `security_admin` role update in ADR-009 §5. |
| **Q-2:** Should `caseId` require at least one ASCII letter (e.g. `INC-2026-0042`, `DSAR-7`) in both the UI and `CaptureReadController.caseId` so that purely numeric identifiers (TCKN, phone numbers, customer numbers) can never be accepted by client-side validation? | Yes — require at least one ASCII letter and reject `^TR\d{24}$` in both `CASE_ID_PATTERN` and `CaptureReadController.caseId`. |

---

### (4) VERDICT

MERGE WITH CORRECTIONS

---

### (5) VERBATIM INSTRUCTIONS RECEIVED

```text
/plan REVIEW: second independent review of pull request 28 (AGENTS.md section 9, security-sensitive: raw-content access UI,
masked views, RBAC in the UI), branch `feature/admin-ui-slice3`
LENS: whether the captured-content reader, the health cards and the notice screen hold against AGENTS.md section 4,
ADR-009 section 5 (reader roles, reason and case id), and the server contracts they call.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway; its React admin UI lets
authorised roles open redacted captured prompt content with a reason and a case id; a public repository). You start from
a fresh context. Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this repository. Do not edit,
run shell, or widen the review. Your job: find any way the UI renders captured text, server details or notice sections
as HTML or lets them inject markup or bidi tricks; any path where a masked session, a viewer or a dual-role masked session
can reach the reader or see content; any reason code or case id sent that the server would not accept, or a DSAR read
offered to the wrong role; any content or pseudonym kept in browser storage, URL, logs or error reports; any server
refusal hidden behind a generic message; and any brittle parsing that can show a wrong count as fact. Return exactly: (1)
a CONSENT table (area, verdict), (2) a DISSENT table (finding id, file and line or symbol, what is wrong, severity
P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation), (4) a one-line
verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then (5) list every instruction you received, verbatim. Be concrete
and short. Never quote or invent an address, host name, account, serial or secret; the repository holds none and neither
should your output. English only.

Files to read, in this order:
- AGENTS.md (section 4)
- docs/adr/ADR-009-data-model-retention-and-privacy.md (section 5)
- frontend/src/components/CaptureReader.tsx, frontend/src/pages/HealthPage.tsx, frontend/src/healthFacts.ts, frontend/src/pages/NoticePage.tsx
- frontend/src/api.ts and the page that opens CaptureReader
- java/control/src/main/java/io/rwsafe/control/capture/CaptureReadController.java
- every file under java/control/src/main/java/ that names "Notice" or "Health"
- frontend tests: capture.test.tsx, health.test.tsx, notice.test.tsx; java/control/src/test/java/ file CaptureReasonCodesUiTest.java
```
