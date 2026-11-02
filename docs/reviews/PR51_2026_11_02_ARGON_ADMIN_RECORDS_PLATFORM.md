<!-- Argon consultation 2026-11-02T09:42:49Z, model gemini-4-argon-high, effort high; unaltered output except 29 local paths masked (AGENTS.md 4.2) -->

Role: `REVIEWER`

### (1) CONSENT

| Area | Verdict |
| :--- | :--- |
| RBAC rule order and role scope ([`AccessRules.java`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/AccessRules.java), [`SecurityConfig.java`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/SecurityConfig.java), [`AccessRulesTest.java`](file://<workspace-root>/java/control/src/test/java/io/rwsafe/control/identity/AccessRulesTest.java)) | **CONSENT** — `admin.audit.read` (`GET /api/v1/admin/audit`) precedes `admin.access` (`/api/v1/admin/**`) and `screens.read` (`/api/v1/**`), granting read-only ledger access only to `security_admin` and `privacy_officer`, while refusing `viewer`, `replay_viewer` (including dual-role masked sessions) and `PASSWORD_CHANGE_PENDING` sessions with 403 `FORBIDDEN`. All other `/api/v1/admin/**` routes remain `security_admin`-only and refuse masked sessions. |
| Identifier and body non-leakage on Audit, Jobs, System, Logs and Notifications ([`SiemRecords.java`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/siem/SiemRecords.java), [`RecordsViews.java`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/admin/RecordsViews.java), [`PlatformAdminController.java`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/admin/PlatformAdminController.java), [`PlatformViews.java`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/admin/PlatformViews.java)) | **CONSENT WITH CORRECTIONS** — `audit_event` has no body column; actors are `USR-` pseudonyms or `system:` tokens; account row keys become `USR-` pseudonyms and non-conforming keys become `KEY-` tokens; free-text reasons pass through `TextMasker::maskFreeText` plus estate and identifier checks; system/notifications expose only validated commit/time, schema version, booleans and destination kinds (`syslog`, `hec`). See D-01 for fail-closed 503 enforcement when privacy keys or dictionaries are missing. |
| Log appender and System logs privacy and bounds ([`LogRing.java`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/ops/LogRing.java), [`LogRingTest.java`](file://<workspace-root>/java/control/src/test/java/io/rwsafe/control/ops/LogRingTest.java)) | **CONSENT** — `RingAppender` reads only level, logger name, unformatted `e.getMessage()` and `IThrowableProxy.getClassName()`, ignoring arguments, formatted messages, exception messages, stack traces and MDC. Third-party templates are dropped; own templates require `fixedTemplate` (`<= 160` chars, no `@`/`/`/`\`/`=`/mid-word `.`, `<= 4` consecutive digits), a source scan proves all own log calls use string literals, and `PlatformAdminController.logs()` re-applies `IdentifierCheck` and estate-term checks (hiding all templates when `!keys.maskingAvailable()`). Memory is bounded (`24` hourly buckets, `256` keys + `other`, `50` recent events). |
| Scheduled jobs behaviour and catalog parity ([`ScheduledJobs.java`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/ops/ScheduledJobs.java), [`JobCatalog.java`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/ops/JobCatalog.java), [`JobRuns.java`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/ops/JobRuns.java), [`PolicyRegistryService.java`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/policy/PolicyRegistryService.java), [`CaptureRetentionJob.java`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/capture/CaptureRetentionJob.java), [`JobCatalogTest.java`](file://<workspace-root>/java/control/src/test/java/io/rwsafe/control/ops/JobCatalogTest.java)) | **CONSENT WITH CORRECTIONS** — Schedules (`PT1M`/`PT5M`, `0 20 0,6,12,18 * * *` `Europe/Istanbul`, `PT5M`/`PT5M`, `PT30S`/`PT30S`), work bodies, failure codes (simple class name or fixed uppercase code, never exception messages) and bounded in-memory ring (`20` runs, `16` fixed count keys) preserve prior job behaviour and `JobCatalogTest` enforces 1-to-1 schedule parity. See D-03 for clearing `runningSince` on non-`RuntimeException` `Throwable`. |
| Masked-role leak probe coverage ([`MaskedRoleLeakProbeTest.java`](file://<workspace-root>/java/control/src/test/java/io/rwsafe/control/privacy/MaskedRoleLeakProbeTest.java)) | **CONSENT** — All five new `/api/v1/admin/*` routes are walked by the masked role (verified 403 `FORBIDDEN`) and by `security_admin` (verified 200 with zero canary hits across bodies and headers). |
| Frontend navigation, menu visibility and pages ([`navigation.ts`](file://<workspace-root>/frontend/src/navigation.ts), [`adminMenu.tsx`](file://<workspace-root>/frontend/src/adminMenu.tsx), [`AuditLogPage.tsx`](file://<workspace-root>/frontend/src/pages/admin/AuditLogPage.tsx), [`JobLogPage.tsx`](file://<workspace-root>/frontend/src/pages/admin/JobLogPage.tsx), [`NotificationsPage.tsx`](file://<workspace-root>/frontend/src/pages/admin/NotificationsPage.tsx), [`SystemLogsPage.tsx`](file://<workspace-root>/frontend/src/pages/admin/SystemLogsPage.tsx), [`SystemPage.tsx`](file://<workspace-root>/frontend/src/pages/admin/SystemPage.tsx)) | **CONSENT** — Menu visibility matches server rules (`canReadAuditLog` for `/admin/audit`, `isAdministrator` for the rest, never `me.masked`), actor filter validates `ACTOR_PATTERN` before request, and server error reasons are rendered via `ErrorPanel`. |

---

### (2) DISSENT

| Finding ID | File and Line / Symbol | What is Wrong | Severity | Concrete Correction |
| :--- | :--- | :--- | :--- | :--- |
| **D-01** | [`RecordsAdminController.java:38-40, 88, 140-143`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/admin/RecordsAdminController.java#L140-L143) and [`SiemRecords.java:204-212, 236-248`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/siem/SiemRecords.java#L204-L212) (`RecordsAdminController#records`, `SiemRecords#pseudonym`, `SiemRecords#ledgerReason`) | The Javadoc on `RecordsAdminController` states that without the privacy key, the estate dictionary or the name dictionary `/api/v1/admin/audit` is refused with HTTP 503 (AGENTS.md 4.10). However, `records()` passes lazy lambdas `pseudonymiser::user` and `key -> pseudonymiser.token("KEY", key)`, and `SiemRecords.pseudonym` and `SiemRecords.ledgerReason` catch `RuntimeException` and substitute `[WITHHELD]`. If a page has no free-text reason (or if `maskFreeText` throws only on invocation and `ledgerReason` catches it) and the privacy key is missing while the estate dictionary is present, `GET /api/v1/admin/audit` returns HTTP 200 instead of failing closed with HTTP 503. | **P1** | In `RecordsAdminController.records()` (before building `SiemRecords`), explicitly verify `keys.keyAvailable()` and `masking.available()` (or invoke the fail-closed check that throws the 503 exception when any of privacy key, estate dictionary, or name dictionary is missing), and add a test covering missing key/dictionary on `/api/v1/admin/audit`. |
| **D-02** | [`RecordsAdminController.java:97-102`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/admin/RecordsAdminController.java#L97-L102) (`RecordsAdminController#audit`) | `cursor` validation checks `cursor.length() <= 19` and all ASCII digits, then calls `Long.parseLong(cursor)`. Any 19-digit string above `Long.MAX_VALUE` (`9223372036854775808`–`9999999999999999999`) passes the check and throws an uncaught `NumberFormatException` instead of `BadRequest("INVALID_CURSOR", ...)`; `"0"` is also accepted though `audit_id >= 1`. | **P2** | Parse `cursor` inside a `try { before = Long.parseLong(cursor); } catch (NumberFormatException e)` block and throw `BadRequest("INVALID_CURSOR", ...)` when parsing fails or `before <= 0`. |
| **D-03** | [`JobRuns.java:74-91`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/ops/JobRuns.java#L74-L91) (`JobRuns#run`) | `track.runningSince` is set before `body.get()` and cleared only inside `record(...)` after `catch (RuntimeException e)`. If `body.get()` throws an `Error` (e.g. `AssertionError` or `LinkageError`), `record(...)` is skipped and `track.runningSince` remains non-null for the lifetime of the instance, leaving the job permanently in `"RUNNING"` state with `nextRunAt = null`. | **P2** | Move `record(track, started, clock.instant(), result)` into a `finally` block (defaulting `result` to `JobResult.failed("FAILED", Map.of())` or catching `Throwable t` to set `result = JobResult.failed(t)` before rethrowing `Error`). |
| **D-04** | [`AuditLedgerQueries.java:87-91`](file://<workspace-root>/java/persistence/src/main/java/io/rwsafe/persistence/AuditLedgerQueries.java#L87-L91) and [`RecordsAdminController.java:106`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/admin/RecordsAdminController.java#L106) (`AuditLedgerQueries#actionIds`) | `actionIds()` runs `SELECT DISTINCT action_id FROM audit_event ORDER BY action_id LIMIT 200` without time bounds on every `GET /api/v1/admin/audit` request (including every cursor page), scanning the full table even though `page(...)` is bounded to `[start, end)`. | **P2** | Scope `actionIds(Instant from, Instant to)` to `AUDIT_OCCURRED_AT.ge(from).and(AUDIT_OCCURRED_AT.lt(to))` (or skip re-querying when `before != null` if not needed). |

---

### (3) QUESTIONS FOR THE PRODUCT OWNER

None. PO decision Q-47 decisions 1.3 and 1.4 are clear and require no further PO decision for this slice.

---

### (4) VERDICT

**MERGE WITH CORRECTIONS**

---

### (5) INSTRUCTIONS RECEIVED (VERBATIM)

1. System instructions (`AGENTS.md` user rule):
   - Durable, vendor-neutral engineering, security and privacy law in `AGENTS.md` (sections 1 to 14), including Role dispatch (`State your role in your first message`), Privacy and masking law (section 4), Data-plane law (section 5), Policy-registry law (section 6), UNKNOWN / fail-closed law (section 7), Shared-host law (section 8), Git authority and execution law (section 9), Ship gate law (section 10), External model and second-opinion consultation law (section 11), Decision records (section 12), Multi-agent work (section 13), and Lessons designed in (section 14).
2. User request (`<USER_REQUEST>`):
```text
/plan REVIEW: second independent review of pull request 51 (AGENTS.md section 9, security-sensitive: RBAC rules, the audit
ledger read path, a log appender, scheduled jobs of the capture retention and the policy snapshot), branch
`feature/admin-records-platform`
LENS: whether Administration → RECORDS (audit log, job log) and PLATFORM (system, system logs, notifications) (PO
decision Q-47 decisions 1.3 and 1.4) show operators what they need without any identifier, prompt or response body
leaking, without widening any role, and without changing what the scheduled jobs do.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway; a public repository).
You start from a fresh context. Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this
repository. Do not edit, run shell, or widen the review. Your job: find any identifier (login name, group, address,
host, account, TCKN, IBAN, phone, card) or any prompt/response body that can reach the audit screen, the job log, the
system screen, the log screen, a log line kept by the appender, or the browser; any role that can now read more than
before (the new `admin.audit.read` rule and its order, privacy officer access); any route the masked role reaches; any
behaviour change in the snapshot re-sign, capture retention, capture key re-read or disk watermark jobs after they were
moved into one class (timing, error handling, a skipped run, a fail-open path); any unbounded memory, query or page
size; any ledger query that can be abused (filters, cursor, time range). Return exactly: (1) a CONSENT table (area,
verdict), (2) a DISSENT table (finding id, file and line or symbol, what is wrong, severity P0/P1/P2, the concrete
correction), (3) QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation), (4) a one-line verdict MERGE / MERGE
WITH CORRECTIONS / DO NOT MERGE, then (5) list every instruction you received, verbatim. Be concrete and short. Never
quote or invent an address, host name, account, serial or secret. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 5, 9)
- docs/design/PO_DECISION_RECORD_2026_11_02_Q47_ADMIN_SECTION.md
- java/control/src/main/java/io/rwsafe/control/ops/ (every file)
- java/control/src/main/java/io/rwsafe/control/admin/RecordsAdminController.java, RecordsViews.java,
  PlatformAdminController.java, PlatformViews.java
- java/persistence/src/main/java/io/rwsafe/persistence/AuditLedgerQueries.java and the SiemRecords class (ledgerEntry)
- java/control/src/main/java/io/rwsafe/control/identity/AccessRules.java and SecurityConfig.java
- the previous scheduled-job code in PolicyRegistryService (reissueWhenDue) and CaptureRetentionJob
- the tests: JobRunsTest, JobCatalogTest, LogRingTest, RecordsAndPlatformIntegrationTest, AuditLedgerQueriesTest,
  AccessRulesTest, MaskedRoleLeakProbeTest
- frontend/src/navigation.ts, frontend/src/adminMenu.tsx, frontend/src/pages/admin/ (the five new pages)
```
