REVIEW: second independent review of pull request 51 (AGENTS.md section 9, security-sensitive: RBAC rules, the audit
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
