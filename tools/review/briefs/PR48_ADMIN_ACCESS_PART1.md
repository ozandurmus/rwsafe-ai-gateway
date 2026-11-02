REVIEW: second independent review of pull request 48 (AGENTS.md section 9, security-sensitive: RBAC, identity,
authentication, sessions, a migration with guard functions, the masked role), branch `feature/admin-access-1`
LENS: whether Administration → Access part 1 (local users, roles and permissions, sessions; PO decision Q-47 decision
1.1) and the new layout keep every identity and masking rule of AGENTS.md section 4 and never let a user gain a role,
keep a session or sign in where they should not.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway; a public repository).
You start from a fresh context. Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this
repository. Do not edit, run shell, or widen the review. Your job: find any privilege escalation (a non-admin reaching
an admin route, an admin raising their own or another's privilege outside the rules, the replay_viewer exclusivity
broken); any way the last security_admin is disabled or demoted, including races; any password weakness (generated
password strength, one-time display leaking into logs, caches or the ledger, hash choice, the forced change bypassed,
the change route usable without the current password, throttle bypass); any session that survives a disable, reset or
role change, or a session id or client address exposed; any login name or identifier reaching a URL, a log, a metric
label, a trace, the masked view, an export or the SIEM; any route the masked role reaches; any drift between the
roles page and what the security chain enforces; any guard function or ledger rule that can be bypassed or edited.
Return exactly: (1) a CONSENT table (area, verdict), (2) a DISSENT table (finding id, file and line or symbol, what is
wrong, severity P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE PRODUCT OWNER (question, your
recommendation), (4) a one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then (5) list every instruction
you received, verbatim. Be concrete and short. Never quote or invent an address, host name, account, serial or secret.
English only.

Files to read, in this order:
- AGENTS.md (sections 4, 9)
- docs/design/PO_DECISION_RECORD_2026_11_02_Q47_ADMIN_SECTION.md
- java/persistence/src/main/resources/db/migration/V11__local_users.sql and the persistence classes it backs
- java/control/src/main/java/io/rwsafe/control/identity/ (every file, especially AccessRules, LocalUsers,
  LocalUserAuthenticator, ActiveSessions, SecurityConfig, AuthController, IdentityService, BreakGlassAccounts,
  LoginThrottle)
- java/control/src/main/java/io/rwsafe/control/admin/ (every file)
- the tests for those classes, MaskedRoleLeakProbeTest and FailClosedProbe
- frontend/src/navigation.ts, frontend/src/adminMenu.tsx, frontend/src/App.tsx, frontend/src/auth.tsx,
  frontend/src/api.ts and frontend/src/pages/admin/
