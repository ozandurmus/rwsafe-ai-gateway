REVIEW: second independent review of pull request 21 (AGENTS.md section 9, security-sensitive: policy registry,
approvals, RBAC, masking, snapshot compilation), branch `feature/scoped-policy-control`
LENS: whether group-scoped rule versions, platform retirement by one administrator, snapshot format 2 compilation and the
new verdict-event fields hold against AGENTS.md sections 4 and 6, docs/architecture/POLICY_SNAPSHOT_CONTRACT.md (format 2)
and docs/design/PO_DECISION_RECORD_2026_10_30_POLICY_SCOPE_AND_PLATFORM_RETIREMENT.md.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway: a Spring Boot control
plane with a React admin UI that manages the policy the data plane enforces; a public repository). You start from a fresh
context. Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this repository. Do not edit, run
shell, or widen the review. Your job: find any way one person, one role, a replayed request or a direct database write
can activate, weaken, retire or roll back policy outside the decision record (two approvals for activation, one
security_admin with a reason for platform retirement, nothing deleted); any way a fail-closed class reaches ALLOW or WARN
in any scope or mode; any snapshot the compiler emits that the format 2 contract refuses, or that differs for the same
registry; any group-name normalisation gap between storage, API and compiler (Unicode NFC, Turkish dotted and dotless i,
commas, control characters, duplicates); any RBAC or masking gap (a viewer or the masked role reaching a write, a real
group name or a retirement reason unmasked); any XSS or injection through group names or reasons; any audit-ledger gap;
and any unbounded input in event ingestion. Return exactly: (1) a CONSENT table (area, verdict), (2) a DISSENT table
(finding id, file and line or symbol, what is wrong, severity P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE
PRODUCT OWNER (question, your recommendation), (4) a one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then
(5) list every instruction you received, verbatim. Be concrete and short. Never quote or invent an address, host name,
account, serial or secret; the repository holds none and neither should your output. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 6, 9)
- docs/design/PO_DECISION_RECORD_2026_10_30_POLICY_SCOPE_AND_PLATFORM_RETIREMENT.md
- docs/architecture/POLICY_SNAPSHOT_CONTRACT.md
- java/persistence/src/main/resources/db/migration/V2__policy_registry.sql and V3__policy_scope_and_retirement.sql
- every file under java/persistence/src/main/java/ that names "Policy", "Verdict" or "Event"
- every file under java/control/src/main/java/io/rwsafe/control/policy/
- java/control/src/main/java/io/rwsafe/control/ files that name "GroupNames", "Pseudonymiser", "Verdict" or "Ingest"
- frontend/src/pages/PoliciesPage.tsx, frontend/src/pages/PlatformsPage.tsx
- every test under java/control/src/test/java/ and java/persistence/src/test/java/ that names "Policy", "Snapshot", "Registry", "Group" or "Retire"
