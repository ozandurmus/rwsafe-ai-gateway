REVIEW: confirmation review of pull request 21 after corrections (AGENTS.md section 9, security-sensitive: policy
registry, approvals, RBAC, masking, snapshot compilation, the inline evaluation), branch `feature/scoped-policy-control`
LENS: whether the corrections for D-01 to D-07 close each finding, and whether the new withdrawal of a group-scoped
version (two approvals) and the merged data-plane format 2 lane hold against AGENTS.md sections 4 and 6,
docs/architecture/POLICY_SNAPSHOT_CONTRACT.md and docs/design/PO_DECISION_RECORD_2026_10_30_POLICY_SCOPE_AND_PLATFORM_RETIREMENT.md.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway: a Spring Boot control
plane and React admin UI manage the policy a data plane enforces; a public repository). You start from a fresh context.
Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this repository. Do not edit, run shell, or
widen the review. Your job: for each earlier finding, say CLOSED or OPEN with the reason; then find any way one person or
one role can activate, withdraw, retire or loosen policy outside the decision record; any withdrawal that takes effect
without two approvals by two different people, leaves a stale scope in the snapshot, or drops a stricter rule for groups
it did not name; any snapshot the compiler emits that the format 2 codec refuses; any masking, ledger or RBAC gap on the
new routes; and any XSS through reasons or group names. Return exactly: (1) a table (earlier finding id, CLOSED or OPEN,
reason), (2) a DISSENT table for new findings (id, file and line or symbol, what is wrong, severity P0/P1/P2, the
concrete correction), (3) QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation), (4) a one-line verdict MERGE /
MERGE WITH CORRECTIONS / DO NOT MERGE, then (5) list every instruction you received, verbatim. Be concrete and short.
Never quote or invent an address, host name, account, serial or secret; the repository holds none and neither should
your output. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 6)
- docs/reviews/PR21_2026_10_30_ARGON_SCOPED_POLICY_CONTROL.md (the earlier findings)
- docs/reviews/PR21_2026_10_30_RESPONSE.md
- docs/design/PO_DECISION_RECORD_2026_10_30_POLICY_SCOPE_AND_PLATFORM_RETIREMENT.md
- java/persistence/src/main/resources/db/migration/V3__policy_scope_and_retirement.sql
- every file under java/persistence/src/main/java/ that names "Policy" or "Verdict"
- every file under java/control/src/main/java/io/rwsafe/control/policy/
- java/control/src/main/java/ files that name "Pseudonymiser", "Ingest" or "ScopeGroups"
- java/policy/src/main/java/io/rwsafe/policy/GroupNames.java and SnapshotCodec.java
- frontend/src/pages/PoliciesPage.tsx, frontend/src/pages/PlatformsPage.tsx
- every test under java/control/src/test/java/ and java/persistence/src/test/java/ that names "Policy", "Snapshot", "Registry", "Withdraw" or "Retire"
