REVIEW: second independent review of pull request 30 (AGENTS.md section 9, security-sensitive: policy registry,
RBAC, database triggers), branch `feature/q41-single-admin-withdrawal`
LENS: whether the single-administrator withdrawal of a group-scoped rule version holds against AGENTS.md sections 4 and 6
and docs/design/PO_DECISION_RECORD_2026_10_31_Q41_Q42_Q44.md (one security_admin, a checked reason, immediate effect,
ledgered, history kept, nothing deleted).

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway: a control plane with a
policy registry that the data plane enforces; a public repository). You start from a fresh context. Read AGENTS.md and
ONLY the files listed below, with the Read tool, inside this repository. Do not edit, run shell, or widen the review.
Your job: find any way someone other than a security_admin (a viewer, the privacy officer, the masked role, a direct SQL
write without the ledger, a replayed request) withdraws, un-withdraws or alters a version; any withdrawal that touches
another scope, a baseline ANY version, a platform or flow row, or a fail-closed invariant; any reason that stores an
identifier; any snapshot that keeps a withdrawn scope; any migration step that loses history or breaks old V3 rows; and
any UI path that hides the server's refusal. Return exactly: (1) a CONSENT table (area, verdict), (2) a DISSENT table
(finding id, file and line or symbol, what is wrong, severity P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE
PRODUCT OWNER (question, your recommendation), (4) a one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then
(5) list every instruction you received, verbatim. Be concrete and short. Never quote or invent an address, host name,
account, serial or secret; the repository holds none and neither should your output. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 6)
- docs/design/PO_DECISION_RECORD_2026_10_31_Q41_Q42_Q44.md
- java/persistence/src/main/resources/db/migration/V3__policy_scope_and_retirement.sql and V9__single_admin_withdrawal.sql
- java/persistence/src/main/java/io/rwsafe/persistence/PolicyRegistryStore.java
- every file under java/control/src/main/java/io/rwsafe/control/policy/
- frontend/src/pages/PoliciesPage.tsx
- every test that names "Withdraw", "PolicyRegistry" or "SnapshotCompiler"
