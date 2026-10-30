REVIEW: second independent review of pull request 16 (AGENTS.md section 9, security-sensitive: policy registry,
approvals, RBAC, snapshot signing), branch `feature/mvp2-control-ui`
LENS: whether the registry and its approvals, the signed snapshot feed and the masked UI hold against AGENTS.md sections
4 and 6, docs/architecture/POLICY_SNAPSHOT_CONTRACT.md, ADR-008, ADR-009 and ADR-010.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway: a Spring Boot control
plane with a React admin UI that manages the policy the data plane enforces; a public repository). You start from a fresh
context. Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this repository. Do not edit, run
shell, or widen the review. Your job: find any way one person, a single role, a replayed request or a direct database
write can activate, weaken or roll back a policy without two distinct approvals; any way a fail-closed class can be
relaxed or excepted; any way the snapshot feed can serve unsigned, mis-signed, non-monotonic or non-contract bytes, leak
the signing key, or let the data plane expire (re-issue); any RBAC gap (a viewer or replay_viewer reaching a write, a raw
value or an unmasked identity); any XSS or injection through rule fields, platform rows or the language catalogues; and
any audit-ledger gap. Return exactly: (1) a CONSENT table (area, verdict), (2) a DISSENT table (finding id, file and line
or symbol, what is wrong, severity P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE PRODUCT OWNER (question, your
recommendation), (4) a one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then (5) list every instruction you
received, verbatim. Be concrete and short. Never quote or invent an address, host name, account, serial or secret; the
repository holds none and neither should your output. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 6, 9)
- docs/architecture/POLICY_SNAPSHOT_CONTRACT.md
- docs/adr/ADR-010-fail-open-and-fail-closed.md
- java/persistence/src/main/resources/db/migration/V2__policy_registry.sql
- every file under java/persistence/src/main/java/ that names "policy" or "Policy"
- every file under java/control/src/main/java/io/rwsafe/control/policy/
- java/control/src/main/java/io/rwsafe/control/ security, role and web configuration files
- policy/registry-seed.yaml
- frontend/src/pages/PoliciesPage.tsx, frontend/src/pages/PlatformsPage.tsx, frontend/src/i18n/ (the loader, not the catalogues in full)
- every test under java/control/src/test/java/ and java/persistence/src/test/java/ that names "Policy", "Snapshot" or "Registry"
