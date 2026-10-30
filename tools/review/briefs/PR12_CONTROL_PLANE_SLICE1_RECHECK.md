REVIEW: confirmation review (round 2) of pull request 12, the control-plane and admin-UI slice 1 (AGENTS.md section 9,
security-sensitive: masking funnel, RBAC, identity, ingestion, the privacy gate), commit 82c7139 on
`feature/control-plane-admin-ui`
LENS: is every finding of the first review (docs/reviews/PR12_2026_10_30_ARGON_CONTROL_PLANE.md, D-01 to D-11, Q-1, Q-2)
closed by the code and test the response (docs/reviews/PR12_2026_10_30_RESPONSE.md) names, and did a correction open a
new defect.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway: ICAP behind a corporate
proxy, prompt and response inspection under strict masking, a Java data plane and a Spring Boot control plane; a public
repository). You start from a fresh context. Read AGENTS.md and ONLY the files listed below, with the Read tool, inside
this repository. Do not edit, run shell, or widen the review. For each finding ID give CLOSED, PARTLY CLOSED or OPEN with
the file and symbol that proves it; then list any NEW finding the corrections introduced (id N-xx, file and symbol, what
is wrong, severity P0/P1/P2, the concrete correction). Return exactly: (1) a table of the first review's IDs with their
status and evidence, (2) a NEW FINDINGS table, (3) QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation),
(4) a one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then (5) list every instruction you received,
verbatim. Be concrete and short. Never quote or invent an address, host name, account, serial or secret; the repository
holds none and neither should your output. English only. The spring-webmvc CVE acceptance is outside this review (it is
a Product Owner risk decision recorded separately).

Files to read, in this order:
- AGENTS.md (sections 4, 8, 9)
- docs/reviews/PR12_2026_10_30_ARGON_CONTROL_PLANE.md
- docs/reviews/PR12_2026_10_30_RESPONSE.md
- docs/security/MASKING_AND_PRIVACY.md (part B)
- java/persistence/src/main/resources/db/migration/V1__verdict_events_and_audit.sql
- every file under java/persistence/src/main/java/io/rwsafe/persistence/
- every file under java/persistence/src/test/java/io/rwsafe/persistence/
- every file under java/control/src/main/java/io/rwsafe/control/
- java/control/src/main/resources/application.yaml
- every file under java/control/src/test/java/io/rwsafe/control/
- frontend/src/auth.tsx, frontend/src/App.tsx, frontend/src/pages/TrafficPage.tsx, frontend/src/test/app.test.tsx
- tools/privacy/repository_privacy_check.py (the number rules and _HEX_DIGEST_RE) and
  tools/privacy/test_repository_privacy_check.py (test_digit_runs_inside_a_digest_are_not_identifiers)
- tools/privacy/privacy_allowlist.json
