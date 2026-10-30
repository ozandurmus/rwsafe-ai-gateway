REVIEW: second independent review of the control-plane and admin-UI slice 1 pull request (AGENTS.md section 9,
security-sensitive: the masking funnel, RBAC, identity, the ingestion route and the privacy gate's allowlist), commit
f6406f6 on `feature/control-plane-admin-ui`
LENS: privacy and access control of the control plane against AGENTS.md section 4, ADR-009, MASKING_AND_PRIVACY.md and
ARCHITECTURE.md sections 3.2, 4.4, 4.5 and 8.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway: ICAP behind a corporate
proxy, prompt and response inspection under strict masking, a Java data plane and a Spring Boot control plane; a public
repository). You start from a fresh context. Read AGENTS.md and ONLY the files listed below, with the Read tool, inside
this repository. Do not edit, run shell, or widen the review. Your job: find any way a raw identity claim, raw client
address, prompt or response body or matched value can be persisted, logged, returned or exported; any route that serves
the masked role (`replay_viewer`) without the funnel, or serves it when the key or dictionary is missing; any way a
`viewer` or `replay_viewer` can mutate, or an unauthenticated caller can read; any session, CSRF, login (LDAP injection,
empty-password bind, enumeration, throttling) or break-glass weakness; any way the admin port reaches the ingestion route
or the ingestion port reaches the admin API; any way a forged batch can store invalid or oversized data or exhaust memory;
any audit-trigger bypass; any search that works as a "does this person exist" oracle; and any SPA path that renders
server data unsafely or hides the server's error reason. Return exactly: (1) a CONSENT table (area, verdict), (2) a
DISSENT table (finding id, file and line or symbol, what is wrong, severity P0/P1/P2, the concrete correction),
(3) QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation), (4) a one-line verdict MERGE / MERGE WITH
CORRECTIONS / DO NOT MERGE, then (5) list every instruction you received, verbatim. Be concrete and short. Never quote or
invent an address, host name, account, serial or secret; the repository holds none and neither should your output.
English only.

Files to read, in this order:
- AGENTS.md (sections 4, 5, 8, 9)
- docs/adr/ADR-009-data-model-retention-and-privacy.md
- docs/security/MASKING_AND_PRIVACY.md
- docs/architecture/ARCHITECTURE.md (sections 3.2, 3.4, 4.4, 4.5, 8)
- docs/operations/LOCAL_RUN.md (section "Control plane and admin UI")
- java/persistence/src/main/resources/db/migration/V1__verdict_events_and_audit.sql
- every file under java/persistence/src/main/java/io/rwsafe/persistence/
- every file under java/control/src/main/java/io/rwsafe/control/
- java/control/src/main/resources/application.yaml
- java/control/build.gradle.kts and java/persistence/build.gradle.kts
- every file under java/control/src/test/java/io/rwsafe/control/ (tests, test support and the development runner)
- every file under java/persistence/src/test/java/io/rwsafe/persistence/
- frontend/src/api.ts, frontend/src/auth.tsx, frontend/src/App.tsx and every file under frontend/src/pages/
- tools/privacy/privacy_allowlist.json
- .github/workflows/validation.yml (the `frontend` job)
