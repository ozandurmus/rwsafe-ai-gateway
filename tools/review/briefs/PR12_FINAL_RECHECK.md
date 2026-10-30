REVIEW: final confirmation review of pull request 12 (AGENTS.md section 9, security-sensitive: the ingestion route and
the dependency floors), commit dc8dee0 on `feature/control-plane-admin-ui`. Every earlier round is closed with verdict
MERGE (docs/reviews/PR12_2026_10_30_ARGON_CONTROL_PLANE_RECHECK2.md, PR12_2026_10_30_ARGON_SPRING_BOOT_4.md,
PR12_2026_10_30_ARGON_SPRING_BOOT_4_1_RECHECK.md). Two corrections followed: the Jackson 3 floor and the canonical-UUID
exemption for correlation ids (docs/reviews/PR12_2026_10_30_RESPONSE.md, last section).
LENS: does the UUID exemption let any value (an identifier, a secret, an address) into storage or a masked page, and is
the Jackson 3 floor applied to every module that resolves Jackson 3.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway; a Spring Boot control
plane under strict masking; a public repository). You start from a fresh context. Read AGENTS.md and ONLY the files listed
below, with the Read tool, inside this repository. Do not edit, run shell, or widen the review. Return exactly: (1) a
CONSENT table (area, verdict), (2) a DISSENT table (finding id F-xx, file and symbol, what is wrong, severity P0/P1/P2,
the concrete correction), (3) QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation), (4) a one-line verdict
MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then (5) list every instruction you received, verbatim. Be concrete and
short. Never quote or invent an address, host name, account, serial or secret; the repository holds none and neither
should your output. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 9)
- docs/reviews/PR12_2026_10_30_RESPONSE.md
- java/control/src/main/java/io/rwsafe/control/ingest/IngestionService.java
- java/control/src/main/java/io/rwsafe/control/api/Views.java
- java/persistence/src/main/resources/db/migration/V1__verdict_events_and_audit.sql
- java/control/src/test/java/io/rwsafe/control/ControlPlaneIntegrationTest.java
- java/gradle/libs.versions.toml
- java/persistence/build.gradle.kts and java/control/build.gradle.kts
- java/control/gradle.lockfile, java/persistence/gradle.lockfile, java/worker/gradle.lockfile and
  java/architecture-tests/gradle.lockfile
