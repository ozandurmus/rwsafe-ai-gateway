REVIEW: confirmation review of the Spring Boot 4.0.8 -> 4.1.1 step in pull request 12 (AGENTS.md section 9,
security-sensitive: the gate chain, RBAC, CSRF, session, the masking funnel, the ingestion connector, persistence and the
audit trigger run on the moved versions), commit 9ea46ea on `feature/control-plane-admin-ui`. The 4.0.8 migration passed
review (docs/reviews/PR12_2026_10_30_ARGON_SPRING_BOOT_4.md, verdict MERGE); the PO then set the line to the newest
Spring Boot 4.1.x at least two weeks old (docs/design/PO_DECISION_RECORD_2026_10_30_SPRING_BOOT_4.md).
LENS: did Spring Boot 4.1.1 (Spring Security 7.1.1, Flyway 12.4.0, jOOQ 3.21.7, UnboundID 7.0.5) change any security,
privacy or audit behaviour, and is M-01 answered.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway; a Spring Boot control
plane under strict masking; a public repository). You start from a fresh context. Read AGENTS.md and ONLY the files listed
below, with the Read tool, inside this repository. Do not edit, run shell, or widen the review. Look for: a Spring
Security 7.1 default that differs from 6.5 or 7.0 and weakens the two filter chains (authorisation rules, the custom
authorisation manager on mutations, CSRF repository and request handler, session fixation, the JSON entry point and
access-denied handler, security headers); an auto-configuration that now activates (Flyway, jOOQ, a generated user, a
Jackson 3 converter taking precedence over Jackson 2 so that unknown fields are accepted or dates change shape); a
Tomcat 11 change that breaks the second connector, the port filter or the body limit; a dependency version below its
stated floor; and a test that no longer proves what its name says. Return exactly: (1) a CONSENT table (area, verdict),
(2) a DISSENT table (finding id M-xx, file and symbol, what is wrong, severity P0/P1/P2, the concrete correction),
(3) QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation), (4) a one-line verdict MERGE / MERGE WITH
CORRECTIONS / DO NOT MERGE, then (5) list every instruction you received, verbatim. Be concrete and short. Never quote or
invent an address, host name, account, serial or secret; the repository holds none and neither should your output.
English only.

Files to read, in this order:
- AGENTS.md (sections 4, 9, 10)
- docs/design/PO_DECISION_RECORD_2026_10_30_SPRING_BOOT_4.md
- docs/reviews/PR12_2026_10_30_ARGON_SPRING_BOOT_4.md
- docs/reviews/PR12_2026_10_30_RESPONSE.md (section "CI findings on the same commit")
- java/gradle/libs.versions.toml
- java/control/build.gradle.kts and java/persistence/build.gradle.kts
- java/control/gradle.lockfile and java/persistence/gradle.lockfile
- java/control/src/main/resources/application.yaml
- java/control/src/main/java/io/rwsafe/control/ControlApplication.java
- java/persistence/src/main/java/io/rwsafe/persistence/Database.java and AuditContext.java
- java/persistence/src/main/resources/db/migration/V1__verdict_events_and_audit.sql
- every file under java/control/src/main/java/io/rwsafe/control/config/
- every file under java/control/src/main/java/io/rwsafe/control/identity/
- java/control/src/main/java/io/rwsafe/control/privacy/MaskingFunnel.java
- java/control/src/main/java/io/rwsafe/control/ingest/IngestionController.java
- java/control/src/main/java/io/rwsafe/control/api/ApiExceptionHandler.java
- java/control/src/test/java/io/rwsafe/control/HttpJsonMapperTest.java
- java/control/src/test/java/io/rwsafe/control/ControlPlaneIntegrationTest.java
- java/control/src/test/java/io/rwsafe/control/MaskingUnavailableIntegrationTest.java
- java/control/src/test/java/io/rwsafe/control/privacy/FunnelCoverageTest.java
