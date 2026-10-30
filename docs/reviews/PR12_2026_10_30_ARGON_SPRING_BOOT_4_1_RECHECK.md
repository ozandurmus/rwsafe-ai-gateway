<!-- Argon consultation 2026-10-30T16:56:17Z, model gemini-4-argon-high, effort high; unaltered output except 0 local paths masked (AGENTS.md 4.2) -->

Role: `REVIEWER`

### (1) CONSENT Table

| Area | Verdict |
|---|---|
| PO decision record & version alignment (`PO_DECISION_RECORD_2026_10_30_SPRING_BOOT_4.md`, `libs.versions.toml`, `control/gradle.lockfile`, `persistence/gradle.lockfile`) | **CONSENT** — Ratified PO decision record sets the line to Spring Boot `4.1.1` (newest `4.1.x` at least two weeks old). Both lockfiles resolve Spring Boot `4.1.1`, Spring Framework `7.0.9`, Spring Security `7.1.1`, Tomcat `11.0.27`, Jackson 2 `2.21.7`, Jackson 3 `3.1.5`, PostgreSQL `42.7.13`, HikariCP `7.0.2`, Flyway `12.4.0`, jOOQ `3.21.7`, UnboundID `7.0.5`, and JUnit `6.0.3`. |
| Prior finding M-01 resolution (`libs.versions.toml`, `control/build.gradle.kts`, `PR12_2026_10_30_RESPONSE.md`) | **CONSENT** — M-01 is answered and closed: `control/build.gradle.kts` updates the constraint comment to Tomcat `11.0.27` (over Boot 4.1.1's managed `11.0.24`), and `libs.versions.toml` documents why `junit = "5.10.3"` stays for non-Boot modules (`jazzer-junit` `0.24.0` compatibility) while Boot-managed modules resolve JUnit `6.0.3`. |
| Spring Security 7.1.1 filter chains, RBAC, CSRF, session & headers (`SecurityConfig`, `AuthController`, `IdentityService`, `Roles`, `BreakGlassAccounts`) | **CONSENT** — Spring Security `7.1.1` preserves the behaviour of both chains: `@Order(1)` `internalChain` (`securityMatcher("/internal/**")`, stateless, only `POST /internal/v1/verdict-events` permitted, `anyRequest().denyAll()`) and `@Order(2)` `adminChain` (`GET /api/v1/**` requires one of the three roles; mutations under `/api/**` enforce `hasRole(SECURITY_ADMIN) && !hasRole(REPLAY_VIEWER)`; `CookieCsrfTokenRepository.withHttpOnlyFalse()` with `SameSite=Strict`, `Path=/`, configurable `Secure`, and `CsrfTokenRequestAttributeHandler`; session invalidation, new session creation, and CSRF token rotation on login; session invalidation and CSRF cookie clearing on logout; CSP, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`; JSON 401/403 handlers via Jackson 2). |
| UnboundID 7.0.5 & login throttling (`LdapAuthenticator`, `LoginThrottle`) | **CONSENT** — `LdapAuthenticator` on UnboundID `7.0.5` enforces `ldaps` (or literal loopback for `ldap`), `HostNameSSLSocketVerifier(true)`, non-blank bind DN, non-empty bind password file, `Filter.encodeValue`, non-empty user password before bind, pooled `bindAndRevertAuthentication` with retry on invalid connections, and closes the initial connection on bind failure. `LoginThrottle` enforces per-pair (5) and per-client (20) lockouts without cross-client lockout or lock eviction. |
| Flyway 12.4.0, jOOQ 3.21.7 & audit trigger (`Database`, `AuditContext`, `V1__verdict_events_and_audit.sql`, `PersistenceConfig`, `ControlApplication`) | **CONSENT** — `Database.migrateAndOpen` runs Flyway `12.4.0` with `cleanDisabled(true)` and `validateMigrationNaming(true)`, and opens jOOQ `3.21.7` (`SQLDialect.POSTGRES`, `withExecuteLogging(false)`, logo/tips disabled). `AuditContext` validates `USR-<10 hex>` or `system:<name>` actors and applies transaction-local `set_config(..., true)` settings enforced by `rwsafe_audit_row` and `rwsafe_audit_insert_only_by_trigger` (`pg_trigger_depth() < 2`). `UserDetailsServiceAutoConfiguration`, `JooqAutoConfiguration`, and `FlywayAutoConfiguration` remain excluded, and neither `spring-boot-jooq` nor `spring-boot-flyway` is on the classpath. |
| Jackson 2 / Jackson 3 split (`application.yaml`, `control/build.gradle.kts`, `IngestionController`, `ApiExceptionHandler`, `HttpJsonMapperTest`) | **CONSENT** — `spring-boot-jackson2:4.1.1` with `spring.http.converters.preferred-json-mapper: jackson2` keeps Spring MVC HTTP JSON on Jackson 2 (`2.21.7`) with `fail-on-unknown-properties: true`, `fail-on-null-for-primitives: true`, and `write-dates-as-timestamps: false`; `IngestionController` streams via the injected Jackson 2 `ObjectMapper`; `HttpJsonMapperTest` and `ControlPlaneIntegrationTest.theContractIsExact` verify converter precedence, unknown-field rejection, and ISO-8601 `Instant` formatting. |
| Masking funnel & Tomcat 11.0.27 connectors/limits (`MaskingFunnel`, `InternalConnector`, `BodyLimitFilter`, `FunnelCoverageTest`, `MaskingUnavailableIntegrationTest`, `ControlPlaneIntegrationTest`) | **CONSENT** — `MaskingFunnel` (`ResponseBodyAdvice`) intercepts all controller responses, sets `X-RWSAFE-Masked` and `X-RWSAFE-Mask-Rules`, fails closed with 503 `MASKING_UNAVAILABLE` or 500 `MASKING_NOT_PROVEN`, and passes `null` 204 bodies; `InternalConnector` and `BodyLimitFilter` isolate `/internal/` to the capture-sink port, require `Content-Length` on internal `POST`, and enforce 2 MiB internal and 64 KiB admin stream byte caps. All four test classes prove what their names state. |

---

### (2) DISSENT Table

| Finding ID | File and Symbol | What is wrong | Severity | Concrete correction |
|---|---|---|---|---|
| None | — | No security, privacy, audit, or dependency-floor defect found in the Spring Boot 4.0.8 -> 4.1.1 step; M-01 is resolved. | — | — |

---

### (3) QUESTIONS FOR THE PRODUCT OWNER

| Question | Recommendation |
|---|---|
| None — the move to Spring Boot 4.1.1 implements the ratified decision in `PO_DECISION_RECORD_2026_10_30_SPRING_BOOT_4.md` and preserves all security, privacy, and audit invariants. | Merge pull request 12. |

---

### (4) Verdict

MERGE

---

### (5) Verbatim Instructions Received

1. **User Request**:
```text
/plan REVIEW: confirmation review of the Spring Boot 4.0.8 -> 4.1.1 step in pull request 12 (AGENTS.md section 9,
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
```

2. **Workspace Rule (`AGENTS.md`)**:
   Loaded from `AGENTS.md` in the repository root (`# AGENTS.md — rwsafe-ai-gateway agent constitution`, sections 1–14).

3. **Slash Command Metadata (`/plan`)**:
   Standard Antigravity `/plan` command metadata injected by the CLI harness.
