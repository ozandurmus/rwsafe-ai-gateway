<!-- Argon consultation 2026-10-30T16:52:44Z, model gemini-4-argon-high, effort high; unaltered output except 2 local paths masked (AGENTS.md 4.2) -->

Role: `REVIEWER`

### (1) CONSENT Table

| Area | Verdict |
|---|---|
| Spring Security 7 filter chains (`SecurityConfig`: `internalChain` `@Order(1)` and `adminChain` `@Order(2)`, route matchers, stateless internal chain) | **CONSENT** — `securityMatcher("/internal/**")` and `authorizeHttpRequests` rules behave identically on Spring Security 7.0.7; only `POST /internal/v1/verdict-events` is permitted on the internal chain and `anyRequest().denyAll()` closes both chains. |
| RBAC & mutation authorisation (`SecurityConfig.adminChain`, `IdentityService.exclusive`, `Roles`) | **CONSENT** — `GET /api/v1/**` requires one of the three roles; mutations under `/api/**` enforce `hasRole(SECURITY_ADMIN) && !hasRole(REPLAY_VIEWER)`; `replay_viewer` remains exclusive at sign-in. |
| CSRF & session management (`SecurityConfig.csrfTokenRepository`, `AuthController.login`, `AuthController.logout`) | **CONSENT** — `CookieCsrfTokenRepository.withHttpOnlyFalse()` (`SameSite=Strict`, `Path=/`, configurable `Secure`) paired with `CsrfTokenRequestAttributeHandler` preserves SPA header validation; login invalidates any prior session, creates a new session, and rotates the CSRF token; logout invalidates the session and clears the CSRF cookie. |
| Security headers & JSON error handlers (`SecurityConfig.adminChain`, `ApiExceptionHandler`) | **CONSENT** — CSP, `Referrer-Policy: no-referrer`, and `X-Frame-Options: DENY` are intact; 401 (`AUTHENTICATION_REQUIRED`) and 403 (`CSRF_TOKEN_INVALID` / `FORBIDDEN`) are written as JSON via the Jackson 2 `ObjectMapper`; `HttpStatus.CONTENT_TOO_LARGE` (413) maps `BodyTooLargeException` both directly and when wrapped in `HttpMessageNotReadableException`. |
| Auto-configuration exclusions (`ControlApplication`, `PersistenceConfig`) | **CONSENT** — `UserDetailsServiceAutoConfiguration` (`org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration`) is excluded by class; `JooqAutoConfiguration` and `FlywayAutoConfiguration` are excluded by name and their Boot 4 auto-configuration artifacts (`spring-boot-jooq`, `spring-boot-flyway`) are absent from the lockfiles. |
| Jackson 2 / Jackson 3 split (`application.yaml`, `build.gradle.kts`, `IngestionController`, `HttpJsonMapperTest`) | **CONSENT** — `spring-boot-jackson2` with `spring.http.converters.preferred-json-mapper: jackson2` keeps Spring MVC HTTP JSON on Jackson 2 (`2.21.7`) with `fail-on-unknown-properties: true`, `fail-on-null-for-primitives: true`, and `write-dates-as-timestamps: false`; `IngestionController` streams via the injected Jackson 2 `ObjectMapper`; `HttpJsonMapperTest` and `ControlPlaneIntegrationTest.theContractIsExact` verify converter precedence, unknown-field rejection, and ISO-8601 `Instant` serialisation. |
| Masking funnel (`MaskingFunnel`, `FunnelCoverageTest`, `MaskingUnavailableIntegrationTest`) | **CONSENT** — `ResponseBodyAdvice` intercepts every controller response, sets `X-RWSAFE-Masked` and `X-RWSAFE-Mask-Rules`, fails closed with 503 `MASKING_UNAVAILABLE` or 500 `MASKING_NOT_PROVEN`, and passes empty (`null`) 204 bodies; `FunnelCoverageTest` verifies all `/api/` routes (8+ routes) on Spring Framework 7's `RequestMappingHandlerMapping`. |
| Tomcat 11 connectors, port isolation & body limits (`InternalConnector`, `BodyLimitFilter`, `application.yaml`) | **CONSENT** — `org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory` attaches the second connector with `maxPostSize(0)`; `internalPortFilter` (`HIGHEST_PRECEDENCE`) isolates `/internal/` to the internal connector port and requires `Content-Length` on `POST`; `BodyLimitFilter` (`HIGHEST_PRECEDENCE + 1`) enforces 2 MiB internal and 64 KiB admin byte caps on both declared length and stream reads; forwarded headers stay disabled by default (`none`, `^$`). |
| Dependency floors & lockfiles (`libs.versions.toml`, `control/gradle.lockfile`, `persistence/gradle.lockfile`) | **CONSENT** — `control` and `persistence` resolve Spring Boot `4.0.8`, Spring Framework `7.0.9`, Spring Security `7.0.7`, Tomcat `11.0.27`, Jackson 2 `2.21.7`, Jackson 3 `3.1.5`, PostgreSQL `42.7.13`, HikariCP `7.0.2`, Flyway `11.14.1`, jOOQ `3.19.37`, UnboundID `7.0.5`, and JUnit `6.0.3`. |

---

### (2) DISSENT Table

| Finding ID | File and Symbol | What is wrong | Severity | Concrete correction |
|---|---|---|---|---|
| M-01 | [libs.versions.toml](file://<workspace-root>/java/gradle/libs.versions.toml#L3) (`versions.junit`) and [build.gradle.kts](file://<workspace-root>/java/control/build.gradle.kts#L22) (`constraints` comment) | `libs.versions.toml` still declares `junit = "5.10.3"` (only modules importing `spring-boot-bom` get upgraded to JUnit `6.0.3` via BOM conflict resolution, leaving non-Boot modules on JUnit 5.10.3), and the comment in `java/control/build.gradle.kts` line 22 still refers to Tomcat `10.1.58` instead of `11.0.27`. Neither affects runtime security or privacy behaviour. | P2 (non-blocking) | Set `junit = "6.0.3"` in `java/gradle/libs.versions.toml` (regenerating non-Boot module lockfiles if any) and update the Tomcat floor comment in `java/control/build.gradle.kts` in a follow-up cleanup. |

---

### (3) QUESTIONS FOR THE PRODUCT OWNER

| Question | Recommendation |
|---|---|
| None — the Spring Boot 4.0.8 migration was directed by the Product Owner on 2026-10-30 and introduces no security or privacy behaviour change. | Merge pull request 12 as is; handle M-01 (`junit` catalog version string and comment) in the next routine commit. |

---

### (4) Verdict

MERGE

---

### (5) Verbatim Instructions Received

1. **User Request**:
```text
/plan REVIEW: second independent review of the Spring Boot 3.5.16 -> 4.0.8 migration in pull request 12 (AGENTS.md section 9,
security-sensitive: the gate chain, RBAC, CSRF, session, the masking funnel and the ingestion connector run on the
migrated framework), commit bba8f45 on `feature/control-plane-admin-ui` (the migration is commit bba8f45 alone; the rest of
the pull request passed three review rounds, verdict MERGE, docs/reviews/PR12_2026_10_30_ARGON_CONTROL_PLANE_RECHECK2.md)
LENS: did the move to Spring Framework 7.0.9, Spring Security 7, Tomcat 11, JUnit 6 and the Jackson 2 / Jackson 3 split
change any security or privacy behaviour of the control plane.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway; a Spring Boot control
plane under strict masking; a public repository). You start from a fresh context. Read AGENTS.md and ONLY the files listed
below, with the Read tool, inside this repository. Do not edit, run shell, or widen the review. Look for: a Spring
Security 7 default that differs from 6.5 and weakens the two filter chains (authorisation rules, the custom
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
- docs/reviews/PR12_2026_10_30_RESPONSE.md (section "CI findings on the same commit")
- java/gradle/libs.versions.toml
- java/control/build.gradle.kts and java/persistence/build.gradle.kts
- java/control/gradle.lockfile and java/persistence/gradle.lockfile
- java/control/src/main/resources/application.yaml
- java/control/src/main/java/io/rwsafe/control/ControlApplication.java
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
