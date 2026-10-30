# PO decision record 2026-10-30: the control plane moves to Spring Boot 4 instead of accepting two spring-webmvc CVEs

**Status:** RATIFIED — Product Owner, 2026-10-30 (chat in the control-plane engineer session, answering whether to accept
the two CVEs or migrate): "Move to Spring Boot 4"; relayed by the design session from the PO's chat the same day:
"Spring Boot 4'e geç (Önerilen)" (move to Spring Boot 4, the recommended option), with the instruction not to record a
baseline acceptance.

## Context
Pull request 12 (control plane and admin UI, slice 1) was built on Spring Boot 3.5.16, the neXus version at the time the
work started. The `security-scans` job (AGENTS.md section 10) blocked it on spring-webmvc 6.2.19: CVE-2026-47884
(XsltView) and CVE-2026-47890 (CRLF in SSE view-fragment rendering), both CRITICAL. Spring Framework 6.2.x has no
open-source fix; the fix is Spring Framework 7.0.9, which needs Spring Boot 4. The control plane uses neither component,
and neXus carries both CVEs under a time-boxed PO acceptance (review 2026-11-05) after moving to Spring Boot 4.0.8 on
2026-10-15. `security/baseline.yaml` in rwsafe has no acceptance.

## Decision
1. `rwsafe-control` and the modules that share its dependency platform (`persistence`, `worker`) move to Spring Boot 4.
   Not chosen: a time-boxed baseline acceptance of the two CVEs on Spring Boot 3.5.16.
2. The line is Spring Boot 4.1.x, at the newest release published at least two weeks before the change: 4.1.1
   (2026-08-20), which manages Spring Framework 7.0.9 and Spring Security 7.1.1. 4.1.2 (2026-10-22) is newer than two
   weeks and is not used yet.
3. The security floors above the Boot-managed versions stay: Tomcat 11.0.27 (the neXus floor, 2026-10-12), Jackson
   2.21.7 and the PostgreSQL JDBC driver 42.7.13.
4. HTTP JSON stays on Jackson 2 (`spring-boot-jackson2`, `spring.http.converters.preferred-json-mapper: jackson2`,
   `spring.jackson2.*`), as in neXus; `HttpJsonMapperTest` pins the converter and the contract's strictness.
5. `security/baseline.yaml` records no acceptance for CVE-2026-47884 or CVE-2026-47890; `security-scans` passes with
   them absent.

## Consequences
- Version difference from neXus, stated on purpose: rwsafe runs Spring Boot 4.1.1 where neXus runs 4.0.8 (both on Spring
  Framework 7.0.9 and Tomcat 11.0.27). ADR-011's shared tooling is unaffected (Gradle, lockfiles, verification
  metadata); a later neXus move to 4.1.x would bring the two back to one line.
- Changed by path: `java/gradle/libs.versions.toml`, `java/control/build.gradle.kts`,
  `java/control/src/main/resources/application.yaml`, `ControlApplication`, `InternalConnector`,
  `ApiExceptionHandler`, every `java/*/gradle.lockfile` that resolves the platform, `java/gradle/verification-metadata.xml`
  (regenerated from an empty Gradle home), `HttpJsonMapperTest`.
- Managed versions that move with Boot 4.1.1: Spring Security 7.1.1, HikariCP 7.0.2, JUnit 6.0.3, Flyway 12.4.0,
  jOOQ 3.21.7, UnboundID LDAP SDK 7.0.5.
- The Jackson 3 starter stays on the classpath unused, because the Maven-portability smoke build (ADR-011 §4) refuses
  dependency exclusions; neXus excludes it.
- No residual risk accepted.

## Open items
None.
