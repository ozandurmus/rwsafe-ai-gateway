# Corporate technology stack: reference and alignment matrix

**Status:** REFERENCE, supplied by the Product Owner on 2026-10-30 (chat): "Bir teknoloji stack var, buraya olabildiğince
uyumlu olmalıyız geliştirme yaparken." The table in section 1 is the PO's text, unaltered except for layout. Section 2 is
the architect's alignment reading; every row that conflicts with the kickoff brief or with a neXus-parity requirement is
carried into `docs/product/OPEN_QUESTIONS.md` and is **not decided here**.

Rule derived from this document: **where the corporate standard and neXus parity agree, rwsafe follows both; where they
differ, rwsafe follows neXus parity for the HOST-A stage and keeps a documented, tested portability path to the corporate
standard, unless the PO decides otherwise in OPEN_QUESTIONS.** The OpenShift portability rules (`PORT-1`, `PORT-3`) that
neXus already follows are the mechanism that keeps that path open.

## 1. The corporate stack as supplied

| Layer | Item | Corporate standard |
|---|---|---|
| Channel | Language | TypeScript |
| Channel | Core frameworks | React, Axios |
| Channel | Test | Vitest |
| Channel | Build | Vite |
| Channel | Protocol | HTTP/1 |
| Channel | Monitoring | Instana |
| aPaaS | Language | Java |
| aPaaS | Core frameworks | Spring, Spring Boot, Spring Cloud Data Flow, MapStruct |
| aPaaS | Test | JUnit, ArchUnit |
| aPaaS | Build | Maven (`mvn`) |
| aPaaS | Protocol | HTTP/1, HTTP/2 |
| aPaaS | Monitoring | Instana |
| DaaS | Language | Java |
| DaaS | Core frameworks | Spring Boot, Spring Data JDBC |
| DaaS | Database | Oracle or PostgreSQL |
| DaaS | Messaging | IBM MQ, RabbitMQ, Kafka |
| DaaS | Protocols | AMQP, MQTT over WebSocket |
| DaaS | Monitoring | Instana |
| DevOps | Source | Bitbucket |
| DevOps | Branch management | Same as ARK |
| DevOps | Project naming | Same as ARK |
| DevOps | Repository naming | Same as ARK, with labelling |
| DevOps | Build | S2I with Jenkins pipeline |
| DevOps | Deployment | Jenkins, ArgoCD (A) |
| DevOps | Deployment namespace | Same as ARK |
| DevOps | Artifacts | Artifactory |
| IaaS | Platform | OpenShift, Nginx |
| Logging | | ELK (ARK logging console log), Splunk |
| Traces | | Instana |
| Metrics | | Instana |
| Security | Framework | Spring Security |
| Security | Login | SAML |
| Security | Secret management | Legacy CyberArk |
| Security | Posture | CNAPP (Cloud-Native Application Protection Platform) |
| Security | Detection | XDR |
| iPaaS | | No gateway |

"ARK" is the name of an internal platform programme whose naming and branching conventions the PO referenced; the
conventions themselves were not supplied and are **UNVERIFIED** here (OPEN_QUESTIONS).

## 2. Alignment matrix

Legend: **ALIGNED** = same choice; **COMPATIBLE** = different tool, same contract, no decision needed; **DEVIATION** = the
brief or neXus parity requires something else, justified below and recorded; **OPEN** = PO decision needed.

| Area | Corporate | Brief / neXus | rwsafe position | Status |
|---|---|---|---|---|
| Frontend language, build, test | TypeScript, Vite, Vitest | React + TypeScript + MUI, Vite, Vitest, Playwright | Same. | ALIGNED |
| Frontend HTTP client | Axios | neXus uses the browser `fetch` API behind one API client module | One API client module; Axios is acceptable if the corporate interceptors (Instana, SAML session) require it. Decide at the first frontend commit, not now. | OPEN (minor) |
| Frontend protocol | HTTP/1 | HTTP/1.1 through the ingress | Same for the admin UI. Streaming inspection paths (SSE, WebSocket) are data-plane, not channel. | ALIGNED |
| Backend language, framework | Java, Spring Boot | Java 21, Spring Boot | Same. Spring Cloud Data Flow is not used (no stream-processing cluster on HOST-A); MapStruct optional for DTO mapping. | ALIGNED |
| Backend test | JUnit, ArchUnit | JUnit 5, ArchUnit architecture tests | Same; ArchUnit fences are a first-commit requirement (inline path has no JDBC, no backtracking regex). | ALIGNED |
| Backend build | Maven | Gradle with lockfiles and `verification-metadata.xml` (brief section 7: "justify any deviation") | Conflict. Gradle gives dependency lockfiles and checksum verification that the SSDF/SLSA target needs and that neXus's ship tooling, Containerfile and security gate already consume; Maven has no native lockfile. Red Hat's OpenJDK S2I builder supports Gradle projects (UNVERIFIED for the corporate builder image version). Recommendation: Gradle for the HOST-A stage, with a Maven build-compatibility check in the roadmap before the corporate platform stage. | OPEN |
| Backend protocol | HTTP/1, HTTP/2 | HTTP/1.1 admin API; ICAP (RFC 3507) and upstream HTTPS for the data plane | ICAP is its own protocol; HTTP/2 is accepted on the LLM gateway ingress. | COMPATIBLE |
| Persistence framework | Spring Data JDBC | jOOQ, Flyway | jOOQ is kept for neXus parity: typed SQL, the per-transaction `set_config` audit actor pattern and trigger-enforced audit need explicit SQL control. Flyway is the only migration authority in both. | DEVIATION (recorded; PO may overrule) |
| Database | Oracle or PostgreSQL | PostgreSQL 16 | PostgreSQL. No Oracle path is designed; the schema avoids PostgreSQL-only features where cheap, but triggers and `pg_advisory_lock` are used. | ALIGNED |
| Messaging | IBM MQ, RabbitMQ, Kafka | None in neXus | The capture and audit pipeline is an in-process bounded queue with explicit overflow policy (council ARCH-1); no broker on HOST-A (resource budget). The queue has a port interface so a Kafka or RabbitMQ sink can be added on the corporate platform without changing the data plane. | COMPATIBLE |
| Source hosting | Bitbucket | GitHub `ozandurmus/rwsafe-ai-gateway` (PO decision, brief section 2) | GitHub for this phase as decided. Branch, project and repository naming "same as ARK" cannot be applied without the ARK convention document. | OPEN |
| Build pipeline | S2I + Jenkins | In-cluster kaniko build Job, local registry, digest-pinned images, ship orchestrator | HOST-A stage uses the neXus engine (parameterised per repository). The Containerfile stays S2I-compatible in spirit: one build stage, no host tooling, no network at test time. A Jenkinsfile is not written in this phase. | COMPATIBLE |
| Deployment | Jenkins, ArgoCD | `hosta_deploy.sh` / `module_deploy.py`, manifests applied from the repository | `deploy/rwsafe/` is laid out as kustomize base + overlays (`k3s`, `openshift`) so ArgoCD can consume it unchanged later. | COMPATIBLE |
| Artifacts | Artifactory | Local in-cluster registry on HOST-A | Images carry SBOM (CycloneDX) and provenance so they can be promoted to Artifactory later. | COMPATIBLE |
| Platform | OpenShift, Nginx | k3s with Traefik on HOST-A; OpenShift portability rules PORT-1/PORT-3 | Workload manifests identical on both; Ingress/Route and quota objects live in overlays; no Traefik-only or Nginx-only annotations (council ARCH-3). | ALIGNED |
| Logging | ELK (ARK console log), Splunk | syslog/SIEM out | Structured JSON console logs (one line per event, no bodies, no raw identities) for ELK; SIEM export in CEF, LEEF and Splunk HEC formats (brief 10.4). | ALIGNED |
| Traces and metrics | Instana | Not specified beyond health | OpenTelemetry traces and Prometheus metrics; Instana ingests OpenTelemetry (UNVERIFIED for the installed Instana version). Labels never carry prompt, user or tenant strings (brief 10.4). | COMPATIBLE |
| Security framework | Spring Security | Spring Security gate chain in neXus | Same. | ALIGNED |
| Login | SAML | LDAP/AD with group-to-role binding plus local break-glass (brief section 5F) | Both: the identity layer binds AD groups to roles; the authentication front can be LDAP bind (HOST-A stage) or SAML 2.0 service provider (corporate stage). Which one is the MVP default is a PO decision. | OPEN |
| Secret management | Legacy CyberArk | Kubernetes Secrets, file-mounted, encrypted at rest, never committed | Secrets reach the process as mounted files only (neXus C1 §6 rule). That contract lets a CyberArk provider (Conjur or an external-secrets operator) feed the same files later; the integration method is UNVERIFIED. | COMPATIBLE |
| CNAPP, XDR | Present | Trivy, Semgrep, gitleaks, ZAP in the ship pipeline | Scanner output is exported in standard formats (SARIF, CycloneDX) for the CNAPP. The off-net agent design (ADR-006) must coexist with the XDR endpoint agent; the XDR product is not named here. | OPEN (which XDR) |
| iPaaS | No gateway | LLM API gateway is rwsafe's own component | Nothing in front of the LLM gateway is assumed. | ALIGNED |

## 3. What this changes in the deliverables

- `docs/adr/ADR-011` (shared tooling with neXus) records the Gradle decision as a deviation from the corporate standard.
- `docs/architecture/ARCHITECTURE.md` shows the authentication front (LDAP or SAML) as a replaceable component.
- `deploy/rwsafe/` is kustomize base + overlays from the first manifest.
- `docs/product/OPEN_QUESTIONS.md` carries: Maven vs Gradle, SAML vs LDAP as MVP login, the ARK naming document, the XDR
  product, Axios.
