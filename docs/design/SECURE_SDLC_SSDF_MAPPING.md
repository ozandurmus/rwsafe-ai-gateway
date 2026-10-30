# Secure SDLC controls mapped to NIST SSDF (SP 800-218), from day one

**Status:** DRAFT for design freeze (becomes the implementation phase's acceptance checklist). Mirrors neXus
`docs/design/SECURE_SDLC_SSDF_MAPPING.md` and closes, at design time, the gaps that document lists as still open for neXus
(threat model, security requirements catalogue mapped to tests, vulnerability SLA, root-cause log, preview-e2e skip rule,
second independent review, signed images and provenance). Nothing here claims production readiness; every row names the
artefact that will prove it.

## 1. Practice mapping

| SSDF practice | rwsafe control | Artefact | Status at design freeze |
|---|---|---|---|
| PO.1 Define security requirements | Security requirements catalogue, each with its proving test; privacy requirements from brief 4A | `docs/security/SECURITY_REQUIREMENTS.md` | written |
| PO.2 Roles and responsibilities | Role files, second-reviewer rule, privacy officer and DPO in the product RBAC | `roles/`, `AGENTS.md` 9, `docs/security/RAW_CONTENT_ACCESS.md` | written |
| PO.3 Supporting toolchains | In-cluster kaniko build, local digest-pinned registry, isolated scanner namespace, offline rule packs, Gradle lockfiles + verification metadata | `deploy/rwsafe/`, `.rwsafe-delivery.json`, `docs/design/SHIP_PIPELINE_PLAN.md` | planned, reuses neXus engine |
| PO.4 Security-check criteria | Exact, owned, dated acceptance baseline; fail-closed summary; logged emergency bypass with reason | `security/baseline.yaml`, `.gitleaks.toml` | written (empty baseline) |
| PO.5 Secure environments | Separate namespace, PSA `restricted`, default-deny NetworkPolicy, lower PriorityClass, no hostPath, read-only root, encrypted Secrets | ADR-001, `deploy/rwsafe/base` | ADR written |
| PS.1 Protect code | GitHub PRs only, protected `main`, pre-receive privacy hook on HOST-A mirror, worker lanes without push | `AGENTS.md` 9, 13 | written |
| PS.2 Verify release integrity | Digest-pinned images, SBOM per image, **signed images with provenance attestation (SLSA level 2 target)** using an in-cluster signing key held as a Secret | `docs/design/SHIP_PIPELINE_PLAN.md` §5 | planned; signing tool choice OPEN (cosign recommended, UNVERIFIED availability through the corporate proxy) |
| PS.3 Archive and protect releases | Release snapshot per deploy (neXus `release_snapshot.py`), reports kept 90 days, SBOMs kept with the snapshot | `docs/operations/DEPLOY_AND_SHARED_HOST_RUNBOOK.md` | planned |
| PW.1 Design to meet requirements | Architecture, ADRs, threat model, policy registry, data-plane law | `docs/architecture/`, `docs/adr/`, `AGENTS.md` 5, 6 | written |
| PW.2 Review design | Security council at design freeze through authorised scripts; every P0 answered by ID | `docs/reviews/` | pending the council run |
| PW.4 Reuse well-secured components | Dependency verification metadata, Trivy on lockfiles, allowlisted base images, model and rule packs signed and safetensors-only | ADR-008, `docs/design/SHIP_PIPELINE_PLAN.md` | planned |
| PW.5 Secure coding | ArchUnit fences (no JDBC, no backtracking regex, no blocking I/O on the inline path; no body in logs), Semgrep packs, RE2/J only | `docs/security/SECURITY_REQUIREMENTS.md` SR-DP-* | written as requirements |
| PW.6 Compiler and build security | Reproducible Gradle build in the pinned JDK image, no network at test time, `--no-daemon`, locked dependencies | Containerfile (implementation phase) | planned |
| PW.7 Review human-readable code | PR review; second independent review for security-sensitive paths; Semgrep Java/TypeScript/OWASP/secrets; gitleaks tree and history | `AGENTS.md` 9, 10 | written |
| PW.8 Test executable code | Unit, ArchUnit, Vitest, Playwright masked-role leak probe, PostgreSQL integration Job on the branch, **Jazzer fuzzing of the ICAP and HTTP parsers in CI**, replay fixtures per platform, protocol-drift tests, production canary prompts, weekly ZAP | `docs/security/SECURITY_REQUIREMENTS.md`, `docs/design/SHIP_PIPELINE_PLAN.md` | written as requirements |
| PW.9 Secure defaults | Fail-closed classes, monitor-only before enforce, masked role default-deny, capture off without notice acceptance | ADR-010, `docs/security/MASKING_AND_PRIVACY.md` | written |
| RV.1 Identify vulnerabilities | Daily scans, weekly DAST, coverage metric (SEC-6), pre-pilot independent penetration test (ICAP fuzzing, agent tampering) | `docs/security/PENETRATION_TEST_PLAN.md` | written |
| RV.2 Assess, prioritise, remediate | **Vulnerability SLA** (section 2); new unaccepted HIGH/CRITICAL stops rollout; daily "fix available / review due" review | section 2, `security/README.md` | written |
| RV.3 Analyse root causes | **Root-cause log** (section 3) with one entry per security defect or bypass found | `docs/security/ROOT_CAUSE_LOG.md` | file created, empty |

## 2. Vulnerability response SLA (closes the neXus gap)

| Severity (CVSS v3.1 base, or scanner severity) | Fix or accepted mitigation within | Where it may run meanwhile |
|---|---|---|
| CRITICAL, reachable from the data plane or admin UI | 7 days | nowhere new: rollout blocked |
| CRITICAL, not reachable (build-only, no fix available) | time-boxed acceptance, max 90 days, daily review | current release only |
| HIGH | 30 days | rollout blocked for new findings |
| MEDIUM | 90 days | tracked |
| LOW | next quarterly review | tracked |

Base images are refreshed at least every 14 days; a CVE with no fix is accepted for a time box, never silently. Rules
packs and ML models follow the same table under their own tool rows (ADR-008 supply chain).

## 3. Root-cause log

`docs/security/ROOT_CAUSE_LOG.md`: one entry per security defect, bypass or privacy leak (found by a test, a scan, a
reviewer, a canary or a user), with the failing control, the fix, the regression test added and the design rule changed.
A bypass-catalogue entry that fails in production becomes a log entry the same day.

## 4. When preview e2e may be skipped (rule, not habit)

`standalone_orchestrate.py ship --no-preview-e2e <reason>` is allowed only when all hold: the diff touches no frontend,
no manifest, no inline-path module and no migration; the reason is one line, recorded in the PR; the post-deploy e2e Job
and the leak probe still run. Anything else ships with preview e2e.

## 5. Second independent review

A PR that touches the inline path, masking, raw-content access, the policy registry, RBAC, deploy manifests, the privacy
gate or the security pipeline needs a second reviewer who did not write it: another human, or an external reviewer run
through `tools/review/` with the diff. The PR records who.

## 6. Signed images and provenance (SLSA level 2 target)

Every production image is built in the cluster from a tagged commit, pushed by digest, signed with a key held in a
Kubernetes Secret in the build namespace, and accompanied by a provenance attestation (builder, source commit, materials)
and a CycloneDX SBOM. The deploy verifies the signature and the attestation's source commit before rolling out. Tool
choice and the corporate proxy path are UNVERIFIED (OPEN_QUESTIONS).
