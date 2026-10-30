# ADR-011: Shared tooling with neXus and the corporate build standard

Status: PROPOSED
Date: 2026-10-30
Answers: brief section 7 (Multi-agent work, Stack), section 10.4 (Shared delivery tooling); council Argon P1-1, P1-3;
`docs/reference/CORPORATE_TECHNOLOGY_STACK.md` rows Build, Persistence, Source

## Context

neXus's delivery engine is mature (ship orchestrator with privacy gate on the shipped tree, preview e2e, security gate,
release snapshots, module drain, in-cluster e2e, masked-role canary) and the brief requires reusing it. Argon's audit
shows it hard-codes neXus names (`ui2`, `~/nexus.git`, `~/run_build.sh`, `/tmp/nexus_build.log`, `nexus-*` worktrees,
`ui2/frontend`, module names, Postgres pod and roles). The PO asked whether rwsafe vendors a copy or a shared package is
extracted. The corporate standard is Maven, Bitbucket, Jenkins/ArgoCD, Artifactory; the brief prescribes Gradle with
lockfiles and verification metadata and asks that deviations be justified.

## Decision

1. **Per-repository delivery manifest, engine shared by parameterisation.** `.rwsafe-delivery.json` (committed) carries
   every name the engine needs; `tools/delivery/*` in rwsafe starts as a **vendored, parameterised copy** of the neXus
   scripts that read the manifest instead of constants. The diff against neXus is kept minimal and listed here
   (`tools/delivery/VENDORED_FROM_NEXUS.md` records the source commit and each changed line). When the PO decides, the
   same change is proposed to neXus as its own PR (`.nexus-delivery.json`), after which both repositories can consume one
   `rwsafe-platform` tooling package. Blind copying is forbidden (AGENTS.md 13).
2. **Shared-host build lock and protected windows** (`SHIP_PIPELINE_PLAN.md` §3) are part of the manifest contract and
   must be adopted by both products before rwsafe's first host build: the `flock` line goes into neXus's `hosta_deploy.sh`
   in the **same prerequisite neXus PR** as the ingress change (ADR-003; PLAT-F9), so a one-sided lock never exists.
   Until that PR is merged rwsafe runs no host build at all.
3. **Registry GC** (`SHIP_PIPELINE_PLAN.md` §4) is proposed as a neXus change and is not run by rwsafe tooling until
   accepted.
4. **Build tool: Gradle**, as the brief prescribes: lockfiles and `verification-metadata.xml` give dependency pinning and
   checksum verification that the SSDF/SLSA target needs and that the shared Containerfile, ship gate and Trivy lockfile
   scan already consume; Maven has no native lockfile and would fork the engine. This is a recorded **deviation from the
   corporate standard**; mitigation: the project keeps a Maven-portability check (no Gradle-only plugin logic in the
   build, standard layout, a generated `pom.xml` smoke build in CI) so a later move to the corporate S2I/Jenkins pipeline
   is mechanical. Decision referred to the PO: OPEN_QUESTIONS Q-15.
5. **Persistence: jOOQ + Flyway**, as the brief prescribes (deviation from Spring Data JDBC, justified by the trigger-based
   audit and typed SQL; referred to the PO in Q-16).
6. **Source: GitHub** as the PO decided; the repository layout and branch names follow the ARK conventions once the PO
   supplies them (Q-17); a Bitbucket mirror is possible later without changing the engine (the manifest's `repo_slug`
   and remote names are the only coupling).
7. **Review and worker scripts** (`tools/review/consult_argon.py`, `consult_fable.py`, `argon_task.py`) are rwsafe copies
   of the neXus scripts with the output root and worktree prefix from the manifest, plus a hard rule that the material
   they send is masked and contains no prompt body (AGENTS.md 4.6, 4.7).

## Alternatives considered

- Extract `rwsafe-platform` now: changes neXus's live pipeline in the middle of its failover pilot; rejected for this phase.
- Vendor without parameterisation: the collisions Argon listed (`/tmp` log, bare repo, build script, worktree prefix);
  rejected.
- Maven from day one: forks the engine, loses lockfile verification; rejected pending the PO's answer.

## Consequences

- The first rwsafe host build needs the neXus-side lock adoption or the read-only wait; recorded in ROADMAP MVP preconditions.
- `tools/delivery/VENDORED_FROM_NEXUS.md` is a maintenance obligation: every neXus engine fix is ported or declined explicitly.

## Evidence and UNVERIFIED facts

- Read: `standalone_orchestrate.py`, `hosta_deploy.sh`, `module_deploy.py`, `run_build.sh`, `argon_task.py`,
  `consult_argon.py` in the neXus checkout (2026-10-30).
- UNVERIFIED: the corporate S2I builder's Gradle support for the installed OpenShift version.

## Open questions

Q-15 (Gradle vs Maven), Q-16 (jOOQ vs Spring Data JDBC), Q-17 (ARK naming conventions).
