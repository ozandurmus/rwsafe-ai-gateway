# Ship pipeline plan: what is reused from neXus and how

**Status:** DRAFT for design freeze. Companion to ADR-011 (shared tooling) and `docs/operations/DEPLOY_AND_SHARED_HOST_RUNBOOK.md`.

## 1. Principle

One delivery engine, two products, zero shared state. neXus's engine (`standalone_orchestrate.py`, `hosta_deploy.sh`,
`module_deploy.py`, `release_snapshot.py`, `security_host.py`, `hosta_preview_e2e.py`, `hosta_e2e.sh`) is kept as the
engine; what it hard-codes today (`ui2` namespace, `~/nexus.git`, `~/run_build.sh`, `/tmp/nexus_build.log`,
`nexus-*` worktrees, `ui2/frontend`, module names) is extracted into a **per-repository delivery manifest**,
`.rwsafe-delivery.json` here and `.nexus-delivery.json` there. Until neXus adopts the manifest, rwsafe vendors a
parameterised copy under `tools/delivery/` with the manifest already applied; the diff against neXus is kept small and
listed in ADR-011 so the engine can be re-unified. Argon's audit of the hard-coded assumptions (council P1-3) is the
checklist.

## 2. The delivery manifest

`.rwsafe-delivery.json` at the repository root (committed; it carries names of this product's own objects, never a host
address or an account). Keys: `product`, `repo_slug`, `worktree_prefix`, `namespaces.{runtime,build,security}`,
`host.{bare_repo,checkout,build_script,build_log,release_snapshots,security_config,lock}` (all under the host account's
home: no `/tmp`, kickoff brief section 8), `images.{registry,repositories}`, `modules`, `frontend_dir`, `java_dir`,
`protected_windows_istanbul`, `db.{statefulset,database,app_role,migrate_role}`.

## 3. Shared-host build lock

Both products' build and deploy scripts take the same host-level lock (`flock` on the path both manifests name) before any
in-cluster build or rollout and release it when the rollout reaches an end state. The lock waits at most 45 minutes and
says whose build it is waiting for. Builds never start inside a protected window (neXus job windows 00/06/12/18 and the
02:00 backup hour, Europe/Istanbul) and never while the other product's deploy is in flight. The lock is added to neXus's
`hosta_deploy.sh` in the same prerequisite neXus PR as the ingress change (PLAT-F9); rwsafe runs no host build before it.

## 4. Registry garbage collection

The local registry holds hundreds of stale tags today (measured 2026-10-30: build-cache 366 tags, service 310, e2e 225).
Rule: keep every digest referenced by any Deployment, StatefulSet, Job template or release snapshot of either product
plus the last 10 tags per repository; delete the rest weekly with the registry's own garbage collector in a maintenance
window; both manifests name their repositories. The first run is a separate, PO-approved neXus change.

## 5. The rwsafe ship sequence

1. Lane: `feature/*` worktree under `~/Codo/rwsafe-*`; the worker commits; privacy gate and `git diff --check` run as
   pre-commit hooks (`tools/delivery/install_hooks.sh`, installed once per checkout by a human).
2. `ship --task|--branch`: rebase on `origin/main`; privacy gate on the shipped tree, never on `main`; unit, ArchUnit and
   frontend checks; PostgreSQL integration Job in `rwsafe-build` against the branch commit, whose output names the commit
   it tested; preview e2e in an isolated namespace copy (masked role, canary digests including Turkish identifiers); then
   PR, merge, push to the host bare repository.
3. Host build under the shared lock: release snapshot; kaniko build of the control-plane and data-plane images (one
   Containerfile, two stages: the data plane is a Netty jar without Spring MVC) and the e2e runner image; security gate Job
   (Semgrep, gitleaks, Trivy fs/config/image, SBOM, Jazzer regression corpus) on the new digests; image signing and
   provenance attestation; then rollout.
4. Rollout: `module_deploy.py` renders the committed manifests with the candidate digests (never image-only patches),
   diffs them server-side, applies after the drain. ICAP and gateway deployments are RollingUpdate `maxUnavailable: 0`
   with a preStop drain; the control plane may be Recreate.
5. Post-deploy: in-cluster e2e Job (admin UI as the masked role, leak probe); **ICAP e2e Job** (REQMOD/RESPMOD fixtures:
   204 fast path, tenant block, secret redaction, SSE sliding window, oversize-body verdict, parse-failure verdict); gateway
   smoke; coverage-metric sanity. Results are commented on the PR.
6. Nightly: full e2e, daily security scan, weekly DAST, weekly registry GC, rwsafe database and config in the platform
   backup set with their own retention.

## 6. Multi-agent reuse

`tools/review/consult_argon.py`, `tools/review/consult_fable.py` and `tools/review/argon_task.py` are the neXus scripts
with the output root (`docs/reviews/`), the worktree prefix (`rwsafe-`) and the standing worker rules taken from the
manifest. They send masked material only and never a prompt body (AGENTS.md 4.6, 4.7).
