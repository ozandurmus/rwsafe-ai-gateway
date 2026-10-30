# Vendored delivery engine: provenance and diff log

ADR-011 §1: rwsafe starts with a parameterised copy of the neXus delivery engine. This file records the neXus source
commit each script was taken from and every line changed, so the engine can be re-unified later.

Status at design freeze: **nothing vendored yet**; the first implementation movement copies, parameterises and records:

| Script | neXus source | Parameters taken from `.rwsafe-delivery.json` |
|---|---|---|
| `standalone_orchestrate.py` | `tools/delivery/standalone_orchestrate.py` | worktree prefix, frontend/java dirs, module names, namespace, host paths, review output root |
| `hosta_deploy.sh` | `tools/delivery/hosta_deploy.sh` | bare repo, build script, build log, namespaces, targets, health-check host |
| `module_deploy.py` | `tools/delivery/module_deploy.py` | namespace, db pod/roles, manifests map, drain tables |
| `release_snapshot.py` | `tools/delivery/release_snapshot.py` | snapshot root, namespace |
| `hosta_preview_e2e.py` / `.sh` | `tools/e2e/` | namespace, canary secret, e2e image |
| `security_host.py` et al. | `tools/security/` | security namespace, config path |
| `run_build.sh` | `deploy/ui2-image-build/run_build.sh` | everything above plus the shared build lock |

Rule: a neXus engine fix is ported here or declined explicitly, with a row in this file.
