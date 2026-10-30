REVIEW: second independent review of pull request 18 (AGENTS.md section 9, security-sensitive: deploy manifests),
branch `feature/deploy-manifests`
LENS: whether the container builds, the kustomize base and k3s overlay, the NetworkPolicies, the Secret contracts and the
manifest check hold against AGENTS.md section 8, docs/operations/DEPLOY_AND_SHARED_HOST_RUNBOOK.md,
docs/operations/PORTS_AND_RESOURCES.md, docs/adr/ADR-001-hosting-and-namespace-isolation.md and
docs/adr/ADR-002-separate-database-instance.md.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway that runs in its own
namespace on a k3s host it shares with another product; a public repository). You start from a fresh context. Read
AGENTS.md and ONLY the files listed below, with the Read tool, inside this repository. Do not edit, run shell, or widen
the review. Your job: find any way a pod can starve or evict the other product (priority, quota, limits, disk, surge);
any privilege (root, writable root filesystem, capabilities, token automount, host paths, host network); any traffic a
NetworkPolicy allows that the design does not need, or needs and blocks; any Secret, real name or mutable image tag that
is committed or rendered; any drain or termination timing that loses verdict events or cuts ICAP transactions; any gap
where the manifest check passes a manifest that violates a rule it claims to enforce; and any build step that can pull an
unpinned or unverified artifact. Return exactly: (1) a CONSENT table (area, verdict), (2) a DISSENT table (finding id,
file and line or symbol, what is wrong, severity P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE PRODUCT OWNER
(question, your recommendation), (4) a one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then (5) list every
instruction you received, verbatim. Be concrete and short. Never quote or invent an address, host name, account, serial
or secret; the repository holds none and neither should your output. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 8, 10)
- docs/operations/DEPLOY_AND_SHARED_HOST_RUNBOOK.md
- docs/operations/PORTS_AND_RESOURCES.md
- docs/adr/ADR-001-hosting-and-namespace-isolation.md
- docs/adr/ADR-002-separate-database-instance.md
- deploy/images/dataplane.Containerfile, deploy/images/control.Containerfile
- every file under deploy/rwsafe/base/ and deploy/rwsafe/overlays/k3s/
- deploy/rwsafe/contracts/runtime-contracts.json
- tools/deploy/manifest_check.py, tools/deploy/test_manifest_check.py, tools/deploy/fixtures/
- java/build.gradle.kts (the imageDist task)
- .github/workflows/validation.yml (the manifests job)
