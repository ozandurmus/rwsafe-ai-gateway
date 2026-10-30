REVIEW: second independent review of pull request 27 (AGENTS.md section 9, security-sensitive: deploy manifests,
NetworkPolicies, Secrets contract, a new metrics listener), branch `feature/deploy-wiring-2`
LENS: whether the wiring of SIEM export, redacted capture, end-user notice values, group-claim encoding and the control
metrics listener into deploy/rwsafe holds against AGENTS.md sections 4 and 8, ADR-001, ADR-009,
docs/operations/PORTS_AND_RESOURCES.md and docs/operations/DEPLOY_AND_SHARED_HOST_RUNBOOK.md.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway that runs in its own
namespace on a k3s host shared with another product; a public repository). You start from a fresh context. Read
AGENTS.md and ONLY the files listed below, with the Read tool, inside this repository. Do not edit, run shell, or widen
the review. Your job: find any committed secret, estate value or real address; any Secret or ConfigMap key used but not
in the contract; any NetworkPolicy that allows more than the feature needs (egress to any address, ingress to the
metrics or drain listeners from more than the scraper and kubelet); any storage or quota choice that can fill the shared
host's disk or break the headroom rule; any feature that starts on by default; any new listener that serves more than
metrics or is reachable from the wrong port; and any manifest-check rule that a manifest can pass while violating it.
Return exactly: (1) a CONSENT table (area, verdict), (2) a DISSENT table (finding id, file and line or symbol, what is
wrong, severity P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation),
(4) a one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then (5) list every instruction you received,
verbatim. Be concrete and short. Never quote or invent an address, host name, account, serial or secret; the repository
holds none and neither should your output. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 8)
- docs/adr/ADR-001-hosting-and-namespace-isolation.md, docs/adr/ADR-009-data-model-retention-and-privacy.md
- docs/operations/PORTS_AND_RESOURCES.md, docs/operations/DEPLOY_AND_SHARED_HOST_RUNBOOK.md (section 7)
- every file under deploy/rwsafe/base/ and deploy/rwsafe/overlays/k3s/
- deploy/rwsafe/contracts/runtime-contracts.json
- tools/deploy/manifest_check.py, tools/deploy/test_manifest_check.py
- every file under java/control/src/main/java/ that names "Metrics" or "Connector", and the control security configuration
