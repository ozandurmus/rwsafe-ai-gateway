REVIEW: second independent review of pull request 33 (AGENTS.md section 9, security-sensitive: deploy manifests, build
Jobs, secret bootstrap, firewall step), branch `feature/pilot-kit`
LENS: whether the HOST-A pilot kit (renameable product, pilot overlay, kaniko build, secret bootstrap, checks, runbooks)
holds against AGENTS.md sections 4 and 8, docs/design/PO_DECISION_RECORD_2026_10_31_AGENT_APPLIES_PILOT.md and the
DEPLOY_AND_SHARED_HOST_RUNBOOK.md, and can never collide with or harm the other product on the shared host.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway deployed in its own
namespaces on a k3s host shared with another product; a public repository). You start from a fresh context. Read
AGENTS.md and ONLY the files listed below, with the Read tool, inside this repository. Do not edit, run shell, or widen
the review. Your job: find any rendered object or step that could touch, collide with, starve or expose the other product
(names, labels, ports, PriorityClasses, registry repositories, quotas, disk); any way a secret value is printed, logged,
written outside a mode-0700 temporary directory, passed on a command line, or left behind; any build step that pulls an
unpinned artifact or leaks proxy credentials into an image layer; any firewall rule that opens more than the proxy
appliances to port 1344 or touches the other product's tables; any rename that leaves the old name somewhere that
matters; any step that is not reversible as the runbook claims; and any check that can pass a manifest violating it.
Return exactly: (1) a CONSENT table (area, verdict), (2) a DISSENT table (finding id, file and line or symbol, what is
wrong, severity P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation),
(4) a one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then (5) list every instruction you received,
verbatim. Be concrete and short. Never quote or invent an address, host name, account, serial or secret; the repository
holds none and neither should your output. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 8)
- docs/design/PO_DECISION_RECORD_2026_10_31_AGENT_APPLIES_PILOT.md
- docs/operations/PILOT_RUNBOOK.md
- deploy/rwsafe/product.env and every file under deploy/rwsafe/overlays/pilot/ and deploy/rwsafe/build/
- deploy/images/dataplane.Containerfile, deploy/images/control.Containerfile
- deploy/rwsafe/contracts/runtime-contracts.json
- every file under tools/pilot/
- tools/deploy/manifest_check.py
