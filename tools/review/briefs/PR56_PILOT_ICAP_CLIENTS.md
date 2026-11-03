REVIEW: second independent review of pull request 56 (AGENTS.md section 9, security-sensitive: the inline path's
ingress NetworkPolicy, the manifest checker, a host-side helper handling real addresses, a shared file module, the
firewall runbook block and its checker), branch `feature/pilot-icap-clients`
LENS: whether the ICAP pods admit TCP 1344 ONLY from the proxy addresses typed on the host (PO decision Q-48), with no
real address reaching the repository, a terminal, a log or an argument list, and whether the firewall step now replaces
its table atomically.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway; a public repository).
You start from a fresh context. Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this
repository. Do not edit, run shell, or widen the review. Your job: find any way the ICAP ingress becomes broader than
the typed /32 addresses (selectors, ports, except, ranges, IPv6, the removed ServiceLB policy, other pilot policies),
any way a value leaks (helper, render, shared module, temp files, symlinks, modes, messages), any bypassable refusal,
any regression of PR 54's directory rules after the refactor, and any error in the firewall block (atomic replace, y/n
loop, validation) or in verify_firewall's 1-to-8 rule. Return exactly: (1) a CONSENT table (area, verdict), (2) a
DISSENT table (finding id, file and line or symbol, what is wrong, severity P0/P1/P2, the concrete correction), (3)
QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation), (4) a one-line verdict MERGE / MERGE WITH CORRECTIONS
/ DO NOT MERGE, then (5) list every instruction you received, verbatim. Be concrete and short. Never quote or invent an
address, host name, account, serial or secret. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 5, 8, 9)
- docs/design/PO_DECISION_RECORD_2026_11_03_Q48_ICAP_INGRESS_FROM_PROXIES.md
- deploy/rwsafe/overlays/pilot/ (every file), deploy/rwsafe/overlays/k3s/03-icap-service-lb.yaml and 04-networkpolicies-k3s.yaml
- tools/deploy/manifest_check.py and tools/deploy/test_manifest_check.py (the ICAP clients and directory rules)
- tools/pilot/host_value_file.py, icap_clients.py, icap_clients.sh, directory_range.py, directory_range.sh, render.py,
  test_render.py, verify_firewall.sh and its test
- .gitignore
- docs/operations/PILOT_RUNBOOK.md (steps 11, 11.5, 14.5)
