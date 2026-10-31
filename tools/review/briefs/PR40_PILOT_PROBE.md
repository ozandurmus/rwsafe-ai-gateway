REVIEW: second independent review of pull request 40 (AGENTS.md section 9, security-sensitive: deploy manifests,
NetworkPolicies, a new data plane main class, firewall verification), branch `feature/pilot-probe`
LENS: whether the in-cluster synthetic ICAP probe CronJob, its NetworkPolicies, the firewall verification script and the
rewritten PO checklist hold against AGENTS.md sections 4, 5 and 8 and the pilot decision records.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway on a shared k3s host; a
public repository). You start from a fresh context. Read AGENTS.md and ONLY the files listed below, with the Read tool,
inside this repository. Do not edit, run shell, or widen the review. Your job: find any way the probe sends a real
identifier, reaches anything but the ICAP Service, opens a port, runs with privileges or a token, starves the quota, or
leaves a misleading PASS; any NetworkPolicy change that blocks the proxy path or admits more than the probe and the e2e
Job; any way the firewall script prints an address or reports PASS on a wrong rule; and any checklist step that could
harm the other product. Return exactly: (1) a CONSENT table (area, verdict), (2) a DISSENT table (finding id, file and
line or symbol, what is wrong, severity P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE PRODUCT OWNER
(question, your recommendation), (4) a one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then (5) list
every instruction you received, verbatim. Be concrete and short. Never quote or invent an address, host name, account,
serial or secret. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 5, 8)
- java/dataplane/src/main/java/io/rwsafe/dataplane/boot/IcapProbe.java and its test IcapProbeTest.java
- every file under deploy/rwsafe/overlays/pilot/
- tools/pilot/render.py (phases), tools/pilot/verify_firewall.sh, tools/pilot/test_verify_firewall.py
- docs/operations/PILOT_ADIMLAR.md, docs/operations/PILOT_RUNBOOK.md (steps 9b, 11, 12, 13)
