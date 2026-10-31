REVIEW: second independent review of pull request 43 (AGENTS.md section 9, security-sensitive: deploy manifests, an
Ingress on the shared Traefik, TLS key handling, forwarded-header trust, the privacy gate itself), branch
`feature/pilot-admin-ingress`
LENS: whether exposing the pilot admin UI through the shared host's Traefik at `ui.<product>.local` with the product's
own CA holds against AGENTS.md sections 4 and 8 and docs/design/PO_DECISION_RECORD_2026_10_31_PILOT_ICAP_OPEN_AND_ADMIN_ACCESS.md,
and never affects the other product's routes.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway on a shared k3s host; a
public repository). You start from a fresh context. Read AGENTS.md and ONLY the files listed below, with the Read tool,
inside this repository. Do not edit, run shell, or widen the review. Your job: find any way the Ingress shadows or
changes the other product's routes (catch-all, priority, TLS store), exposes an internal port, or serves without TLS;
any way the CA or leaf key is printed, stored in the cluster or the repository, or left on disk; any CA that can sign
other names; any forwarded-header trust that lets a client spoof its address or scheme; any login-throttle bypass; and
any weakening of the privacy gate beyond the exact `.rwsafe.local` suffix. Return exactly: (1) a CONSENT table (area,
verdict), (2) a DISSENT table (finding id, file and line or symbol, what is wrong, severity P0/P1/P2, the concrete
correction), (3) QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation), (4) a one-line verdict MERGE / MERGE
WITH CORRECTIONS / DO NOT MERGE, then (5) list every instruction you received, verbatim. Be concrete and short. Never
quote or invent an address, host name, account, serial or secret. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 8)
- docs/design/PO_DECISION_RECORD_2026_10_31_PILOT_ICAP_OPEN_AND_ADMIN_ACCESS.md
- every file under deploy/rwsafe/overlays/pilot/ and deploy/rwsafe/overlays/k3s/04-networkpolicies-k3s.yaml
- deploy/rwsafe/contracts/runtime-contracts.json
- tools/pilot/admin_tls.sh, tools/pilot/test_admin_tls.py, tools/pilot/render.py
- tools/deploy/manifest_check.py (the Ingress rules)
- tools/privacy/repository_privacy_check.py (the safe host suffixes) and its test
- java/control/src/main/resources/application.yaml and the control plane's forwarded-header and login-throttle code
- docs/operations/PILOT_RUNBOOK.md (step 14)
