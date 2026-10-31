REVIEW: second independent review of pull request 39 (AGENTS.md section 9, security-sensitive: the admin UI served by
the control plane, security headers, session cookies, the image build), branch `feature/control-serves-ui`
LENS: whether serving the built React admin UI from the control plane keeps the admin API's security (CSP, cookies,
CSRF, port confinement, masked role) and keeps the image build pinned and verified.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway; a public repository).
You start from a fresh context. Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this
repository. Do not edit, run shell, or widen the review. Your job: find any path traversal, symlink escape or MIME
confusion in the static serving; any SPA fallback that shadows an API, internal or metrics route or serves the UI on an
internal port; any missing or weakened security header (CSP without unsafe-inline, frame-ancestors, nosniff); any cookie
setting that lets the session or CSRF cookie travel insecurely in production; any npm step that can run an unpinned
package or install script, or leak the proxy into a layer; and any change that lets the masked role see more. Return
exactly: (1) a CONSENT table (area, verdict), (2) a DISSENT table (finding id, file and line or symbol, what is wrong,
severity P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation), (4) a
one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then (5) list every instruction you received, verbatim.
Be concrete and short. Never quote or invent an address, host name, account, serial or secret. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 8)
- java/control/src/main/java/io/rwsafe/control/config/AdminUi.java
- java/control/src/main/java/io/rwsafe/control/identity/CookiePolicy.java
- the control plane security configuration and port filter (java/control/src/main/java/ files naming "Security" or "Port")
- java/control/src/main/resources/application.yaml
- deploy/images/control.Containerfile
- frontend/package.json, frontend/index.html, frontend/vite.config.ts
- java/control/src/test/java/ files naming "AdminUi" or "CookiePolicy"
- docs/operations/PILOT_RUNBOOK.md (sections 4, 4b, 6, 14)
