REVIEW: second independent review of pull request 28 (AGENTS.md section 9, security-sensitive: raw-content access UI,
masked views, RBAC in the UI), branch `feature/admin-ui-slice3`
LENS: whether the captured-content reader, the health cards and the notice screen hold against AGENTS.md section 4,
ADR-009 section 5 (reader roles, reason and case id), and the server contracts they call.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway; its React admin UI lets
authorised roles open redacted captured prompt content with a reason and a case id; a public repository). You start from
a fresh context. Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this repository. Do not edit,
run shell, or widen the review. Your job: find any way the UI renders captured text, server details or notice sections
as HTML or lets them inject markup or bidi tricks; any path where a masked session, a viewer or a dual-role masked session
can reach the reader or see content; any reason code or case id sent that the server would not accept, or a DSAR read
offered to the wrong role; any content or pseudonym kept in browser storage, URL, logs or error reports; any server
refusal hidden behind a generic message; and any brittle parsing that can show a wrong count as fact. Return exactly: (1)
a CONSENT table (area, verdict), (2) a DISSENT table (finding id, file and line or symbol, what is wrong, severity
P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation), (4) a one-line
verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then (5) list every instruction you received, verbatim. Be concrete
and short. Never quote or invent an address, host name, account, serial or secret; the repository holds none and neither
should your output. English only.

Files to read, in this order:
- AGENTS.md (section 4)
- docs/adr/ADR-009-data-model-retention-and-privacy.md (section 5)
- frontend/src/components/CaptureReader.tsx, frontend/src/pages/HealthPage.tsx, frontend/src/healthFacts.ts, frontend/src/pages/NoticePage.tsx
- frontend/src/api.ts and the page that opens CaptureReader
- java/control/src/main/java/io/rwsafe/control/capture/CaptureReadController.java
- every file under java/control/src/main/java/ that names "Notice" or "Health"
- frontend tests: capture.test.tsx, health.test.tsx, notice.test.tsx; java/control/src/test/java/ file CaptureReasonCodesUiTest.java
