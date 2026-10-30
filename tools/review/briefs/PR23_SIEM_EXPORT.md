REVIEW: second independent review of pull request 23 (AGENTS.md section 9, security-sensitive: data leaving the
product, masking, audit), branch `feature/siem-export`
LENS: whether the SIEM exporter (CEF and LEEF over syslog with TLS, Splunk HEC over HTTPS) holds against AGENTS.md
sections 4 and 5, the SR-SIEM and SR-AUD requirements, ADR-009 and ADR-010 ("accountability never silently degrades").

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway that exports verdict
events and audit-ledger entries to the corporate SIEM; a public repository). You start from a fresh context. Read
AGENTS.md and ONLY the files listed below, with the Read tool, inside this repository. Do not edit, run shell, or widen
the review. Your job: find any prompt or response content, raw identity, raw client address or estate value that can
leave in an exported record; any CEF or LEEF injection (header pipes, extension equals and backslashes, tabs, newlines,
ANSI, oversized values); any TLS gap (no host-name check, trust of any certificate, downgrade, plain fallback); any way an
event or ledger entry is lost or skipped without being counted and visible (the 15-second settle window against long
transactions, cursor moves before acknowledgement, syslog without acknowledgement, overflow, restart); any blocking of
ingestion or of the request path; any unbounded memory or retry; and any secret (HEC token) that can reach a log or
metric. Return exactly: (1) a CONSENT table (area, verdict), (2) a DISSENT table (finding id, file and line or symbol,
what is wrong, severity P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE PRODUCT OWNER (question, your
recommendation), (4) a one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then (5) list every instruction you
received, verbatim. Be concrete and short. Never quote or invent an address, host name, account, serial or secret; the
repository holds none and neither should your output. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 5)
- docs/adr/ADR-009-data-model-retention-and-privacy.md, docs/adr/ADR-010-fail-open-and-fail-closed.md
- every file under java/control/src/main/java/io/rwsafe/control/siem/
- java/persistence/src/main/java/io/rwsafe/persistence/SiemExportStore.java
- java/persistence/src/main/resources/db/migration/V4__siem_watermark.sql
- deploy/rwsafe/contracts/runtime-contracts.json
- the "SIEM export" section of docs/operations/LOCAL_RUN.md
- every test under java/control/src/test/java/ and java/persistence/src/test/java/ that names "Siem"
