REVIEW: confirmation review of pull request 25 after corrections (AGENTS.md section 9, security-sensitive: the inline path, raw and
redacted content, encryption, masking, the read path), branch `feature/redacted-capture`
LENS: whether the corrections for D-01 to D-07 and the three answered questions (storage outside PostgreSQL per ADR-009, reader roles, key rotation versus shredding) close each finding, and whether redacted content capture, its encryption and retention, the notice-acknowledgement gate, the disk watermark
breaker and the authorised read path hold against AGENTS.md sections 4, 5 and 8 (especially 4.7, 4.13, 4.14), PO
decisions Q-3, Q-4 and Q-5, ADR-009 and ADR-010.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway; captured prompt content
is the most sensitive data it holds; a public repository). You start from a fresh context. Read AGENTS.md and ONLY the
files listed below, with the Read tool, inside this repository. Do not edit, run shell, or widen the review. Your job:
find any way unredacted bytes, a detected secret or an identifier reach storage, the spool, a log, a metric, an exception
or a response; any capture stored without a current notice acknowledgement or above the watermark; any encryption flaw
(nonce reuse, key in the row, missing authentication of metadata, key rotation that leaves readable data, shredding that
does not shred); any read without role, reason, case id and a ledger entry written first; any masked-role or viewer path
to content; any request-thread work beyond wrapping an existing array; any retention or deletion gap; and any bidi or
control-character injection in served text. For each earlier finding and question say CLOSED or OPEN with the reason. Also check the chunk store: content-addressing that could act as an existence oracle, reference counting under concurrency, eviction order, deletion that leaves orphan chunk files, re-wrap without decryption, and the shred list. Return exactly: (1) a table (earlier finding or question, CLOSED or OPEN, reason), (2) a DISSENT table for new findings
(finding id, file and line or symbol, what is wrong, severity P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE
PRODUCT OWNER (question, your recommendation), (4) a one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then
(5) list every instruction you received, verbatim. Be concrete and short. Never quote or invent an address, host name,
account, serial or secret; the repository holds none and neither should your output. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 5, 8)
- docs/reviews/PR25_2026_10_31_ARGON_REDACTED_CAPTURE.md (the earlier findings)
- docs/reviews/PR25_2026_10_31_RESPONSE.md
- docs/adr/ADR-009-data-model-retention-and-privacy.md
- docs/design/PO_DECISION_RECORD_2026_10_30_MVP_BLOCKING_QUESTIONS.md (Q-3, Q-4, Q-5)
- java/persistence/src/main/resources/db/migration/V8__redacted_capture.sql
- every file under java/control/src/main/java/io/rwsafe/control/capture/
- every file under java/platform-core/src/main/java/ that names "Watermark" or "Capacity"
- java/dataplane/src/main/java/ files that name "Capture" or "CapturedText", plus events/VerdictEvent.java, events/VerdictEventJson.java and controlplane/EventShipper.java
- every file under java/persistence/src/main/java/ that names "Capture"
- java/control/src/main/java/io/rwsafe/control/siem/SiemRecords.java
- every test that names "Capture", "Watermark" or "Keyring"
