REVIEW: second independent review of pull request 22 (AGENTS.md section 9, security-sensitive: masking, internal routes,
security configuration, block pages on the inline path), branch `feature/end-user-notices`
LENS: whether the Turkish end-user texts, their rendering, and the notice acknowledgement recording and gate hold against
AGENTS.md sections 3, 4 and 5, the SR-PRIV and PRIV-2 requirements, and PO decisions Q-4, Q-5, Q-6, Q-32, Q-33 and Q-35.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway that shows employees a
Turkish notice and block pages and records their acknowledgement; a public repository). You start from a fresh context.
Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this repository. Do not edit, run shell, or
widen the review. Your job: find any XSS, header injection or external resource in a rendered page; any prompt content,
identity or estate value reaching a page, a log or the masked role; any way the acknowledgement gate opens content
capture without a record of the current notice version, or a record can be forged, replayed, altered or deleted; any
internal route reachable from outside its port or by the wrong role; any blocking work or regex on the request thread;
and any Turkish wording that contradicts the decision records (consent as a basis, exceptions for fail-closed classes,
personal accounts, retention). Return exactly: (1) a CONSENT table (area, verdict), (2) a DISSENT table (finding id, file
and line or symbol, what is wrong, severity P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE PRODUCT OWNER
(question, your recommendation), (4) a one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then (5) list every
instruction you received, verbatim. Be concrete and short. Never quote or invent an address, host name, account, serial
or secret; the repository holds none and neither should your output. English only, except quoted Turkish catalogue keys.

Files to read, in this order:
- AGENTS.md (sections 3, 4, 5)
- docs/i18n/README.md and every file under docs/i18n/tr/
- java/platform-core/src/main/resources/io/rwsafe/platform/enduser/end-user-tr.properties
- every file under java/platform-core/src/main/java/ that names "EndUser"
- java/dataplane/src/main/java/io/rwsafe/dataplane/server/BlockPages.java
- java/persistence/src/main/resources/db/migration/V5__notice_acknowledgement.sql
- every file under java/control/src/main/java/ that names "Notice", "Acknowledg" or "SecurityConfig"
- every test under java/platform-core/src/test/, java/control/src/test/ and java/persistence/src/test/ that names "Notice", "EndUser" or "Acknowledg", and java/dataplane/src/test/java/io/rwsafe/dataplane/server/BlockPagesTest.java
