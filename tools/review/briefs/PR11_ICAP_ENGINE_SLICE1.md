REVIEW: second independent review of the ICAP engine slice 1 pull request (AGENTS.md section 9, security-sensitive: the
inline path), commit d321bce on `feature/icap-engine-slice1`
LENS: protocol correctness and bypass resistance of the ICAP engine against RFC 3507, the ICAP and streaming protocol
spec, AGENTS.md sections 4 and 5, and the council findings OFF2-1, OFF2-2, OFF2-6, OFF2-10, PLAT-F4.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway: ICAP behind a corporate
proxy, prompt and response inspection under strict masking, a Java/Netty data plane; a public repository). You start from
a fresh context. Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this repository. Do not edit,
run shell, or widen the review. Your job: find any frame or body that gets an allow (204 or an unchanged 200) when the
spec requires inspection or a block; any parsing ambiguity between this engine and an HTTP/ICAP peer (Encapsulated
offsets, chunk framing, preview and ieof, header folding, duplicate framing headers) that lets content pass uninspected;
any way the REDACT rewrite or the block response can inject headers or desynchronise the proxy; any way the streamed
RESPMOD can forward bytes of a window before inspecting it; any unbounded memory or CPU on hostile input; any body text
that can reach a log, an exception message, an event or a metric (AGENTS.md 4.14); and any ArchUnit fence the code
evades. Return exactly: (1) a CONSENT table (area, verdict), (2) a DISSENT table (finding id, file and line or symbol,
what is wrong, severity P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE PRODUCT OWNER (question, your
recommendation), (4) a one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then (5) list every instruction you
received, verbatim. Be concrete and short. Never quote or invent an address, host name, account, serial or secret; the
repository holds none and neither should your output. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 5, 9)
- docs/architecture/ICAP_AND_STREAMING_PROTOCOL_SPEC.md
- docs/adr/ADR-010-fail-open-and-fail-closed.md
- docs/operations/LOCAL_RUN.md
- every file under java/dataplane/src/main/java/io/rwsafe/dataplane/
- every file under java/detect/src/main/java/io/rwsafe/detect/
- every file under java/policy/src/main/java/io/rwsafe/policy/
- every file under java/platform-core/src/main/java/io/rwsafe/platform/verdict/
- java/dataplane/src/test/java/io/rwsafe/dataplane/server/IcapEngineEndToEndTest.java
- java/dataplane/src/test/java/io/rwsafe/dataplane/icap/IcapParsingTest.java
- java/dataplane/src/test/java/io/rwsafe/dataplane/fuzz/ (all three targets)
- java/architecture-tests/src/test/java/io/rwsafe/architecture/Fences.java
- java/architecture-tests/src/test/java/io/rwsafe/architecture/ProductFencesTest.java
