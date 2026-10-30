REVIEW: second independent review of pull request 17 (AGENTS.md section 9, security-sensitive: the inline path),
branch `feature/dataplane-decoding`
LENS: whether gzip/deflate decompression and base64 layer decoding on the inline ICAP path hold against AGENTS.md
section 5, docs/architecture/ICAP_AND_STREAMING_PROTOCOL_SPEC.md section 3, docs/security/BYPASS_CATALOGUE.md (BY-ENC-1,
BY-ENC-2, BY-ENC-8, BY-PROTO-7) and docs/adr/ADR-010-fail-open-and-fail-closed.md.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway; its ICAP engine inspects
prompts that a web proxy forwards; a public repository). You start from a fresh context. Read AGENTS.md and ONLY the files
listed below, with the Read tool, inside this repository. Do not edit, run shell, or widen the review. Your job: find any
decompression bomb, ratio or memory bound that can be exceeded; any multi-member, trailing-garbage, stacked or mislabelled
encoding that is inspected as something it is not, or silently allowed; any base64 run, layer depth, URL-safe or
line-broken form that escapes the detectors; any backtracking regex or blocking call on the request thread; any path where
a decode failure becomes an allow on a fail-closed flow; any rewritten body whose headers (Content-Encoding,
Content-Length) disagree with its bytes; any prompt content reaching a log, exception message or metric label; and any
false-positive rule (EMBEDDED_FILE, UNDECODABLE_BLOB, minimum run 12, entropy 4.5) that is unjustified. Return exactly:
(1) a CONSENT table (area, verdict), (2) a DISSENT table (finding id, file and line or symbol, what is wrong, severity
P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation), (4) a one-line
verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then (5) list every instruction you received, verbatim. Be concrete
and short. Never quote or invent an address, host name, account, serial or secret; the repository holds none and neither
should your output. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 5, 7)
- docs/architecture/ICAP_AND_STREAMING_PROTOCOL_SPEC.md (section 3)
- docs/security/BYPASS_CATALOGUE.md
- java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/ContentDecoding.java
- java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java
- java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/BodyInspector.java
- java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/CapturedBody.java
- java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java
- java/dataplane/src/test/java/io/rwsafe/dataplane/server/BodyDecodingTest.java
- java/dataplane/src/test/java/io/rwsafe/dataplane/server/DecodingEndToEndTest.java
- java/dataplane/src/test/java/io/rwsafe/dataplane/fuzz/Base64LayerFuzzTest.java
