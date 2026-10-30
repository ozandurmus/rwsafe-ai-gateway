REVIEW: second independent review of pull request 14 (AGENTS.md section 9, security-sensitive: the inline path and policy
activation), branch `feature/dataplane-slice2`
LENS: whether the signed policy pull, Secure ICAP, admission control, drain, verdict spool and metrics hold against the
POLICY_SNAPSHOT_CONTRACT, the ICAP and streaming protocol spec (§2, §3, §4.2, §7, §8), ADR-010 §3, SR-DP-8 and SR-DP-12.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway: ICAP behind a corporate
proxy, prompt and response inspection under strict masking, a Java/Netty data plane; a public repository). You start from
a fresh context. Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this repository. Do not edit,
run shell, or widen the review. Your job: find any way an attacker or a fault can make the engine run a weaker or older
policy (signature bypass, parser ambiguity, key confusion, clock, cache poisoning, activation race); any way the Secure
ICAP listener accepts a peer without the proxy's certificate or marks a plain connection as verified; any way one
identity, a slow body or many bodies can exhaust the engine, or the admission counters leak and lock out users; any way a
drain drops an in-flight transaction or keeps serving forever; any way a verdict event is lost without the fail-closed
backpressure engaging, or the spool replays out of order or unbounded; any content or identity reaching a metric label;
and any ArchUnit fence the code evades. Return exactly: (1) a CONSENT table (area, verdict), (2) a DISSENT table (finding
id, file and line or symbol, what is wrong, severity P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE PRODUCT
OWNER (question, your recommendation), (4) a one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then (5) list
every instruction you received, verbatim. Be concrete and short. Never quote or invent an address, host name, account,
serial or secret; the repository holds none and neither should your output. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 5, 9)
- docs/architecture/POLICY_SNAPSHOT_CONTRACT.md
- docs/architecture/ICAP_AND_STREAMING_PROTOCOL_SPEC.md (sections 2, 3, 4.2, 7, 8)
- docs/adr/ADR-010-fail-open-and-fail-closed.md
- java/policy/src/main/java/io/rwsafe/policy/Json.java, SnapshotCodec.java, SnapshotVerifier.java, PolicySnapshot.java
- every file under java/dataplane/src/main/java/io/rwsafe/dataplane/server/
- every file under java/dataplane/src/main/java/io/rwsafe/dataplane/controlplane/
- every file under java/dataplane/src/main/java/io/rwsafe/dataplane/boot/
- every file under java/dataplane/src/main/java/io/rwsafe/dataplane/events/ and .../metrics/
- java/dataplane/src/main/java/io/rwsafe/dataplane/icap/IcapResponses.java
- java/dataplane/src/test/java/io/rwsafe/dataplane/server/SliceTwoTest.java
- java/policy/src/test/java/io/rwsafe/policy/SnapshotCodecTest.java
- java/architecture-tests/src/test/java/io/rwsafe/architecture/Fences.java, ProductFencesTest.java
