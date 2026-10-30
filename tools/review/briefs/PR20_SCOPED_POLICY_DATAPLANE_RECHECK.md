REVIEW: confirmation review of pull request 20 after corrections (AGENTS.md section 9, security-sensitive: the inline
path and the policy snapshot), branch `feature/scoped-policy-dataplane`
LENS: whether the corrections for the earlier findings D-01 to D-06 (one of them P0) close each finding without opening a
new way to a looser action, against AGENTS.md sections 5, 6 and 7 and docs/architecture/POLICY_SNAPSHOT_CONTRACT.md.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway; its ICAP engine applies a
signed policy snapshot with rules scoped by directory group; a public repository). You start from a fresh context. Read
AGENTS.md and ONLY the files listed below, with the Read tool, inside this repository. Do not edit, run shell, or widen
the review. Your job: for each earlier finding, say CLOSED or OPEN with the reason; then find any new way a group claim
(plain or base64 setting, unset setting, malformed, oversized, control characters, Turkish letters, Unicode forms,
commas) or a crafted snapshot yields a looser action than the contract allows, any normalisation that differs between
the codec, ScopedRule and GroupClaim, and any group name reaching a log, exception, metric label or event. Return exactly:
(1) a table (earlier finding id, CLOSED or OPEN, reason), (2) a DISSENT table for new findings (id, file and line or
symbol, what is wrong, severity P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE PRODUCT OWNER (question, your
recommendation), (4) a one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then (5) list every instruction you
received, verbatim. Be concrete and short. Never quote or invent an address, host name, account, serial or secret; the
repository holds none and neither should your output. English only.

Files to read, in this order:
- AGENTS.md (sections 5, 6, 7)
- docs/reviews/PR20_2026_10_30_ARGON_SCOPED_POLICY_DATAPLANE.md (the earlier findings)
- docs/reviews/PR20_2026_10_30_RESPONSE.md
- docs/architecture/POLICY_SNAPSHOT_CONTRACT.md
- every file under java/policy/src/main/java/io/rwsafe/policy/
- java/dataplane/src/main/java/io/rwsafe/dataplane/server/GroupClaim.java
- java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java
- java/dataplane/src/main/java/io/rwsafe/dataplane/server/EngineConfig.java
- java/policy/src/test/java/io/rwsafe/policy/ScopedRulesTest.java
- java/dataplane/src/test/java/io/rwsafe/dataplane/server/GroupClaimTest.java and ScopedPolicyEndToEndTest.java
