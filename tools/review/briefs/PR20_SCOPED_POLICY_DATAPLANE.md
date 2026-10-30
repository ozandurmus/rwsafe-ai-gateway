REVIEW: second independent review of pull request 20 (AGENTS.md section 9, security-sensitive: the inline path and the
policy snapshot), branch `feature/scoped-policy-dataplane`
LENS: whether snapshot format 2 (scoped rules by directory group) and its evaluation on the data plane hold against
AGENTS.md sections 4, 5, 6 and 7, docs/architecture/POLICY_SNAPSHOT_CONTRACT.md (section "Format 2: scoped rules"),
docs/design/PO_DECISION_RECORD_2026_10_30_POLICY_SCOPE_AND_PLATFORM_RETIREMENT.md and the identity row of
docs/architecture/ICAP_AND_STREAMING_PROTOCOL_SPEC.md.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway; its ICAP engine inspects
prompts that a web proxy forwards and applies a signed policy snapshot; a public repository). You start from a fresh
context. Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this repository. Do not edit, run
shell, or widen the review. Your job: find any way a group claim on a plain (not mutually authenticated) connection, a
missing, duplicated, oversized or malformed X-Authenticated-Groups header, a case or whitespace trick, or a crafted
snapshot can make a transaction get a looser action than the contract allows; any way a fail-closed class reaches ALLOW
or WARN in any scope or mode; any way a monitor rule changes a verdict; any non-strictest result when several rules
match; any parser that accepts what the contract refuses; any group name reaching a log, exception, metric label or
verdict event; any backtracking regex, String.split or blocking call on the request thread; and any unbounded list or
allocation driven by the header or the snapshot. Return exactly: (1) a CONSENT table (area, verdict), (2) a DISSENT table
(finding id, file and line or symbol, what is wrong, severity P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE
PRODUCT OWNER (question, your recommendation), (4) a one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then
(5) list every instruction you received, verbatim. Be concrete and short. Never quote or invent an address, host name,
account, serial or secret; the repository holds none and neither should your output. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 5, 6, 7)
- docs/architecture/POLICY_SNAPSHOT_CONTRACT.md
- docs/design/PO_DECISION_RECORD_2026_10_30_POLICY_SCOPE_AND_PLATFORM_RETIREMENT.md
- docs/architecture/ICAP_AND_STREAMING_PROTOCOL_SPEC.md (the identity row of the first table)
- every file under java/policy/src/main/java/io/rwsafe/policy/
- java/dataplane/src/main/java/io/rwsafe/dataplane/server/GroupClaim.java
- java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java
- java/dataplane/src/main/java/io/rwsafe/dataplane/events/VerdictEvent.java and VerdictEventJson.java
- java/policy/src/test/java/io/rwsafe/policy/ScopedRulesTest.java
- java/dataplane/src/test/java/io/rwsafe/dataplane/server/GroupClaimTest.java and ScopedPolicyEndToEndTest.java
