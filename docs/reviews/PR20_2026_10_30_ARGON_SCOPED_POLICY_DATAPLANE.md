<!-- Argon consultation 2026-10-30T20:18:59Z, model gemini-4-argon-high, effort high; unaltered output except 0 local paths masked (AGENTS.md 4.2) -->

Role: REVIEWER

### (1) CONSENT Table

| Area | Verdict |
|---|---|
| Untrusted / plain ICAP connection handling (`IcapConnectionHandler.java:253`, `PolicyEvaluator.java:56-58, 126-159`) | **CONSENT** — When `mutualTls` is `false` or the claim is `null`, `PolicyEvaluator.resolve` returns the precompiled `strictest` resolution (strictest of `ANY` and every `enforce` scoped rule per class). |
| Fail-closed class protection in `SnapshotCodec` and `ScopedRule` (`SnapshotCodec.java:121-123`, `ScopedRule.java:25-30`) | **CONSENT** — `SnapshotCodec` and `ScopedRule` reject `ALLOW` and `WARN` for any `DataClass.failClosed()` class in both `enforce` and `monitor` modes. |
| Monitor-mode rule isolation (`PolicyEvaluator.java:93-95, 110-112, 135-137, 150-152`) | **CONSENT** — `MONITOR` rules never alter `scoped` or `effective` actions; they only populate `monitorRuleIds` when their action would differ. |
| Multi-rule conflict resolution (`Action.java:11-13`, `PolicyEvaluator.java:94, 136, 181`) | **CONSENT** — When multiple `enforce` scoped rules match a user (or multiple classes are found), `Action.max` (`BLOCK > REDACT > WARN > ALLOW`) selects the strictest action. |
| Group-name privacy in logs, exceptions, metrics, and verdict events (`ScopedRule.java:40-43`, `VerdictEvent.java:20-55`, `VerdictEventJson.java:24-70`) | **CONSENT** — `ScopedRule.toString()` prints only group count; `EffectiveActions`, `Decision`, and `VerdictEvent` carry only rule IDs (bounded to 16 IDs × 128 chars), never group names; `VerdictEventJson` omits `appliedRuleIds` and `monitorRuleIds` when empty. |
| Inline-path non-blocking and linear-time execution (`GroupClaim.java`, `PolicyEvaluator.java`, `Json.java`, `IcapConnectionHandler.java`) | **CONSENT** — No `java.util.regex`, no `String.split`, and no blocking I/O or control-plane calls on the request thread. |
| Duplicate `X-Authenticated-Groups` header rejection (`GroupClaim.java:39-43`) | **CONSENT** — `icapHead.count(HEADER) != 1` returns `null`, selecting `strictest`. |

---

### (2) DISSENT Table

| Finding ID | File and Line / Symbol | What Is Wrong | Severity | Concrete Correction |
|---|---|---|---|---|
| **D-01** | `java/dataplane/src/main/java/io/rwsafe/dataplane/server/GroupClaim.java:54-57, 95-124` (`GroupClaim.parse`, `GroupClaim.base64`) | **1. Base64 single-group claim bypasses stricter group rule:** When ProxySG base64-encodes `X-Authenticated-Groups` and a user belongs to a single group whose characters are all in `[A-Za-z0-9+/=]` (e.g. `"finance"` → `"ZmluYW5jZQ=="`), `base64()` decodes `"finance"`, finds `outside == false` because every character of `"finance"` satisfies `isBase64(c)`, and returns `null`. `GroupClaim.parse` then treats the base64 string `"zmluyw5jzq=="` as a literal plain-text group name instead of returning `null`. On Secure ICAP (`mutualTls = true`), `PolicyEvaluator.resolve(true, Set.of("zmluyw5jzq=="))` sees a non-null claim matching no rule and returns `anyScope` (`TCKN = REDACT` in `ScopedPolicyEndToEndTest`) instead of the `"finance"` rule (`TCKN = BLOCK`) or `strictest`.<br>**2. Plain group name rewritten as base64:** Any plain group name of length $4k$ in `[A-Za-z0-9+/=]` whose decoded bytes are printable UTF-8 with at least one non-base64 char (e.g. `"YWIt"` → `"ab-"`, or `"cGxhdGZvcm0tZGV2cyxh"` → `"platform-devs,a"`) is rewritten by `base64()`, which can drop a stricter group or synthesize a looser group.<br>**3. Violates `AGENTS.md` §7:** Parser guesses on an unverified wire format instead of failing closed. | **P0** | Remove the `outside` heuristic. Do not guess between plain and base64 per value: either configure the header encoding explicitly, or require an explicit prefix (e.g. `base64:`) / fail closed (`return null`) when a value contains `'='` or fails unambiguous parsing. |
| **D-02** | `java/policy/src/main/java/io/rwsafe/policy/ScopedRule.java:35-37` (`ScopedRule.normaliseGroup`) | `group.strip().toLowerCase(Locale.ROOT)` neither folds Turkish `İ` (`U+0130`) / `I` (`U+0049`) consistently nor normalises Unicode to NFC. In Java, `"\u0130".toLowerCase(Locale.ROOT)` yields `"i\u0307"` (`i` + combining dot above, 2 chars), which does not equal `"i"` (`U+0069`). On Secure ICAP, if a user is in `"İç-Denetim"` (stricter rule, stored in snapshot as `"iç-denetim"`) and `"platform-devs"` (looser rule), `"İç-Denetim"` normalises to `"i\u0307ç-denetim"`, misses the stricter rule, matches `"platform-devs"`, and yields the looser action. NFD vs NFC Turkish characters (`ğ`, `ş`, `ü`, `ö`, `ç`) have the same mismatch. | **P1** | In `ScopedRule.normaliseGroup`, normalise with `Normalizer.normalize(group.strip(), Normalizer.Form.NFC)`, replace `'\u0130'` with `'i'` before `.toLowerCase(Locale.ROOT)`, remove any residual `'\u0307'` after `'i'`, and re-normalise to NFC. |
| **D-03** | `java/dataplane/src/main/java/io/rwsafe/dataplane/server/GroupClaim.java:58-75, 81-88` (`GroupClaim.parse`, `GroupClaim.utf8`) | **1. Oversized entry skipped instead of failing closed:** Line 63 (`if (!entry.isEmpty() && entry.length() <= MAX_GROUP_NAME)`) silently skips an entry over 256 chars instead of returning `null`. A header `"platform-devs," + "x".repeat(300)` returns `Set.of("platform-devs")` (looser rule) instead of `null` (`strictest`), contradicting line 29's fail-closed rationale.<br>**2. Token count unbounded up to 8 KiB:** Line 65 checks `groups.size() > MAX_GROUPS` on the deduplicated `HashSet` rather than the number of comma-separated tokens, so `"a,a,..."` (4,096 duplicate tokens) or `",,,..."` (8,192 empty tokens) runs thousands of loop iterations and allocations on the request thread.<br>**3. Control characters accepted in plain path:** Unlike `base64()` (line 118), `utf8()` / `parse()` does not reject control chars (`c < 0x20 || c == 0x7f`), so `"finance\u0000,platform-devs"` misses `"finance"` and selects `"platform-devs"`. | **P1** | In `GroupClaim.parse`: (1) return `null` if any char in `value` has `c < 0x20 || c == 0x7f`; (2) return `null` if any token has `entry.length() > MAX_GROUP_NAME`; (3) increment a `tokens` counter on every comma-separated segment and return `null` as soon as `++tokens > MAX_GROUPS`. |
| **D-04** | `java/policy/src/main/java/io/rwsafe/policy/ScopedRule.java:20-32`, `PolicySnapshot.java:41-56`, `PolicyEvaluator.java:55-58` | **1. `ScopedRule` constructor does not normalise `groups` or reject empty `classActions`:** `ScopedRule` stores `Set.copyOf(groups)` as-is. A `ScopedRule` constructed in Java with `"Finance"` puts `"Finance"` into `PolicyEvaluator.rulesByGroup`, which never matches `GroupClaim.parse`'s `"finance"`.<br>**2. `PolicySnapshot` constructor does not enforce fail-closed on `ANY`:** Unlike `ScopedRule`, `PolicySnapshot`'s constructor allows a fail-closed `DataClass` to be set to `ALLOW` or `WARN` in `classActions`.<br>**3. `PolicyEvaluator.resolve(true, Set.of())`:** Checks `claimedGroups == null` but not `claimedGroups.isEmpty()`, returning `anyScope` instead of `strictest` for an empty set. | **P1** | (1) In `ScopedRule` compact constructor, reject `classActions.isEmpty()`, reject blank/oversized group names, and normalise every element with `ScopedRule.normaliseGroup`. (2) In `PolicySnapshot` constructor, reject `ALLOW` or `WARN` for any `c.failClosed()` entry in `this.classActions`. (3) In `PolicyEvaluator.resolve`, check `if (!trusted || claimedGroups == null || claimedGroups.isEmpty()) return strictest;`. |
| **D-05** | `java/policy/src/main/java/io/rwsafe/policy/SnapshotCodec.java:61-104, 137-167`, `Json.java:34-36` (`SnapshotCodec.parse`, `SnapshotCodec.scopedRules`, `Json.parse`) | **1. Unknown fields accepted on root and platform objects:** `POLICY_SNAPSHOT_CONTRACT.md` lines 13, 51, 65 require exact fields and refuse unknown fields, but `SnapshotCodec.parse` only checks `keySet()` on `scopedRules` entries (line 139), not on the root map `m` or `platforms` entries `p`.<br>**2. Empty `classActions` accepted on `ScopedRule`:** `SnapshotCodec.scopedRules` accepts `"classActions": {}` (sets no class).<br>**3. Group length checked before `.strip()` and duplicates within one rule's `groups` not checked after normalisation:** A 256-char whitespace-padded blank or control-char string is only partially checked.<br>**4. Non-strict UTF-8 in `Json.parse`:** `new String(utf8, StandardCharsets.UTF_8)` (line 35) replaces malformed UTF-8 with `U+FFFD` instead of rejecting with `MALFORMED`. | **P1** | (1) Check `m.keySet()` against the exact format-1 / format-2 root keys and `p.keySet()` against `Set.of("platform", "hostSuffixes", "apiHosts", "loginHosts")`. (2) Reject `actions.isEmpty()` in `SnapshotCodec.scopedRules`. (3) Check stripped group length `1..MAX_GROUP_NAME` and reject control chars (`c < 0x20 || c == 0x7f`). (4) Decode `utf8` in `Json.parse` using `StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)`. |
| **D-06** | `java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java:653-659` (`IcapConnectionHandler.abortStream`) | When a streamed RESPMOD response is aborted on a finding (`Verdict.STREAM_ABORTED`), `abortStream` calls `emit(Verdict.STREAM_ABORTED, reason, streamFindings)` with `decision = null`, so `appliedRuleIds` and `monitorRuleIds` are always empty—unlike whole-body RESPMOD `terminateWholeResponse` (line 522), which passes `decision` and populates both lists as required by `POLICY_SNAPSHOT_CONTRACT.md` step 4. | **P2** | In `abortStream`, when `nonVerdictReason == null`, evaluate `Decision decision = policy.evaluator().onFindings(streamFindings, false, effective)` and pass `decision` to `emit(Verdict.STREAM_ABORTED, reason, streamFindings, decision)`. |

---

### (3) QUESTIONS FOR THE PRODUCT OWNER

| # | Question | Recommendation |
|---|---|---|
| **Q-1** | `PO_DECISION_RECORD_2026_10_30_POLICY_SCOPE_AND_PLATFORM_RETIREMENT.md` marks `X-Authenticated-Groups` on the estate proxy as **UNVERIFIED**. Should `rwsafe-icap` configure the expected `X-Authenticated-Groups` encoding explicitly (`plain` vs `base64` via manifest configuration once verified on the appliance) rather than guessing per header value with a heuristic? | **Configure explicitly (no heuristic).** Use an explicit engine setting (defaulting to the verified ProxySG format) so the parser never guesses (`AGENTS.md` §7) and cannot misread a base64-encoded single group name as plain text (D-01). |
| **Q-2** | Will directory groups in the policy registry and `X-Authenticated-Groups` be short group names (`cn` / `sAMAccountName` / `WinNT://...` without commas) or full LDAP Distinguished Names (`CN=...,OU=...,DC=...`, which contain commas inside a single group name)? | **Use short group names without commas** in both ProxySG ICAP configuration and the policy registry, and forbid `,` inside group names in `SnapshotCodec` so comma-separated header parsing is unambiguous. |

---

### (4) Verdict

**DO NOT MERGE** (until P0 finding D-01 and P1 findings D-02 through D-05 are corrected).

---

### (5) Instructions Received (Verbatim)

```text
/plan REVIEW: second independent review of pull request 20 (AGENTS.md section 9, security-sensitive: the inline path and the
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
```
