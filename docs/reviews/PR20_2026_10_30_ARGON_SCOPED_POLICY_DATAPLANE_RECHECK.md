<!-- Argon consultation 2026-10-30T20:30:16Z, model gemini-4-argon-high, effort high; unaltered output except 0 local paths masked (AGENTS.md 4.2) -->

Role: REVIEWER

### (1) Earlier Findings Status

| Earlier Finding ID | Status | Reason |
|---|---|---|
| **D-01** | **CLOSED** | The per-value base64 heuristic (`outside`) is removed. `EngineConfig.GroupClaimEncoding` (`DISABLED`, `PLAIN`, `BASE64`) is configured explicitly via `fromSetting` (accepting only `"plain"` or `"base64"`, defaulting to `DISABLED`). `GroupClaim.parse` returns `null` when disabled and always base64-decodes the entire value when `BASE64` is configured (`GroupClaim.java:38-60, 95-104`, `EngineConfig.java:37-58`). |
| **D-02** | **CLOSED** | `GroupNames.normalise` (`GroupNames.java:34-64`) is shared by `SnapshotCodec`, `ScopedRule`, and `GroupClaim`. It normalises to Unicode NFC, folds `İ` (`U+0130`), `I` (`U+0049`), and `ı` (`U+0131`) to `i`, lowercases with `Locale.ROOT`, strips any residual `U+0307` after `i`, and re-normalises to NFC. |
| **D-03** | **CLOSED** | `GroupClaim.groups` (`GroupClaim.java:62-92`) rejects control characters (`c < 0x20 || c == 0x7f`), counts every comma-separated token (including empty and duplicate tokens) against `MAX_TOKENS = 256`, and returns `null` when `GroupNames.normalise(token)` returns `null` (including stripped tokens over 256 chars). |
| **D-04** | **CLOSED** | `ScopedRule` (`ScopedRule.java:21-43`) rejects empty `classActions` and validates/normalises all group names via `GroupNames.normalise`; `PolicySnapshot` (`PolicySnapshot.java:49-54`) rejects `ALLOW` or `WARN` for any `failClosed()` class in `ANY`; `PolicyEvaluator.resolve` (`PolicyEvaluator.java:56-58`) returns `strictest` when `claimedGroups.isEmpty()`. |
| **D-05** | **CLOSED** | `SnapshotCodec.parse` (`SnapshotCodec.java:79-81, 109-111`) enforces exact field sets on the root object (`ROOT_FIELDS_1` / `ROOT_FIELDS_2`) and platform rows (`PLATFORM_FIELDS`); `SnapshotCodec.scopedRules` (`SnapshotCodec.java:169-183`) validates groups via `GroupNames.normalise` and rejects empty `classActions`; `Json.parse` (`Json.java:41-45`) decodes UTF-8 with `CodingErrorAction.REPORT`. |
| **D-06** | **CLOSED** | `IcapConnectionHandler.abortStream` (`IcapConnectionHandler.java:660-662`) evaluates `policy.evaluator().onFindings(streamFindings, false, effective)` when `nonVerdictReason == null` and passes `decision` to `emit`, populating `appliedRuleIds` and `monitorRuleIds`. |

---

### (2) DISSENT Table (New Findings)

| Finding ID | File and Line / Symbol | What Is Wrong | Severity | Concrete Correction |
|---|---|---|---|---|
| **N-01** | `java/dataplane/src/main/java/io/rwsafe/dataplane/server/GroupClaim.java:51` (`GroupClaim.parse`) and `java/policy/src/main/java/io/rwsafe/policy/GroupNames.java:38-47` (`GroupNames.normalise`) | **`String.strip()` runs before the control-character check (`c < 0x20 || c == 0x7f`):** In Java, `Character.isWhitespace(int)` is `true` for ASCII control characters `0x09..0x0D` (`\t`, `\n`, `\u000B`, `\f`, `\r`) and `0x1C..0x1F` (FS, GS, RS, US).<br>1. In `GroupClaim.parse` (line 51), `headerValue.strip()` strips leading and trailing `0x09..0x0D` and `0x1C..0x1F` before `groups(list)` checks `c < 0x20`. On Secure ICAP with `PLAIN` encoding, a header `"platform-devs,\u001f"` (where the second token is a corrupted control character `0x1F`) is stripped to `"platform-devs,"`, ignoring the empty trailing token and returning `Set.of("platform-devs")` (looser rule) instead of `null` (`strictest`).<br>2. In `GroupNames.normalise` (line 38), `name.strip()` strips leading and trailing `0x09..0x0D` and `0x1C..0x1F` before lines 42–47 check `c < 0x20`, so `SnapshotCodec` and `ScopedRule` accept `"groups": ["\u001ffinance"]` or `"\tfinance\n"` as `"finance"`, whereas `GroupClaim.groups` rejects `"other,\u001ffinance"` because `\u001f` is not at the outer boundary of `headerValue`. | **P2** | (1) In `GroupNames.normalise`, check `for (int i = 0; i < name.length(); i++) { char c = name.charAt(i); if (c == ',' || c < 0x20 || c == 0x7f) return null; }` **before** `String s = name.strip();`.<br>(2) In `GroupClaim.parse`, reject any character with `c < 0x20 || c == 0x7f` in `headerValue` **before** calling `headerValue.strip()`. |

---

### (3) QUESTIONS FOR THE PRODUCT OWNER

| # | Question | Recommendation |
|---|---|---|
| — | None. Earlier questions Q-1 and Q-2 are resolved and implemented. | — |

---

### (4) Verdict

**MERGE WITH CORRECTIONS**

---

### (5) Instructions Received (Verbatim)

```text
/plan REVIEW: confirmation review of pull request 20 after corrections (AGENTS.md section 9, security-sensitive: the inline
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
```
