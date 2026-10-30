<!-- Argon consultation 2026-10-30T20:39:59Z, model gemini-4-argon-high, effort high; unaltered output except 29 local paths masked (AGENTS.md 4.2) -->

Role: `REVIEWER`

### (1) Earlier Findings Status

| Earlier Finding ID | Status | Reason |
|---|---|---|
| **D-01** (P0) | **CLOSED** | [`InspectionResult`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/InspectionResult.java#L39-L42), [`BodyInspector.inspectText`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/BodyInspector.java#L107-L129), [`BodyInspector.inspectJson`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/BodyInspector.java#L131-L181), [`IcapConnectionHandler.stronger`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java#L419-L425), and [`IcapConnectionHandler.decideRespmodWholeBody`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java#L498-L504) preserve findings alongside `EMBEDDED_FILE` and `UNDECODABLE_BLOB` (a new `FINDING_LIMIT` early-return regression inside [`Base64Layers.scanView`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L206-L209) is recorded as **D-08** below). |
| **D-02** (P0) | **CLOSED** | Sliding-window entropy in [`Base64Layers.entropy`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L337-L356), multi-view scanning in [`Base64Layers.scanViews`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L181-L189), and depth-limit flagging in [`Base64Layers.examine`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L124-L127) close the NUL/invalid-byte, depth-3, and entropy-dilution bypasses. |
| **D-03** (P1) | **OPEN** | [`Base64Layers.examine`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L150-L155) trims every non-zero alignment `offset = 1..3` to a multiple of 4 (`int end = offset + (run.length() - offset) / 4 * 4`). Because [`Base64Layers.scan`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L112-L116) strips `'='` padding first, any base64 payload whose byte length is not a multiple of 3 ($4k + 2$ or $4k + 3$ alphabet chars, including bare 11-byte `b64(tckn)` = 15 chars and bare 20-byte `b64(awsKey)` = 27 chars) has its final 2- or 3-char quantum truncated at `offset = 1..3`, dropping the last 1–2 bytes of the secret whenever preceded by `"-"`, `"/"`, or `"v1/"` (recorded as **D-09** below). |
| **D-04** (P2) | **CLOSED** | [`BodyInspector.bzip2`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/BodyInspector.java#L211-L220) and [`ContentDecoding.compressed`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/ContentDecoding.java#L57-L70) remain intact. |
| **D-05** (P0) | **CLOSED** | [`Base64Layers.scanViews`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L181-L189) scans UTF-8 without NUL alongside UTF-16LE and UTF-16BE at both byte parities (`0` and `1`) and merges the maximum per [`DataClass`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L217-L225), and [`Base64Layers.examine`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L124-L127) flags runs at `depth >= MAX_DEPTH` as `"UNDECODABLE_BLOB"` (opening a false-positive and fan-out issue recorded as **D-10** below). |
| **D-06** (P1) | **CLOSED** | [`Base64Layers.worse`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L256-L269) orders `"EMBEDDED_FILE"` (`1`) < `"UNDECODABLE_BLOB"` (`2`) < hard limits (`3`) in both [`Base64Layers.flag`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L245-L247) and [`BodyInspector.inspectJson`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/BodyInspector.java#L160). |
| **D-07** (P1) | **OPEN** | Glued suffixes and prefixes work when the base64 payload is a multiple of 3 bytes (`40` chars in [`BodyDecodingTest.gluedSuffixAndLongPrefixesAreFound`](file://<workspace-root>/java/dataplane/src/test/java/io/rwsafe/dataplane/server/BodyDecodingTest.java#L430-L436) and [`prefixAndSuffixMatrixInBothAlphabets`](file://<workspace-root>/java/dataplane/src/test/java/io/rwsafe/dataplane/server/BodyDecodingTest.java#L439-L455)), but prefixes with `prefix.length() % 4 != 0` (`"item-"`, `"token_"`) still fail whenever the payload byte length is $\not\equiv 0 \pmod 3$ because `offset = 1..3` drops the untrimmed final quantum (recorded as **D-09** below). |

---

### (2) DISSENT Table (New Findings)

| Finding ID | File and Line / Symbol | What Is Wrong | Severity | Concrete Correction |
|---|---|---|---|---|
| **D-08** | [`Base64Layers.java#L205-L209`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L205-L209) (`scanView`), [`IcapConnectionHandler.java#L419-L425`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java#L419-L425) (`stronger`) | **Early `return` on `DetectorSet.overLimit(found)` in `scanView` discards all findings in `found` before updating `best`, turning a blocking finding into an allow on fail-open flows.** When a decoded base64 layer contains enough findings to trip `DetectorSet.overLimit(found)` at line 206 (e.g., `b64((awsKey + " ").repeat(70))`), `scanView` calls `halt("FINDING_LIMIT")` and `return`s at line 208 **before** lines 217–225 populate `best`. `examine` then adds nothing to `this.findings`, returning `Outcome(findings = [], reason = "FINDING_LIMIT", stops = true)`. On a fail-open/warn flow (`DecodingEndToEndTest.failOpenServer`), 1 base64-encoded secret is **BLOCKED**, whereas 70 base64-encoded secrets return `findings = []` so `stronger` falls back to `onNonVerdict(UNINSPECTABLE, "FINDING_LIMIT")` and **ALLOWS (`204 No Content`)** the request; on fail-closed flows and RESPMOD, `VerdictEvent` loses all finding class counts. | **P0** | Remove the early `return;` at line 208 of `Base64Layers.scanView` and instead gate the recursive scan at line 210 with `if (!DetectorSet.overLimit(found) && depth < MAX_DEPTH)` so `found` is always merged into `best` at lines 217–225 before `if (DetectorSet.overLimit(found)) halt("FINDING_LIMIT");` at lines 226–228. |
| **D-09** | [`Base64Layers.java#L112-L116`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L112-L116) (`scan`), [`Base64Layers.java#L150-L164`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L150-L164) (`examine`) | **Non-zero alignments (`offset = 1..3`) truncate the final 2- or 3-char partial quantum, missing prefixed secrets/TCKNs whenever plaintext byte length $\not\equiv 0 \pmod 3$ (`BY-ENC-1`).** `scan` strips `'='` padding before calling `examine`. Any payload of $3k + 1$ or $3k + 2$ bytes (2/3 of all lengths, including bare 11-byte `b64(tckn)` = 15 chars, 20-byte `b64(awsKey)` = 27 chars, and 20-byte `b64("customer " + tckn)` = 27 chars) has length $4k + 2$ or $4k + 3$. With any prefix of length $p \not\equiv 0 \pmod 4$ (e.g., `"-"`, `"/"`, `"v1/"`, `"item-"`, `"token_"`), `whole` (`offset = 0`) is bit-shifted, and at the aligned `offset = p % 4`, `int end = offset + (run.length() - offset) / 4 * 4` chops off the last 2 or 3 base64 chars, truncating the last 1–2 bytes of the TCKN (to 9 digits) or AWS key (to 18 chars) so detectors miss it. All existing prefix tests in `BodyDecodingTest` used `"synthetic " + awsKey` ($30$ bytes $\equiv 0 \pmod 3$, $40$ base64 chars). | **P1** | For each `offset` in `0..3` when `!clean`, decode both the multiple-of-4 slice `end = offset + (run.length() - offset) / 4 * 4` and, when `(run.length() - offset) % 4 >= 2`, the untrimmed tail slice `run.substring(offset, run.length())` (skipping a slice when identical to an already-decoded `whole`). |
| **D-10** | [`Base64Layers.java#L123-L128`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L123-L128), [`#L150-L164`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L150-L164) (`examine`), [`Base64Layers.java#L181-L216`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L181-L216) (`scanViews`, `scanView`) | **(1) Any 12+ char ASCII word in a 2nd decoded layer triggers `UNDECODABLE_BLOB`, and (2) unguarded `scanViews` across depths causes $25^d$ view fan-out.** (1) At `depth == 1` (the 2nd decoded layer), `scanView` calls `scan(normalised, 2)`. Every 12+ char word or identifier in `[A-Za-z0-9+/_-]` in layer-2 plaintext (e.g., `"configuration"`, `"international"`, `"musteri_numarasi"`) calls `examine(run, 2)`, which unconditionally sets `flag("UNDECODABLE_BLOB")` at line 126. Thus `b64(b64("international release notes"))` is falsely blocked as `UNDECODABLE_BLOB` on fail-closed flows and terminated on RESPMOD, and `b64(b64("configuration " + tckn))` is blocked instead of redacted (`BY-ENC-2`). (2) In `examine`, a non-clean run runs up to 5 decodes $\times$ 5 views (`scanViews`) = 25 `scanView` calls at `depth = 0`, each recursing into `depth = 1` ($25^2 = 625$ views) and `depth = 2` ($25^3 = 15,625$ views, because `examine` does not stop decoding at `depth >= MAX_DEPTH`), while `charge` only counts once per `decode` call rather than per scanned view, and line 163 calls `scanViews` (5 views) even when `BodyInspector.strictUtf8(bytes, bytes.length) != null`. | **P1** | 1. In `examine`'s alignment loop (line 163), check `String s = BodyInspector.strictUtf8(bytes, bytes.length);` and call `scanView(s, depth, best)` when non-null instead of `scanViews`. 2. Charge each view scanned in `scanViews` against `MAX_DECODED` (or cap total `scanView` invocations per field) and do not recurse further from `depth >= MAX_DEPTH`. 3. At `depth >= MAX_DEPTH`, only flag `"UNDECODABLE_BLOB"` when `run` looks like an actual encoded layer or blob (e.g., `run` contains digits/`+`/`/`/`=` or non-ASCII after decode, or `run.length() > 24`, rather than a plain 12-letter dictionary word). |

---

### (3) QUESTIONS FOR THE PRODUCT OWNER

| Question | Recommendation |
|---|---|
| **Q-1:** In [`DecodingEndToEndTest.base64CloudKeyIsBlocked`](file://<workspace-root>/java/dataplane/src/test/java/io/rwsafe/dataplane/server/DecodingEndToEndTest.java#L132-L141), double-encoded `b64(b64(awsKey))` is now asserted to return `Verdict.UNINSPECTABLE("UNDECODABLE_BLOB")` (because the 20-char plaintext `awsKey` at depth 2 is itself treated as a depth-3 base64 run), which also causes any 12+ letter word inside a depth-2 payload (e.g., `b64(b64("configuration " + tckn))`) to block as `UNDECODABLE_BLOB` instead of redacting as `Verdict.REDACT` under `BY-ENC-2`. Should depth-2 plaintext words and secrets be treated as depth-2 content (`Verdict.BLOCK` / `Verdict.REDACT`) unless a genuine 3rd layer is present? | **Yes:** keep depth-2 plaintext words and secrets as depth-2 findings (`BLOCK` for `SECRET`, `REDACT` for `TCKN`) so `BY-ENC-2` ("decoded to depth 2, detected; depth 3+ → the residual blob is `UNINSPECTABLE`") holds for redactable PII and benign 12+ letter words in double-encoded text. |

---

### (4) Verdict

**DO NOT MERGE** (merge after fixing P0 finding D-08 and P1 findings D-09 and D-10).

---

### (5) Verbatim Instructions Received

```text
/plan REVIEW: second confirmation review of pull request 17 after corrections (AGENTS.md section 9, security-sensitive: the inline
path), branch `feature/dataplane-decoding`
LENS: whether the corrections for the findings of the first confirmation review, D-05 (P0), D-06 and D-07, and the still-open D-02 and D-03, close each finding without opening a
new bypass, against AGENTS.md sections 5 and 7 and docs/security/BYPASS_CATALOGUE.md.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway; its ICAP engine inspects
prompts that a web proxy forwards; a public repository). You start from a fresh context. Read AGENTS.md and ONLY the
files listed below, with the Read tool, inside this repository. Do not edit, run shell, or widen the review. Your job: for
each earlier finding, say CLOSED or OPEN with the reason; then find any new way a finding is lost beside a non-verdict, a
blocking finding ends in an allow, a response with a finding ends in 204, a base64 layer (NUL-padded, UTF-16, third
layer, prefixed, path-glued, offset) escapes the detectors, a decode or retry loop exceeds its budget or becomes
super-linear, a class is counted twice across alignments or views, or text is misread as a binary signature. Return exactly: (1) a table (earlier finding id, CLOSED or OPEN,
reason), (2) a DISSENT table for new findings (id, file and line or symbol, what is wrong, severity P0/P1/P2, the concrete
correction), (3) QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation), (4) a one-line verdict MERGE / MERGE
WITH CORRECTIONS / DO NOT MERGE, then (5) list every instruction you received, verbatim. Be concrete and short. Never
quote or invent an address, host name, account, serial or secret; the repository holds none and neither should your
output. English only.

Files to read, in this order:
- AGENTS.md (sections 5, 7)
- docs/reviews/PR17_2026_10_30_ARGON_DATAPLANE_DECODING.md (the first findings)
- docs/reviews/PR17_2026_10_30_ARGON_DATAPLANE_DECODING_RECHECK.md (the confirmation findings)
- docs/reviews/PR17_2026_10_30_RESPONSE.md
- docs/security/BYPASS_CATALOGUE.md (section 8)
- java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java
- java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/BodyInspector.java
- java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/ContentDecoding.java
- java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/InspectionResult.java
- java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java
- java/dataplane/src/test/java/io/rwsafe/dataplane/server/BodyDecodingTest.java
- java/dataplane/src/test/java/io/rwsafe/dataplane/server/DecodingEndToEndTest.java
```
