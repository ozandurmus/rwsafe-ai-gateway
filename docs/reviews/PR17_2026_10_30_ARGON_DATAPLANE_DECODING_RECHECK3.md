<!-- Argon consultation 2026-10-30T20:54:11Z, model gemini-4-argon-high, effort high; unaltered output except 26 local paths and one checksum-valid TCKN example masked (AGENTS.md 4.2, 4.5) -->

Role: `REVIEWER`

### (1) Earlier Findings Status

| Earlier Finding ID | Status | Reason |
|---|---|---|
| **D-01** (P0) | **CLOSED** | [`InspectionResult`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/InspectionResult.java#L39-L42), [`BodyInspector.inspectText`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/BodyInspector.java#L107-L129), [`BodyInspector.inspectJson`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/BodyInspector.java#L131-L181), [`IcapConnectionHandler.stronger`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java#L419-L425), and [`IcapConnectionHandler.decideRespmodWholeBody`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java#L492-L524) preserve findings and rewrites alongside non-verdicts. |
| **D-02** (P0) | **CLOSED** | Sliding-window entropy in [`Base64Layers.entropy`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L417-L436) and multi-view byte scanning in [`Base64Layers.scanViews`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L215-L231) remain intact. |
| **D-03** (P1) | **CLOSED** | [`Base64Layers.examine`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L146-L160) decodes both the untrimmed (`lenient`) and multiple-of-4 (`trimmed`) candidates across all four alignments `0..3`, and [`Base64Layers.quantumMasked`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L335-L349) blanks non-printable 3-byte prefix/suffix quanta so glued prefixes and path segments do not hide adjacent values. |
| **D-04** (P2) | **CLOSED** | [`BodyInspector.bzip2`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/BodyInspector.java#L211-L220) and [`ContentDecoding.compressed`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/ContentDecoding.java#L57-L70) remain intact. |
| **D-05** (P0) | **CLOSED** | [`Base64Layers.scanViews`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L215-L231) scans UTF-8 without NUL, quantum-masked ASCII, and UTF-16LE/BE at both byte parities while deduplicating per [`DataClass`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L256-L264). |
| **D-06** (P1) | **CLOSED** | [`Base64Layers.worse`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L319-L332) orders `"EMBEDDED_FILE"` (`1`) < `"UNDECODABLE_BLOB"` (`2`) < hard limits (`3`) within and across fields. |
| **D-07** (P1) | **CLOSED** | Closed together with **D-03** and **D-09** by decoding both `lenient` and `trimmed` slices at offsets `0..3` and scanning [`Base64Layers.quantumMasked`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L335-L349). |
| **D-08** (P0) | **CLOSED** | [`Base64Layers.scanView`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L248-L267) now merges `found` (and any inner findings) into `best` before `halt("FINDING_LIMIT")`, and [`Base64Layers.examine`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L163-L169) copies `best` into `findings` on every exit path, verified by [`DecodingEndToEndTest.encodedSecretsAtTheFindingLimitStillBlockOnAFailOpenFlow`](file://<workspace-root>/java/dataplane/src/test/java/io/rwsafe/dataplane/server/DecodingEndToEndTest.java#L260-L272). |
| **D-09** (P1) | **CLOSED** | [`Base64Layers.examine`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L148-L159) keeps the final 2- or 3-character partial quantum via `lenient` alongside `trimmed`, and [`BodyDecodingTest.prefixedPayloadsWithAPartialLastQuantumAreFound`](file://<workspace-root>/java/dataplane/src/test/java/io/rwsafe/dataplane/server/BodyDecodingTest.java#L469-L478) and [`prefixAndSuffixMatrixInBothAlphabets`](file://<workspace-root>/java/dataplane/src/test/java/io/rwsafe/dataplane/server/BodyDecodingTest.java#L443-L465) verify bare 11-byte TCKNs and 20-byte keys across prefixes and suffixes. |
| **D-10** (P1) | **OPEN** | View fan-out is closed (`scanViews` runs only when `strictUtf8 == null`, charges each view to `MAX_DECODED`, and does not recurse, verified in [`Base64LayersTest`](file://<workspace-root>/java/dataplane/src/test/java/io/rwsafe/dataplane/inspect/Base64LayersTest.java#L32-L61)), and 2nd-layer words/values are kept as content. However, the new [`Base64Layers.thirdLayer`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L275-L292) shape check misses unpadded 15-char 3rd-layer TCKNs, prefixed/suffixed 3rd-layer base64 runs, and uppercase+digit 3rd-layer base64 runs (recorded as **D-11** below). |

---

### (2) DISSENT Table (New Findings)

| Finding ID | File and Line / Symbol | What Is Wrong | Severity | Concrete Correction |
|---|---|---|---|---|
| **D-11** | [`Base64Layers.java#L130-L137`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L130-L137) (`examine`), [`Base64Layers.java#L275-L292`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L275-L292) (`thirdLayer`) | **Three 3rd-layer base64 forms return `false` from `thirdLayer(run, pad)` and are silently allowed (`BY-ENC-2`):** (1) *Unpadded 15-char 3rd-layer TCKN:* A bare 11-byte TCKN encoded without `'='` padding is 15 characters (`n = 15, pad = 0`), as noted at [`Base64Layers.java#L43`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L43), but line 277 rejects `n + pad < 16`, so `b64(b64(b64(tckn).replace("=", "")))` is silently allowed. (2) *Prefixed or suffixed 3rd-layer base64:* Prepending `"-"`, `"/"`, `"v1/"`, `"item-"`, or `"token_"`, or appending `"-"`, to the 3rd-layer base64 string inside the 2nd layer makes `n % 4 == 1`, or `pad > 0 && (n + pad) % 4 != 0` (for every `'='`-padded 3rd layer with a 1–3 char prefix, e.g. `b64(b64("-" + b64(awsKey)))` or `b64(b64("v1/" + b64(tckn)))`), or shifts the final quantum so `(last & 0x0f) != 0` / `(last & 0x03) != 0` at line 281, causing `thirdLayer` to return `false`. (3) *Uppercase+digit 3rd-layer base64:* Every 3-digit ASCII group `0x30..0x39` encodes to uppercase `'M'..'O'` in the first sextet and digits `'0'..'5'` when the third digit is `'4'..'9'`; thus valid TCKNs such as `"<masked-tckn>"` encode to `"MTA0MDA0MDA0OTI="` (`upper = true, lower = false, pad = 1`), which fails `upper && lower` at line 291 and is silently allowed. | **P1** | In `Base64Layers.thirdLayer(String run, int pad)`: 1. Lower the minimum length from `n + pad < 16` to `n + pad < 15`. 2. Drop the alignment-sensitive `n % 4 == 1`, `(pad > 0 && (n + pad) % 4 != 0)`, and `last` unused-bit checks so a glued prefix or suffix inside the 2nd layer cannot hide a 3rd layer. 3. Return `true` when `pad > 0`, or `upper && lower`, or `upper && digit && !run.startsWith("AKIA") && !run.startsWith("ASIA")` (so 2nd-layer plain words, snake_case identifiers, all-caps words, plain numbers, and 2nd-layer AWS keys remain `false`, while unpadded, prefixed/suffixed, and uppercase+digit 3rd-layer base64 runs are flagged as `"UNDECODABLE_BLOB"`). |

---

### (3) QUESTIONS FOR THE PRODUCT OWNER

| Question | Recommendation |
|---|---|
| None. | — |

---

### (4) Verdict

**DO NOT MERGE** (merge after fixing P1 finding D-11 in `Base64Layers.thirdLayer`).

---

### (5) Verbatim Instructions Received

```text
/plan REVIEW: third confirmation review of pull request 17 after corrections (AGENTS.md section 9, security-sensitive: the inline
path), branch `feature/dataplane-decoding`
LENS: whether the corrections for the findings of the second confirmation review, D-08 (P0), D-09 and D-10, and the still-open D-03 and D-07, close each finding without opening a
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
- docs/reviews/PR17_2026_10_30_ARGON_DATAPLANE_DECODING_RECHECK.md (the first confirmation findings)
- docs/reviews/PR17_2026_10_30_ARGON_DATAPLANE_DECODING_RECHECK2.md (the second confirmation findings)
- docs/reviews/PR17_2026_10_30_RESPONSE.md
- docs/security/BYPASS_CATALOGUE.md (section 8)
- java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java
- java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/BodyInspector.java
- java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/ContentDecoding.java
- java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/InspectionResult.java
- java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java
- java/dataplane/src/test/java/io/rwsafe/dataplane/server/BodyDecodingTest.java
- java/dataplane/src/test/java/io/rwsafe/dataplane/server/DecodingEndToEndTest.java
- java/dataplane/src/test/java/io/rwsafe/dataplane/inspect/Base64LayersTest.java
```
