<!-- Argon consultation 2026-10-30T20:22:42Z, model gemini-4-argon-high, effort high; unaltered output except 24 local paths masked (AGENTS.md 4.2) -->

Role: `REVIEWER`

### (1) Earlier Findings Status

| Earlier Finding ID | Status | Reason |
|---|---|---|
| **D-01** (P0) | **CLOSED** | [`InspectionResult`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/InspectionResult.java#L39-L42) now carries `findings`, `redactable`, and `redactedBody` alongside a `nonVerdict`. [`Base64Layers.inspect`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L67-L74) preserves collected findings when `reason != null`; [`BodyInspector.inspectText`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/BodyInspector.java#L107-L129) and [`BodyInspector.inspectJson`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/BodyInspector.java#L131-L182) retain findings and rewrites across `EMBEDDED_FILE` and `UNDECODABLE_BLOB`; [`IcapConnectionHandler.stronger`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java#L419-L425) enforces the stronger of the finding action and non-verdict action on REQMOD; and [`IcapConnectionHandler.decideRespmodWholeBody`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java#L498-L504) terminates any whole-body response that carries findings or `UNDECODABLE_BLOB` (leaving a precedence edge case when `EMBEDDED_FILE` precedes `UNDECODABLE_BLOB`, recorded as **D-06** below). |
| **D-02** (P0) | **OPEN** | Sliding-window Shannon entropy over `min(length, 256)` in [`Base64Layers.entropy`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L375-L394) closes the entropy-dilution bypass, and single-NUL/UTF-16LE recovery is added in [`Base64Layers.recovered`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L252-L275). However, two bypasses remain: (1) [`Base64Layers.utf16le`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L264-L275) misclassifies NUL-padded UTF-8 (`concat(new byte[L], utf8(secret))`) as UTF-16LE, decoding the ASCII secret bytes into CJK code points (`0x2020..0x7a7a`) and skipping `withoutNul` UTF-8 scanning; (2) at `depth == MAX_DEPTH`, a single control byte (`0x01`) or invalid UTF-8 byte (`0xff`) inside the 3rd layer bypasses [`Base64Layers.layer`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L158-L163) (recorded as **D-05** below). |
| **D-03** (P1) | **OPEN** | [`Base64Layers.realign`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L188-L206) handles leading `[-_+/]`, `/`-segments, and 1–3 char alphanumeric prefixes, but still fails when: (1) a single trailing `-` or `_` is glued to a $4k$-char base64 string (e.g. `b64("synthetic " + awsKey) + "-"`, length `41 % 4 == 1`), where `decode` returns `null` and `offset = 1..3` shifts the start index and misaligns the entire payload; or (2) a prefix of length $\ge 5$ with `len % 4 != 0` (e.g. `"item-" + enc`, `"token_" + enc`) leaves at least one 4-char prefix quantum in `stripped.substring(offset)` that decodes to 3 non-UTF-8 bytes, causing `text(bytes)` in [`Base64Layers.retry`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L217-L219) to return `null` (recorded as **D-07** below). |
| **D-04** (P2) | **CLOSED** | [`BodyInspector.bzip2`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/BodyInspector.java#L212-L221) now requires `'B', 'Z', 'h'`, level `'1'..'9'`, and the 6-byte block or end-of-stream magic, and [`ContentDecoding.compressed`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/ContentDecoding.java#L57-L70) treats `0x78 0x5e` (`"x^"`) as zlib only when `BodyInspector.strictUtf8(b, len) == null`. |

---

### (2) DISSENT Table (New Findings)

| Finding ID | File and Line / Symbol | What Is Wrong | Severity | Concrete Correction |
|---|---|---|---|---|
| **D-05** | [`Base64Layers.java#L137-L143`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L137-L143) (`examine`), [`Base64Layers.java#L158-L163`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L158-L163) (`layer`), [`Base64Layers.java#L252-L275`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L252-L275) (`recovered`, `utf16le`) | **NUL-padded UTF-8 and 3rd-layer control/non-UTF-8 byte bypasses (`BY-ENC-1`, `BY-ENC-2`):** (1) In `utf16le(byte[] b)`, `zeros * 2 >= b.length / 2` counts `b[k] == 0` at odd indices without requiring `b[k - 1] != 0`. For `concat(new byte[L], utf8(secret))` (e.g. 30 NUL bytes + 30-byte ASCII secret, 80 base64 chars), half of the odd indices are `0`, so `utf16le` returns `true`. `new String(b, UTF_16LE)` decodes each pair of ASCII bytes in `secret` into a BMP CJK character (`0x2020..0x7a7a`, no UTF-16 surrogates, so `s.indexOf('\uFFFD') < 0`). `recovered` returns the CJK string and `examine` skips `withoutNul(bytes)` as UTF-8, missing the secret completely. (2) At `depth == MAX_DEPTH` (`2`), `layer` flags `UNDECODABLE_BLOB` only if `printable(text)` is true for every char, and `examine` line 141 calls `scanLayer` instead of `layer` when `recovered == null`. A 3rd layer containing a single control byte (`b64(b64(b64("\x01" + secret)))`) or invalid UTF-8 byte (`b64(b64(b64("\xff" + b64(secret))))`) with `run.length() <= 256` fails `printable(text)` / `recovered != null` and is silently allowed. | **P0** | 1. In `utf16le(byte[] b)`, count only ASCII-like UTF-16LE pairs (`b[k - 1] != 0 && b[k] == 0` vs non-NUL pairs), and in `examine`, when `utf16le` matches, also scan `new String(withoutNul(bytes), StandardCharsets.UTF_8)` if `strictUtf8` on `withoutNul(bytes)` succeeds. 2. At `depth >= MAX_DEPTH`, flag `"UNDECODABLE_BLOB"` in `examine` / `layer` whenever `withoutNul(bytes)` contains a contiguous printable ASCII run of `>= 9` bytes (instead of requiring the entire decoded buffer to be `strictUtf8` and `printable`). |
| **D-06** | [`Base64Layers.java#L233-L237`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L233-L237) (`flag`), [`BodyInspector.java#L158-L161`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/BodyInspector.java#L158-L161) (`inspectJson`), [`IcapConnectionHandler.java#L54-L55`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java#L54-L55), [`#L498-L508`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java#L498-L508) (`decideRespmodWholeBody`) | **An earlier `EMBEDDED_FILE` masks a later `UNDECODABLE_BLOB`, letting a whole-body response with a blob or depth-3 payload end in `204`.** `Base64Layers.flag` sets `reason` only when `reason == null`, and `BodyInspector.inspectJson` sets `blobReason` only when `blobReason == null`. If an earlier base64 run or JSON leaf sets `EMBEDDED_FILE` (e.g. `b64("%PDF-1.4\n")` or a >256-char PNG) and a subsequent run or leaf triggers `UNDECODABLE_BLOB` (a 300-byte random blob or `b64(b64(b64(secret)))`), `result.reason()` remains `"EMBEDDED_FILE"`. Because `TERMINATING_REASONS` contains `"UNDECODABLE_BLOB"` but not `"EMBEDDED_FILE"`, `decideRespmodWholeBody` answers `204 No Content` instead of terminating the response; on REQMOD, prepending `b64("%PDF-1.4\n")` downgrades `UNDECODABLE_BLOB` to `EMBEDDED_FILE`. | **P1** | Give `"UNDECODABLE_BLOB"` precedence over `"EMBEDDED_FILE"` in both `Base64Layers.flag` (`if (reason == null || "EMBEDDED_FILE".equals(reason)) reason = r;`) and `BodyInspector.inspectJson` (`if (blobReason == null || "UNDECODABLE_BLOB".equals(layers.reason())) blobReason = layers.reason();`). |
| **D-07** | [`Base64Layers.java#L188-L230`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L188-L230) (`realign`, `retry`), [`Base64Layers.java#L350-L354`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L350-L354) (`decode`) | **Glued suffixes (`enc + "-"`) and 5–7+ char prefixes (`"item-" + enc`, `"token_" + enc`) defeat `realign` (`BY-ENC-1`).** (1) When `enc` has length $4k$ (such as the 40-char `b64("synthetic " + Synthetic.awsKey())` in `BodyDecodingTest`), appending a single `"-"` or `"_"` makes `run.length() == 41` (`1 mod 4`). `decode(run)` returns `null`, `stripLeading` leaves the trailing `"-"`, and `offset = 1..3` shifts the start index (`1, 2, 3`), misaligning the entire 40-char base64 payload so all retries fail. (2) For a prefix of length $\ge 5$ with `len % 4 != 0` (e.g. `"item-" + enc` or `"token_" + enc`), `realign` does not split on `'-'` or `'_'`, and the aligned retry (`offset = 1`, `"tem-" + enc`) decodes `"tem-"` into 3 invalid UTF-8 bytes `[0xb5, 0xe9, 0xbe]` ahead of the secret, causing `text(bytes)` in `retry` to return `null`. | **P1** | 1. In `realign`, strip both leading and trailing `[-_+/]` characters and split on `'-'` and `'_'` as well as `'/'` when the whole run does not decode to printable text. 2. In `retry`, if `candidate.length() % 4 == 1`, trim the trailing character before calling `decode`, and when `text(bytes)` is null because of leading/trailing prefix/suffix bytes from `offset = 1..3`, scan `new String(withoutNul(bytes), StandardCharsets.UTF_8)` if `bytes` contains a contiguous printable ASCII span of `>= 9` bytes (charging `bytes.length` to `decoded`). |

---

### (3) QUESTIONS FOR THE PRODUCT OWNER

| Question | Recommendation |
|---|---|
| None (earlier questions Q-1 and Q-2 are resolved and recorded in [`BYPASS_CATALOGUE.md`](file://<workspace-root>/docs/security/BYPASS_CATALOGUE.md#L99-L104) §8). | — |

---

### (4) Verdict

**DO NOT MERGE** (merge after fixing P0 finding D-05 and P1 findings D-06 and D-07).

---

### (5) Verbatim Instructions Received

```text
/plan REVIEW: confirmation review of pull request 17 after corrections (AGENTS.md section 9, security-sensitive: the inline
path), branch `feature/dataplane-decoding`
LENS: whether the corrections for the earlier findings D-01 to D-04 (two of them P0) close each finding without opening a
new bypass, against AGENTS.md sections 5 and 7 and docs/security/BYPASS_CATALOGUE.md.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway; its ICAP engine inspects
prompts that a web proxy forwards; a public repository). You start from a fresh context. Read AGENTS.md and ONLY the
files listed below, with the Read tool, inside this repository. Do not edit, run shell, or widen the review. Your job: for
each earlier finding, say CLOSED or OPEN with the reason; then find any new way a finding is lost beside a non-verdict, a
blocking finding ends in an allow, a response with a finding ends in 204, a base64 layer (NUL-padded, UTF-16, third
layer, prefixed, path-glued, offset) escapes the detectors, a decode or retry loop exceeds its budget or becomes
super-linear, or text is misread as a binary signature. Return exactly: (1) a table (earlier finding id, CLOSED or OPEN,
reason), (2) a DISSENT table for new findings (id, file and line or symbol, what is wrong, severity P0/P1/P2, the concrete
correction), (3) QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation), (4) a one-line verdict MERGE / MERGE
WITH CORRECTIONS / DO NOT MERGE, then (5) list every instruction you received, verbatim. Be concrete and short. Never
quote or invent an address, host name, account, serial or secret; the repository holds none and neither should your
output. English only.

Files to read, in this order:
- AGENTS.md (sections 5, 7)
- docs/reviews/PR17_2026_10_30_ARGON_DATAPLANE_DECODING.md (the earlier findings)
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
