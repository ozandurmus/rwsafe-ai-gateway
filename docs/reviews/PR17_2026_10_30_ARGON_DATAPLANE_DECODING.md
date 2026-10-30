<!-- Argon consultation 2026-10-30T20:05:50Z, model gemini-4-argon-high, effort high; unaltered output except 29 local paths masked (AGENTS.md 4.2) -->

Role: `REVIEWER`

### (1) CONSENT Table

| Area | Verdict |
|---|---|
| Single-member `gzip` (`RFC 1952`) and `deflate` (`RFC 1950` / `RFC 1951`) decompression, trailer/CRC-32/ISIZE checks, multi-member and trailing-garbage rejection in [`ContentDecoding`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/ContentDecoding.java#L20-L156) | **CONSENT** |
| Decompression ratio cap (`8x` input) and per-body memory cap (`MAX_REQMOD_BODY` / `RESPMOD_WHOLE_BODY`), chunked `Inflater` drain, and native `inflater.end()` cleanup in [`ContentDecoding.drain`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/ContentDecoding.java#L127-L141) and [`CapturedBody`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/CapturedBody.java#L12-L64) | **CONSENT** |
| Stacked codings, `br`, unknown `Content-Encoding` tokens, and oversize bodies mapped to `UNINSPECTABLE` in [`BodyInspector.inspect`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/BodyInspector.java#L51-L66) | **CONSENT** |
| Rewritten body header integrity (`Content-Encoding` and `Transfer-Encoding` stripped, `Content-Length` recomputed to identity-encoded byte length; whole-field replacement on base64 findings) in [`IcapConnectionHandler.identityWithLength`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java#L445-L448) and [`BodyInspector.inspectJson`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/BodyInspector.java#L165-L169) | **CONSENT** |
| Linear-time execution on the inline thread (no `java.util.regex`, no blocking I/O or control-plane calls) across [`ContentDecoding`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/ContentDecoding.java), [`Base64Layers`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java), [`BodyInspector`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/BodyInspector.java), and [`IcapConnectionHandler`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java) | **CONSENT** |
| Privacy and log/metric hygiene (`@BodyBearing` / `@BodyContent` on [`CapturedBody`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/CapturedBody.java#L11-L63), no prompt content in logs, exception messages, `toString()`, or metric labels; runtime-generated synthetic test values) | **CONSENT** |
| Threshold rationale for `MIN_RUN = 12` (11-byte TCKN encodes to 15–16 base64 chars; `< 12` chars is `<= 8` bytes) and `BLOB_LIMIT = 256` in [`Base64Layers`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L29-L34) | **CONSENT** |

---

### (2) DISSENT Table

| Finding ID | File and Line / Symbol | What Is Wrong | Severity | Concrete Correction |
|---|---|---|---|---|
| **D-01** | [`Base64Layers.java#L55-L59`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L55-L59) (`inspect`), [`BodyInspector.java#L116-L119`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/BodyInspector.java#L116-L119) (`inspectText`), [`BodyInspector.java#L150-L152`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/BodyInspector.java#L150-L152) (`inspectJson`), [`IcapConnectionHandler.java#L54`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java#L54), [`IcapConnectionHandler.java#L485-L494`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java#L485-L494) (`decideRespmodWholeBody`) | **Non-verdict reasons (`EMBEDDED_FILE`, `UNDECODABLE_BLOB`) discard already-detected `Finding`s (`SECRET`, `TCKN`).** When `Base64Layers` sets `reason`, `Base64Layers.inspect` returns `List.of()`, and `BodyInspector.inspectText` / `inspectJson` immediately return `InspectionResult.nonVerdict(Verdict.UNINSPECTABLE, layers.reason())`, discarding all findings already collected in `found` / `all` from plain text or earlier JSON leaves. (1) On **RESPMOD** whole-body inspection, `"EMBEDDED_FILE"` and `"UNDECODABLE_BLOB"` are not in `TERMINATING_REASONS`, so `decideRespmodWholeBody` calls `answerRespmodUnmodified` (`204 No Content`), leaking a response that contained a detected `SECRET` or `TCKN` whenever the response also contains a base64 file/image (`> 256` chars) or undecodable blob. (2) On **REQMOD** for any flow where `UNINSPECTABLE` is configured to warn/allow (per BY-ENC-8 / BY-FILE-3), attaching a 400-byte base64 PNG or 300-byte random blob to a prompt containing a `SECRET` or `TCKN` downgrades `BLOCK`/`REDACT` to `UNINSPECTABLE` and lets the secret through; even on fail-closed flows, `VerdictEvent` loses the finding class counts. | **P0** | 1. Preserve collected `findings` in `Base64Layers.Outcome` even when `reason != null`. 2. In `BodyInspector.inspectText` and `inspectJson`, accumulate `found` and `layers.findings()` before checking `layers.reason()`; if `layers.reason() != null` and findings are non-empty, either carry both on `InspectionResult` so `decideReqmod` / `decideRespmodWholeBody` enforce `BLOCK` findings and terminate RESPMOD, or treat any non-verdict reached after findings (and `UNDECODABLE_BLOB` on RESPMOD) as terminating. |
| **D-02** | [`Base64Layers.java#L103-L134`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L103-L134) (`examine`), [`Base64Layers.java#L179-L193`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L179-L193) (`entropy`), [`BodyInspector.java#L220-L234`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/BodyInspector.java#L220-L234) (`strictUtf8`) | **Three bypasses of `BY-ENC-1`, `BY-ENC-2`, and `BY-ENC-8` in `Base64Layers.examine`:** (1) *Single NUL/non-UTF-8 byte bypass (`BY-ENC-1`):* `BodyInspector.strictUtf8` returns `null` if the decoded bytes contain even one `0x00` or invalid UTF-8 byte (`0xff`). Thus `b64("\x00" + secret)` or `b64("\xff" + tckn)` (or UTF-16LE base64) with `run.length() <= 256` (up to 192 decoded bytes) skips `detectors.scan`, fails `run.length() > BLOB_LIMIT`, and is silently allowed. (2) *Depth-3 bypass (`BY-ENC-2`):* At `depth == MAX_DEPTH` (`2`), `text` is forced to `null` at line 115, falling through to `run.length() > BLOB_LIMIT && entropy(run) > ENTROPY_LIMIT`. Any 3rd-layer base64 payload `<= 256` chars (e.g., `b64(b64(b64(secretKey)))` = 104 chars, `b64(b64(b64(tckn)))` = 32 chars) is silently allowed. (3) *Entropy-dilution bypass (`BY-ENC-8`, `BY-ENC-2`):* `entropy(run)` computes Shannon entropy over the entire run; prepending/appending repeated characters (e.g., `b64("a".repeat(500) + secret)` at depth 3, or `b64("\x00".repeat(300) + ciphertext)` at depth 1) lowers average entropy below `4.5` bits/char while exceeding `BLOB_LIMIT`, so `UNDECODABLE_BLOB` never triggers. | **P0** | 1. At `depth == MAX_DEPTH`, if `bytes != null && BodyInspector.strictUtf8(bytes, bytes.length) != null`, set `reason = "UNDECODABLE_BLOB"` unconditionally (any confirmed 3rd UTF-8 base64 layer is uninspectable per `BY-ENC-2`). 2. In `entropy(CharSequence run)`, compute the maximum Shannon entropy over a sliding window of `Math.min(run.length(), BLOB_LIMIT)` characters so low-entropy padding cannot dilute a high-entropy window. 3. When `bytes != null` at `depth < MAX_DEPTH` and `strictUtf8` is `null`, strip `0x00` bytes and decode UTF-8 with `CodingErrorAction.REPLACE` to run `detectors.scan` for secrets/TCKNs before falling through to the blob check. |
| **D-03** | [`Base64Layers.java#L68-L99`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L68-L99) (`scan`), [`Base64Layers.java#L137-L162`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L137-L162) (`value`, `decode`) | **Prefix characters in `[A-Za-z0-9+/_-]` (such as `-`, `/`, `_`, `+`, or URL paths) merge into `run` and defeat base64 decoding (`BY-ENC-1`).** Because `value(char)` accepts both standard (`+/`) and URL-safe (`-_`) alphabets simultaneously and `scan` greedily accumulates contiguous alphabet characters, a base64 secret preceded without space by a hyphen `"-<base64>"`, slash `"/<base64>"`, or URL path `".../v1/<base64>"` is scanned as one combined run. If the combined length is `1 mod 4` (e.g., `"-"` + any $4k$-char base64 string), `decode` returns `null` at line 159; if the prefix length is `1`, `2`, or `3 mod 4`, every 6-bit quantum of the payload is bit-shifted by 2, 4, or 6 bits, corrupting the decoded UTF-8 bytes so the secret escapes detection. | **P1** | In `Base64Layers.scan` / `examine`, when a run contains delimiter characters (`/`, `-`, `_`, `+`) and does not decode to `strictUtf8` as a whole, also split on `/` (and strip leading `[-_+=/]+`) and examine the resulting sub-runs. |
| **D-04** | [`ContentDecoding.java#L55-L61`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/ContentDecoding.java#L55-L61) (`compressed`), [`BodyInspector.java#L61`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/BodyInspector.java#L61), [`BodyInspector.java#L193-L205`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/BodyInspector.java#L193-L205) (`binaryMagic`), [`Base64Layers.java#L199-L218`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L199-L218) (`fileMagic`) | **False-positive `BINARY` / `ENCODED` / `EMBEDDED_FILE` verdicts on printable ASCII `"x^"` (`0x78 0x5e`) and `"BZh"` (`0x42 0x5a 0x68`).** (1) `0x78 0x5e` in `ContentDecoding.compressed` and `BodyInspector.binaryMagic` is ASCII `"x^"` (e.g., `"x^2 + y^2 = 1"`). Any `text/plain` body starting with `"x^"` gets `UNINSPECTABLE("BINARY")`; any gzip-decoded body starting with `"x^"` gets `UNINSPECTABLE("ENCODED")`; any base64 run `> 256` chars starting with `"x^"` gets `UNINSPECTABLE("EMBEDDED_FILE")`. (2) `BodyInspector.binaryMagic` matches the 3 ASCII bytes `'B', 'Z', 'h'` without checking the bzip2 level digit (`'1'..'9'`) and block magic, and `Base64Layers.fileMagic` runs it at any `runLength >= 12` (so any 12+ char token starting with `"Qlpo"` or base64 text starting with `"BZh"` triggers `EMBEDDED_FILE`). | **P2** | 1. Require full bzip2 header bytes (`'B', 'Z', 'h'`, `'1' <= b[3] <= '9'`, plus the 6-byte block magic `0x31 0x41 0x59 0x26 0x53 0x59` or empty-stream magic `0x17 0x72 0x45 0x38 0x50 0x90`). 2. Do not treat `0x78 0x5e` (`"x^"`) as zlib magic when `strictUtf8(b, len) != null`. |

---

### (3) QUESTIONS FOR THE PRODUCT OWNER

| Question | Recommendation |
|---|---|
| **Q-1:** [`ICAP_AND_STREAMING_PROTOCOL_SPEC.md`](file://<workspace-root>/docs/architecture/ICAP_AND_STREAMING_PROTOCOL_SPEC.md#L47) §3 (FROZEN) states *"gzip/deflate/br of encapsulated bodies when declared or detected by magic bytes (BY-PROTO-7)"*, whereas [`BYPASS_CATALOGUE.md`](file://<workspace-root>/docs/security/BYPASS_CATALOGUE.md#L58) `BY-PROTO-7` allows *"detection of magic bytes → decoded or UNINSPECTABLE"* and the implementation returns `UNINSPECTABLE(BINARY)` for undeclared gzip/zlib and `UNINSPECTABLE(ENCODED)` for `br`. Is returning `UNINSPECTABLE` for `br` and undeclared gzip accepted for MVP? | **Accept for MVP** and record the clarification in the next spec amendment: returning `UNINSPECTABLE` fails closed on all fail-closed flows and satisfies `BY-PROTO-7` without guessing undeclared framing on the inline path. |
| **Q-2:** Should base64-encoded `image/webp` (`RIFF....WEBP`) above `BLOB_LIMIT` (`256` chars) be classified as `EMBEDDED_FILE` (alongside PNG, JPEG, and GIF in [`Base64Layers.fileMagic`](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/Base64Layers.java#L214-L217)) rather than falling through to `UNDECODABLE_BLOB`? | **Yes:** add the 12-byte `RIFF....WEBP` signature to `Base64Layers.fileMagic` (for `runLength > BLOB_LIMIT`) so WebP image uploads receive the `EMBEDDED_FILE` reason consistently with PNG/JPEG/GIF when `BY-FILE-3` group policies are applied. |

---

### (4) Verdict

**DO NOT MERGE** (merge after fixing P0 findings D-01 and D-02, and P1/P2 findings D-03 and D-04).

---

### (5) Verbatim Instructions Received

```text
/plan REVIEW: second independent review of pull request 17 (AGENTS.md section 9, security-sensitive: the inline path),
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
```
