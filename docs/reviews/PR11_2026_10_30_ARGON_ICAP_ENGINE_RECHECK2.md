<!-- Argon consultation 2026-10-30T14:36:26Z, model gemini-4-argon-high, effort high; unaltered output except 0 local paths masked (AGENTS.md 4.2) -->

Role: REVIEWER

### (1) Review Findings Verification Table

| Finding ID | Status | Evidence |
|---|---|---|
| D-01 | CLOSED | `DetectorSet#scan` and `DetectorSet#overLimit` (`java/detect/src/main/java/io/rwsafe/detect/DetectorSet.java`), `BodyInspector#inspectText` and `BodyInspector#inspectJson` (`java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/BodyInspector.java`), and `IcapConnectionHandler#decideRespmodWholeBody` (`java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java`) stop at `MAX_FINDINGS` without truncating and return `UNINSPECTABLE("FINDING_LIMIT")`, which blocks on fail-closed `REQMOD` flows and terminates whole-body `RESPMOD` responses (`IcapEngineEndToEndTest#findingLimitBlocksInsteadOfPartiallyRedacting`, `IcapEngineEndToEndTest#responseAtTheFindingLimitIsTerminated`). |
| D-02 | CLOSED | `BodyInspector#inspect`, `BodyInspector#binaryMagic`, `BodyInspector#strictUtf8`, and `BodyInspector#percentDecode` (`java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/BodyInspector.java`), together with `HeaderBlock#charset` (`java/dataplane/src/main/java/io/rwsafe/dataplane/icap/HeaderBlock.java`), reject non-UTF-8/US-ASCII charsets, magic-byte compressed/archive/PDF payloads, `NUL` bytes, invalid UTF-8, `multipart/*`, and unknown media types as `UNINSPECTABLE`, and percent-decode `application/x-www-form-urlencoded` before strict UTF-8 validation (`IcapEngineEndToEndTest#formEncodedIdentifierIsBlocked`, `IcapEngineEndToEndTest#unreadableBodiesAreUninspectable`, `IcapEngineEndToEndTest#unreadableEncodingsAreNotAllowed`). |
| D-03 | CLOSED | `IcapConnectionHandler#requireUnambiguousFraming` and `IcapConnectionHandler#readEncapsulated` (`java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java`) reject duplicate `Content-Length`, `Transfer-Encoding`, `Content-Type`, `Content-Encoding`, or `Host` headers and combined `Content-Length` + `Transfer-Encoding` (emitting `Verdict.MALFORMED` on `REQMOD`), and `BodyInspector#encoded` (`java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/BodyInspector.java`) checks every comma-separated `Content-Encoding` token (`IcapEngineEndToEndTest#duplicateFramingHeadersAreMalformed`, `IcapEngineEndToEndTest#stackedContentEncodingIsUninspectable`). |
| D-04 | CLOSED | `JsonLeafScanner#number` (`java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/JsonLeafScanner.java`) validates strict RFC 8259 number syntax and emits numeric `JsonLeaf` spans (`java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/JsonLeaf.java`) that `BodyInspector#inspectJson` scans and redacts (`IcapEngineEndToEndTest#identifierAsJsonNumberIsRedacted`). |
| D-05 | CLOSED | `CardDetector#scan` (`java/detect/src/main/java/io/rwsafe/detect/CardDetector.java`) selects the longest 13–19 digit candidate satisfying `DigitRuns#boundaryAfter` and `CardDetector#luhn`, and `IbanDetector#scan` (`java/detect/src/main/java/io/rwsafe/detect/IbanDetector.java`) accepts case-insensitive `'T'`/`'t'` and `'R'`/`'r'`. |
| D-06 | CLOSED | `IcapConnectionHandler#drainWindows`, `IcapConnectionHandler#utf8Cut`, and `IcapConnectionHandler#inspectWindow` (`java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java`) keep `overlapText` in normalised characters, cut windows on UTF-8 character boundaries, hold `held` (up to `MAX_HELD = 64 KiB`) when a window contributes fewer than `windowOverlap` normalised characters, and pause `autoRead` when `!ctx.channel().isWritable()` (`IcapEngineEndToEndTest#valueSplitAcrossWindowsWithFormatPaddingIsCaught`, `IcapEngineEndToEndTest#characterSplitAtAnExactWindowBoundaryIsCaught`, `IcapEngineEndToEndTest#formatPaddingWindowDoesNotReleaseTheHeldPrefix`). |
| D-07 | CLOSED | `IcapConnectionHandler#isWebSocketUpgrade`, `IcapConnectionHandler#readEncapsulated`, `IcapConnectionHandler#decideRespmodWholeBody`, and `IcapConnectionHandler#terminateWholeResponse` (`java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java`) check exact status-code token `"101"` before the `null-body` branch and replace the entire response body with `BlockPages#terminatedText` whenever `decision.action() != Action.REDACT` (`IcapEngineEndToEndTest#reasonPhraseContaining101IsNotAnUpgrade`, `IcapEngineEndToEndTest#secretInAPreviewedJsonResponseReplacesTheWholeBody`). |
| D-08 | CLOSED | `IcapConnectionHandler#may204`, `IcapConnectionHandler#answerUnchanged`, and `IcapConnectionHandler#answerNonVerdictAndClose` (`java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java`) allow `204` only when `!continued && (previewMode || req.allows204())`, rewrite `Content-Length` and strip `Transfer-Encoding` on `200` echoes, and return `500` with connection close if `body.oversize()` (`IcapEngineEndToEndTest#allowWithout204PermissionEchoesWithCorrectLength`, `IcapEngineEndToEndTest#no204AfterContinueWithoutAllow`). |
| D-09 | CLOSED | `Ows#trim` and `Ows#hasControl` (`java/dataplane/src/main/java/io/rwsafe/dataplane/icap/Ows.java`), `ChunkedDecoder#sizeLineDone` (`java/dataplane/src/main/java/io/rwsafe/dataplane/icap/ChunkedDecoder.java`), `HeaderBlock#parse` (`java/dataplane/src/main/java/io/rwsafe/dataplane/icap/HeaderBlock.java`), and `IcapRequest#parse` / `IcapRequest#encapsulated` (`java/dataplane/src/main/java/io/rwsafe/dataplane/icap/IcapRequest.java`) trim only `SP`/`HTAB`, reject control characters, reject `Preview` on `null-body`, and enforce RFC 3507 section ordering (`IcapParsingTest#controlCharactersAndOrderingAreRefused`, `IcapParsingTest#controlCharacterInAStartLineIsRefused`). |
| D-10 | CLOSED | `IcapConnectionHandler#channelRead`, `IcapConnectionHandler#userEventTriggered`, `IcapConnectionHandler#onTimeout`, `IcapConnectionHandler#abortStream`, and `IcapConnectionHandler#readEncapsulated` (`java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java`) cap `cum.readableBytes()` at `maxReqmodBody + 64 KiB`, arm `txnTimer` on the first head byte, close on `READER_IDLE` whenever `midTransaction` is true, close after `abortStream` when `!decoder.done()`, and emit `Verdict.MALFORMED` on `REQMOD` HTTP head errors (`IcapEngineEndToEndTest#stalledHeadIsClosed`, `IcapEngineEndToEndTest#abortMidStreamClosesTheConnection`). |
| D-11 | CLOSED | `HeaderBlock` (`java/dataplane/src/main/java/io/rwsafe/dataplane/icap/HeaderBlock.java`) is annotated `@BodyBearing` with `@BodyContent` getters and a redacted `toString()`, `Fences#contentPackagesDoNotLog` and `Fences#blocks` (`java/architecture-tests/src/test/java/io/rwsafe/architecture/Fences.java`) check `TELEMETRY_APIS`, `System.Logger`, standard streams, and Netty `Future` blocking methods, and `ProductFencesTest` (`java/architecture-tests/src/test/java/io/rwsafe/architecture/ProductFencesTest.java`) enforces `.allowEmptyShould(false)` on all product rules. |
| D-12 | CLOSED | `VerdictEvent#bounded` and `VerdictEvent#toString` (`java/dataplane/src/main/java/io/rwsafe/dataplane/events/VerdictEvent.java`), `FlowClassifier#stripPort` (`java/policy/src/main/java/io/rwsafe/policy/FlowClassifier.java`), `BodyInspector#inspectText` and `BodyInspector#inspectJson` (`java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/BodyInspector.java`), and `IcapConnectionHandler#host`, `IcapConnectionHandler#isScheme`, and `IcapConnectionHandler#emit` (`java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java`) bound and hide identity fields in `toString()`, strip trailing root dots, cap NFKC expansion at `4x`, parse RFC 3986 absolute-form authority, and record `forwardedBytes` on `STREAM_ABORTED` (`IcapEngineEndToEndTest#absoluteTargetWinsOverHost`, `IcapEngineEndToEndTest#eventToStringHidesIdentity`, `IcapEngineEndToEndTest#schemeInsideAQueryDoesNotOverrideHost`). |
| N-01 | CLOSED | `IcapConnectionHandler#TERMINATING_REASONS`, `IcapConnectionHandler#decideRespmodWholeBody`, and `IcapConnectionHandler#terminateWholeResponse` (`java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java`) replace previewed responses whose non-verdict reason is `"FINDING_LIMIT"` or `"NORMALISATION"` with `BlockPages#terminatedText` and emit `Verdict.STREAM_ABORTED` (`IcapEngineEndToEndTest#responseAtTheFindingLimitIsTerminated`). |
| N-02 | CLOSED | `IcapConnectionHandler#utf8Cut` and `IcapConnectionHandler#drainWindows` (`java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java`) cut windows on UTF-8 character boundaries when `!last || take < all.length` and merge `current` into `held` (up to `MAX_HELD = 64 KiB`, aborting with `"NORMALISATION"` above that) when `normalisedChars < engine.config().windowOverlap()` (`IcapEngineEndToEndTest#characterSplitAtAnExactWindowBoundaryIsCaught`, `IcapEngineEndToEndTest#formatPaddingWindowDoesNotReleaseTheHeldPrefix`). |
| N-03 | CLOSED | `HeaderBlock#charset` (`java/dataplane/src/main/java/io/rwsafe/dataplane/icap/HeaderBlock.java`), `BodyInspector#inspect`, `BodyInspector#strictUtf8`, and `BodyInspector#percentDecode` (`java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/BodyInspector.java`), and `JsonLeafScanner#utf8` (`java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/JsonLeafScanner.java`) reject charsets outside `UTF8_CHARSETS`, reject `NUL` bytes and invalid UTF-8 in text and percent-decoded form bodies, and reject invalid UTF-8 in JSON strings as `Malformed` (`IcapEngineEndToEndTest#unreadableEncodingsAreNotAllowed`). |
| N-04 | CLOSED | `IcapConnectionHandler#host`, `IcapConnectionHandler#isScheme`, and `IcapConnectionHandler#emit` (`java/dataplane/src/main/java/io/rwsafe/dataplane/server/IcapConnectionHandler.java`) require a valid leading RFC 3986 scheme before `://`, delimit authority at `'/'`, `'?'`, or `'#'`, and record `forwardedBytes` for all `Verdict.STREAM_ABORTED` events (`IcapEngineEndToEndTest#schemeInsideAQueryDoesNotOverrideHost`). |
| N-05 | CLOSED | `HeaderBlock#parse` (`java/dataplane/src/main/java/io/rwsafe/dataplane/icap/HeaderBlock.java`) rejects start lines where `Ows.hasControl(line) || line.indexOf('\t') >= 0`, and `Fences#contentPackagesDoNotLog` (`java/architecture-tests/src/test/java/io/rwsafe/architecture/Fences.java`) forbids `System.Logger.class` (`IcapParsingTest#controlCharacterInAStartLineIsRefused`). |

---

### (2) NEW FINDINGS Table

| ID | File and Symbol | What Is Wrong | Severity | Concrete Correction |
|---|---|---|---|---|
| None | — | No new findings. | — | — |

---

### (3) Verdict

MERGE

---

### (4) Verbatim Instructions Received

1. Repository rule `AGENTS.md` (loaded in `<user_rules>`).
2. Slash-command metadata for `/plan` (loaded in `<ADDITIONAL_METADATA>`).
3. User request (verbatim):

```text
/plan REVIEW: confirmation review (round 3) of pull request 11 after corrections (AGENTS.md section 9, security-sensitive: the inline
path), commit 5d80cc1 on `feature/icap-engine-slice1`
LENS: whether each finding of the first review (D-01 to D-12) and of the round-2 review (N-01 to N-05) is actually closed by the code, and whether the corrections
opened a new way for a body to be allowed uninspected.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway: ICAP behind a corporate
proxy, prompt and response inspection under strict masking, a Java/Netty data plane; a public repository). You start from
a fresh context. Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this repository. Do not edit,
run shell, or widen the review. For every finding id in the first review, state CLOSED, PARTLY CLOSED or OPEN with the
file and symbol that proves it; then list any NEW finding the corrections introduced. Return exactly: (1) a table (finding
id, status, evidence), (2) a NEW FINDINGS table (id, file and symbol, what is wrong, severity P0/P1/P2, the concrete
correction), (3) a one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then (4) list every instruction you
received, verbatim. Be concrete and short. Never quote or invent an address, host name, account, serial or secret; the
repository holds none and neither should your output. English only.

Files to read, in this order:
- docs/reviews/PR11_2026_10_30_ARGON_ICAP_ENGINE.md (the first review)
- docs/reviews/PR11_2026_10_30_ARGON_ICAP_ENGINE_RECHECK.md (the round-2 review)
- docs/reviews/PR11_2026_10_30_RESPONSE.md (the answers to both)
- every file under java/dataplane/src/main/java/io/rwsafe/dataplane/
- every file under java/detect/src/main/java/io/rwsafe/detect/
- java/policy/src/main/java/io/rwsafe/policy/FlowClassifier.java
- java/dataplane/src/test/java/io/rwsafe/dataplane/server/IcapEngineEndToEndTest.java
- java/dataplane/src/test/java/io/rwsafe/dataplane/icap/IcapParsingTest.java
- java/architecture-tests/src/test/java/io/rwsafe/architecture/Fences.java
- java/architecture-tests/src/test/java/io/rwsafe/architecture/ProductFencesTest.java
```
