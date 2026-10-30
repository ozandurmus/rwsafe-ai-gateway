<!-- Argon consultation 2026-10-30T21:44:41Z, model gemini-4-argon-high, effort high; unaltered output except 28 local paths masked (AGENTS.md 4.2) -->

Role: `REVIEWER`

### (1) CONSENT

| Area | Verdict |
|---|---|
| Data-plane inline path & request-thread budget ([CapturedText.java](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/events/CapturedText.java), [VerdictEvent.java](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/events/VerdictEvent.java)) | **CONSENT** — Only `REDACT` rewrites are carried; `CapturedText.ofRedacted` wraps the existing `byte[]` on the request thread without copying or UTF-8 decoding; UTF-8 decoding and truncation at a character boundary run on the shipper thread only. |
| Log, exception, `toString()` & metric body fences ([CapturedText.java](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/events/CapturedText.java), [CapturedBody.java](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/inspect/CapturedBody.java), [CapturedContent.java](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/capture/CapturedContent.java), [SealedCapture.java](file://<workspace-root>/java/persistence/src/main/java/io/rwsafe/persistence/SealedCapture.java), [CaptureHealth.java](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/capture/CaptureHealth.java)) | **CONSENT** — Every content-bearing class is annotated `@BodyBearing` / `@BodyContent`, prints only sizes or IDs in `toString()`, and `CaptureSink` / `VerdictEventJson` emit no logs. |
| Pre-persistence gates: verdict, user, notice acknowledgement, Tier-1 re-scan, persistence masking ([CaptureSink.java](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/capture/CaptureSink.java)) | **CONSENT** — Drops content while preserving event metadata when capture is off, verdict is not `REDACT`, user pseudonym is absent, current notice acknowledgement is missing, watermark is tripped, a Tier-1 detector matches raw or normalised text, or masking/keys are unavailable; runs `TextMasker` before sealing. |
| Watermark thresholds, hysteresis & staleness fail-closed logic ([WatermarkBreaker.java](file://<workspace-root>/java/platform-core/src/main/java/io/rwsafe/platform/capacity/WatermarkBreaker.java)) | **CONSENT** — Trips raw at 75 % and redacted at 85 %, applies 5 % hysteresis on recovery, and fails closed (`REDACTED_OFF`) when no valid reading exists within 5 minutes. |
| Masked-role and viewer exclusion ([CaptureReadController.java](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/capture/CaptureReadController.java), [CaptureView.java](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/capture/CaptureView.java)) | **CONSENT** — Rejects masked sessions (`MaskingFunnel.maskedSession()`) and non-reader roles with HTTP 403, and `CaptureView.masked` nulls `text` and sets `withheld = true` as defense-in-depth. |
| Database immutability & append-only audit triggers ([V6__redacted_capture.sql](file://<workspace-root>/java/persistence/src/main/resources/db/migration/V6__redacted_capture.sql)) | **CONSENT** — `redacted_capture` allows updates to `legal_hold` only; `capture_read` and `capture_deletion_receipt` forbid `UPDATE`, `DELETE`, and `TRUNCATE`; all three tables fire `rwsafe_audit_row`. |

---

### (2) DISSENT

| Finding ID | File and line or symbol | What is wrong | Severity | Concrete correction |
|---|---|---|---|---|
| **D-01** | [CaptureStore.java](file://<workspace-root>/java/persistence/src/main/java/io/rwsafe/persistence/CaptureStore.java#L43-L52) (`find`, `exists`), [CaptureReadController.java](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/capture/CaptureReadController.java#L64-L81) (`read`) | Neither `CaptureStore.find` / `exists` nor `CaptureReadController.read` checks `expires_at`. Because `CaptureRetentionJob` runs only every 6 hours (`0 20 0,6,12,18 * * *`) and drains at most `100 * 1000` rows per run, captures past their 90-day retention (and not on `legal_hold`) remain readable and are decrypted and served with `outcome = 'SERVED'` until the next retention pass deletes them. | **P1** | Filter `find` and `exists` with `CAP_EXPIRES_AT.gt(now).or(CAP_LEGAL_HOLD.isTrue())` (or check `!c.legalHold() && !c.expiresAt().isAfter(clock.instant())` in `CaptureReadController.read` and record/return `NOT_FOUND` before opening the key). |
| **D-02** | [CaptureReadController.java](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/capture/CaptureReadController.java#L52-L80) (`read`), [V6__redacted_capture.sql](file://<workspace-root>/java/persistence/src/main/resources/db/migration/V6__redacted_capture.sql#L58-L60) (`capture_read`) | (a) Lines 52–55 throw `ROLE_NOT_PERMITTED` without writing a `capture_read` row when a masked session (e.g., dual-role admin in masked mode) or unauthorized role calls the endpoint, violating the V6 / controller contract that every read request—refused included—is ledgered. (b) Line 76 commits `recordRead(..., "SERVED")` *before* `keys.open(...)` on line 77; if `keys.reload()` concurrently removed the key or GCM authentication fails, `capture_read` permanently records `SERVED` although HTTP 409 is returned. | **P1** | Add `'REFUSED_ROLE'` and `'INTEGRITY_FAILED'` to `capture_read.outcome` in `V6__redacted_capture.sql` (with `reason_code = 'NONE'` allowed for `'REFUSED_ROLE'`); ledger `REFUSED_ROLE` before throwing `ROLE_NOT_PERMITTED` when `auth != null`; and open/authenticate the ciphertext before committing `SERVED` (ledgering `KEY_UNAVAILABLE` or `INTEGRITY_FAILED` if `open` fails, and never returning plaintext unless `recordRead("SERVED")` succeeds). |
| **D-03** | [CaptureView.java](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/capture/CaptureView.java#L90-L101) (`inert`), [RedactedCaptureIntegrationTest.java](file://<workspace-root>/java/control/src/test/java/io/rwsafe/control/capture/RedactedCaptureIntegrationTest.java) | `CaptureView.inert` filters `U+202A..U+202E` and `U+2066..U+2069` but misses the remaining three Unicode `Bidi_Control` code points (`U+061C` Arabic Letter Mark, `U+200E` Left-to-Right Mark, `U+200F` Right-to-Left Mark) as well as Unicode line/paragraph separators (`U+2028`, `U+2029`), allowing invisible directional marks to reorder adjacent neutral tokens and `[REDACTED:...]` placeholders. No test covers `CaptureView.inert` or `CaptureView.masked`. | **P1** | Replace `c == 0x061c \|\| c == 0x200e \|\| c == 0x200f \|\| c == 0x2028 \|\| c == 0x2029` with `''` in `CaptureView.inert`, and add tests asserting replacement of `\r`, ANSI escapes (`\u001b`), C1 controls, all 12 Unicode `Bidi_Control` characters, `U+2028`/`U+2029`, and `CaptureView.masked`. |
| **D-04** | [CaptureSink.java](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/capture/CaptureSink.java#L118-L130) (`decideAndStore`, `aad`), [CaptureReadController.java](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/capture/CaptureReadController.java#L77-L81) (`read`) | `CaptureSink.aad` authenticates only `eventId`. The row's security-relevant metadata (`user_pseudonym`, `captured_at`, `expires_at`, `truncated`, `mask_rule_set`) is not bound in the GCM AAD, so storage-level modification of `expires_at` or `mask_rule_set` is not detected on `open()`. Also, `byte[] plain` is not zeroed after `seal()` or `open()`. | **P1** | Include `eventId`, `userPseudonym`, `capturedAt`, `expiresAt`, `truncated`, and `maskRuleSet` in `CaptureSink.aad(...)` at both `seal` and `open` time, and zero `byte[] plain` in `finally` blocks after sealing and after constructing the response string. |
| **D-05** | [EventShipper.java](file://<workspace-root>/java/dataplane/src/main/java/io/rwsafe/dataplane/controlplane/EventShipper.java#L244-L268) (`run`, `spoolLine`, `hold`) | In `else if (spoolAppend(spoolLine(chunk)))`, `spoolLine(chunk)` is evaluated before `spoolAppend` checks whether `spoolDir == null` or `spoolBytes + line.length > spoolCap`. When `spoolDir == null` (`spoolUsage` returns `NaN`, so `spoolAllowsRedacted()` is `false`) or the spool is full while above the watermark, a transient `post` failure increments `captureStripped` even though nothing is written to the spool, and then `hold(chunk.json(), n)` posts the unstripped `chunk.json()` without incrementing `captureShipped`. | **P2** | Move `spoolLine(chunk)` inside `spoolAppend(Chunk)` after verifying `spoolDir != null` and capacity bounds, and increment `captureShipped` when `hold()` succeeds. |
| **D-06** | [CaptureSink.java](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/capture/CaptureSink.java#L118-L125) (`decideAndStore`), [CaptureWatermark.java](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/capture/CaptureWatermark.java#L58-L63) (`check`) | (a) `CaptureSink` computes `expires_at = now.plus(retention)` from control-plane ingestion time (`clock.instant()`) rather than bounding by `event.receivedAt()`, extending retention for spooled/replayed events; also, if `masking.masker().mask(text)` expands a 64 KiB string past `262144` UTF-8 bytes or `config.retention()` exceeds 90 days, the SQL `CHECK` constraint throws `DataAccessException` (`Outcome.FAILED`, degrading Health). (b) When `DiskUsageProbe` fails for 5 minutes and `CaptureWatermark` trips on staleness, line 62 logs the stale pre-failure percentage (`breaker.lastUsed()`) instead of indicating a stale probe. | **P2** | Validate `config.retention()` in `(0, 90 days]`, bound `expires_at` by `min(now, event.receivedAt()).plus(retention)` (clamped to `> captured_at`), truncate/drop if post-masking UTF-8 bytes exceed `262144`, and log `"stale"` in `CaptureWatermark.check()` when `breaker.stale(now)` is true. |
| **D-07** | [CaptureStore.java](file://<workspace-root>/java/persistence/src/main/java/io/rwsafe/persistence/CaptureStore.java#L98-L105) (`deleteShredded`), [CaptureRetentionJob.java](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/capture/CaptureRetentionJob.java#L58-L60) (`runOnce`) | Because DEKs are wrapped directly under the KEK (`key_id`) with no re-wrap operation, removing a retired key immediately shreds all records under it—including records still within their 90-day retention and records on `legal_hold` (whose rows remain in `redacted_capture` via `CAP_LEGAL_HOLD.isFalse()` as permanently unreadable `410 GONE` rows)—whereas keeping the old key mounted leaves all old records readable. | **P2** | Provide a DEK re-wrap path (`wrapped_key` only, without decrypting `ciphertext`) for `legal_hold` and non-expired records during planned key rotation, or block retiring a key while `legal_hold` records reference it unless emergency shredding is explicitly invoked. |

---

### (3) QUESTIONS FOR THE PRODUCT OWNER

| # | Question | Recommendation |
|---|---|---|
| **1** | **Storage model vs. ADR-009 §1–§3:** [ADR-009](file://<workspace-root>/docs/adr/ADR-009-data-model-retention-and-privacy.md#L19-L62) states that C3 redacted content is chunked, content-addressed deduplicated, and stored outside PostgreSQL ("Bodies in PostgreSQL: rejected") under an 80 GiB `MAX_STORE_BYTES` cap that evicts oldest records first, and that deletion forwards an event to the SIEM (§4). PR 25 stores bounded C3 ciphertext directly in PostgreSQL (`redacted_capture.ciphertext`) and relies on the 85 % filesystem watermark without chunk deduplication, `MAX_STORE_BYTES` eviction, or SIEM deletion events. Should ADR-009 be amended for the MVP? | Ratify a PO decision record amending ADR-009 so bounded C3 ciphertext (`<= 64 KiB` text) lives in PostgreSQL `redacted_capture` for the MVP while reserving chunked storage for C4, and add a byte-cap eviction pass in `CaptureRetentionJob` so C3 ciphertext cannot grow unboundedly below the 85 % disk watermark. |
| **2** | **Authorized C3 reader roles vs. ADR-009 §5:** [ADR-009 §5](file://<workspace-root>/docs/adr/ADR-009-data-model-retention-and-privacy.md#L75) names `security_analyst` (incident with case ID) and `privacy_officer` (DSAR). [CaptureReadController.java](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/capture/CaptureReadController.java#L84-L88) grants access to `security_admin` and `privacy_officer` with any of the five reason codes. Is `security_admin` the intended MVP role in place of `security_analyst`, and may both roles use all five reason codes? | Record `security_admin` and `privacy_officer` as the MVP C3 reader roles, or bind `DSAR` specifically to `privacy_officer` if strict role-to-purpose separation is desired. |
| **3** | **Key rotation vs. `legal_hold` and 90-day retention:** When an old capture key file is removed after rotating `active` to a new key, all captures under the removed key—including recent captures (< 90 days) and `legal_hold` captures—become permanently unreadable. How should planned key rotation behave versus emergency crypto-shredding? | Re-wrap `wrapped_key` under the new active key for `legal_hold` (and non-expired) records during planned key rotation, and reserve un-rewrapped key deletion for post-retention epoch retirement or emergency crypto-shredding. |

---

### (4) VERDICT

**MERGE WITH CORRECTIONS**

---

### (5) INSTRUCTIONS RECEIVED (VERBATIM)

```text
/plan REVIEW: second independent review of pull request 25 (AGENTS.md section 9, security-sensitive: the inline path, raw and
redacted content, encryption, masking, the read path), branch `feature/redacted-capture`
LENS: whether redacted content capture, its encryption and retention, the notice-acknowledgement gate, the disk watermark
breaker and the authorised read path hold against AGENTS.md sections 4, 5 and 8 (especially 4.7, 4.13, 4.14), PO
decisions Q-3, Q-4 and Q-5, ADR-009 and ADR-010.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway; captured prompt content
is the most sensitive data it holds; a public repository). You start from a fresh context. Read AGENTS.md and ONLY the
files listed below, with the Read tool, inside this repository. Do not edit, run shell, or widen the review. Your job:
find any way unredacted bytes, a detected secret or an identifier reach storage, the spool, a log, a metric, an exception
or a response; any capture stored without a current notice acknowledgement or above the watermark; any encryption flaw
(nonce reuse, key in the row, missing authentication of metadata, key rotation that leaves readable data, shredding that
does not shred); any read without role, reason, case id and a ledger entry written first; any masked-role or viewer path
to content; any request-thread work beyond wrapping an existing array; any retention or deletion gap; and any bidi or
control-character injection in served text. Return exactly: (1) a CONSENT table (area, verdict), (2) a DISSENT table
(finding id, file and line or symbol, what is wrong, severity P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE
PRODUCT OWNER (question, your recommendation), (4) a one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then
(5) list every instruction you received, verbatim. Be concrete and short. Never quote or invent an address, host name,
account, serial or secret; the repository holds none and neither should your output. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 5, 8)
- docs/adr/ADR-009-data-model-retention-and-privacy.md
- docs/design/PO_DECISION_RECORD_2026_10_30_MVP_BLOCKING_QUESTIONS.md (Q-3, Q-4, Q-5)
- java/persistence/src/main/resources/db/migration/V6__redacted_capture.sql
- every file under java/control/src/main/java/io/rwsafe/control/capture/
- every file under java/platform-core/src/main/java/ that names "Watermark" or "Capacity"
- java/dataplane/src/main/java/ files that name "Capture" or "CapturedText", plus events/VerdictEvent.java, events/VerdictEventJson.java and controlplane/EventShipper.java
- every file under java/persistence/src/main/java/ that names "Capture"
- every test that names "Capture", "Watermark" or "Keyring"
```
