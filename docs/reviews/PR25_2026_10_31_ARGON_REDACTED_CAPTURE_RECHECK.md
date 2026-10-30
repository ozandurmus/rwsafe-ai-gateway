<!-- Argon consultation 2026-10-30T22:23:41Z, model gemini-4-argon-high, effort high; unaltered output except 0 local paths masked (AGENTS.md 4.2) -->

Role: `REVIEWER`

### (1) EARLIER FINDINGS AND QUESTIONS

| Earlier finding or question | Status | Reason |
|---|---|---|
| **D-01** (P1 — expired captures served before retention job runs) | **CLOSED** | `CaptureStore.findLive(eventId, now)` filters with `CAP_EXPIRES_AT.gt(now).or(CAP_LEGAL_HOLD.isTrue())`, and `CaptureReadController.read` ledgers `NOT_FOUND` and returns HTTP 404 before unwrapping keys or reading chunks. Covered by `CaptureStoreTest.expiredRecordsAreNeverFoundAndRetentionDeletesThemWithAReceipt` and `RedactedCaptureIntegrationTest.expiredOrTamperedRecordsAreNeverServed`. |
| **D-02** (P1 — role/masked refusals not ledgered; `SERVED` committed before `open()`) | **CLOSED** | `V8__redacted_capture.sql` adds `REFUSED_ROLE` and `INTEGRITY_FAILED` to `capture_read.outcome`; `CaptureRefusalLedger` and `CaptureReadController.read` ledger `REFUSED_ROLE` for masked sessions, unauthorized roles, and non-`privacy_officer` `DSAR` requests; `vault.open(c)` runs before `recordRead(..., "SERVED")`, ledgering `KEY_UNAVAILABLE` (410) or `INTEGRITY_FAILED` (409) on failure and zeroing `plain` if `recordRead` fails. |
| **D-03** (P1 — incomplete Bidi/separator filtering in `CaptureView.inert`) | **CLOSED** | `CaptureView.inert` strips `\r` and replaces C0 controls (except `\n` and `\t`), `DEL`, C1 controls (`0x7f..0x9f`), all 12 Unicode `Bidi_Control` characters (`U+061C`, `U+200E`, `U+200F`, `U+202A..U+202E`, `U+2066..U+2069`), and `U+2028`/`U+2029` with `U+FFFD`. Covered by `ChunkerAndViewTest.servedTextIsInert` and `theMaskedProjectionWithholdsTheText`. |
| **D-04** (P1 — metadata not authenticated; plaintext buffers not zeroed) | **CLOSED** | Each chunk's AES-256-GCM tag binds `rwsafe-c3-chunk-v1|<address>`, each wrapped key binds `rwsafe-capture-key|<keyId>|<purpose>`, and each record's `manifest_mac` (HMAC-SHA256 under a per-record wrapped key) binds `eventId`, `userPseudonym`, `capturedAt`, `expiresAt`, `truncated`, `maskRuleSet`, `plainBytes`, and the ordered chunk addresses. Plaintext, DEK, and record-key byte arrays are zeroed in `finally` blocks. |
| **D-05** (P2 — `EventShipper` premature `captureStripped` increment and missing `captureShipped` on `hold`) | **CLOSED** | `EventShipper.spoolChunk` checks `spoolDir == null` first and increments `captureStripped` only when `spoolAppend` succeeds; `run()` increments `captureShipped` when `hold()` succeeds. Covered by `CaptureShippingTest.withoutASpoolAHeldChunkShipsItsContentAndNothingIsCountedStripped`. |
| **D-06** (P2 — retention calculated from ingestion time; post-masking size/expiry throwing SQL exceptions; stale watermark log) | **CLOSED** | `CaptureSink.decideAndStore` computes `expiresAt` from `min(now, event.receivedAt()).plus(config.retention())`, returns counted outcomes `EXPIRED`, `EMPTY`, and `TOO_LARGE` (`> 262144` post-masking UTF-8 bytes) without throwing, `V8__redacted_capture.sql` enforces `expires_at <= captured_at + interval '90 days'`, and `CaptureWatermark.check` logs a dedicated stale message when `breaker.stale(now)` is true. |
| **D-07** (P2 — key rotation vs. shredding for live and `legal_hold` records) | **CLOSED** | Addressed together with Q-3 via envelope DEK/record-key re-wrapping (`CaptureKeyring.rewrap`, `CaptureRetentionJob.rewrap`, `CaptureStore.applyRewrap`) and explicit emergency shredding via the Secret's `shredded` list (`CaptureStore.deleteShredded`), subject to the pagination/filtering correction in **D-09** below. |
| **Q-1** (Storage model vs. ADR-009 §1–§3) | **CLOSED** | Implemented per ADR-009: content-defined Gear chunking (`Chunker`, 8–64 KiB), keyed HMAC-SHA256 addressing (`CaptureKeyring.address`, preventing unkeyed existence-oracle lookups), per-chunk AES-256-GCM files outside PostgreSQL (`ChunkFiles`), trigger-maintained `ref_count` and `capture_store_usage`, `MAX_STORE_BYTES` oldest-first eviction (`StoreCap`), and SIEM-exportable audit/receipt rows (`SiemRecords`). |
| **Q-2** (Authorized C3 reader roles vs. ADR-009 §5) | **CLOSED** | `security_admin` and `privacy_officer` are enforced as the MVP C3 reader roles, with `DSAR` restricted to `privacy_officer` (`REASON_NOT_PERMITTED_FOR_ROLE`, ledgered as `REFUSED_ROLE`). |
| **Q-3** (Planned key rotation vs. emergency crypto-shredding) | **CLOSED** | Planned rotation re-wraps record and chunk keys under `active` without decrypting chunk files and logs `REWRAP` key events; emergency crypto-shredding uses the Secret's `shredded` list to revoke key usage immediately, delete non-held records with `KEY_SHREDDED` receipts and `EMERGENCY_SHRED` key events, and retain held rows as unreadable. |

---

### (2) DISSENT

| Finding ID | File and line or symbol | What is wrong | Severity | Concrete correction |
|---|---|---|---|---|
| **D-08** | `java/control/src/main/java/io/rwsafe/control/capture/CaptureSink.java` lines 134–146 (`decideAndStore`), `java/control/src/main/java/io/rwsafe/control/capture/CaptureVault.java` lines 106–140 (`prepare`), `java/persistence/src/main/java/io/rwsafe/persistence/CaptureStore.java` lines 117–138 (`insert`) | `vault.prepare(plain, plain.length)` queries `existingChunks(addresses)` outside the insert transaction and sets `wrappedKey = null, storedBytes = 0` for any chunk currently in `capture_chunk`. Next, `cap.makeRoom(prepared.newBytes())` runs (or `CaptureRetentionJob` runs concurrently) and can evict/delete the old record that held the last reference to that deduplicated chunk, deleting its `capture_chunk` row and file before `prepared.store(...)` starts its transaction. `CaptureStore.insert` then hits `id == null`, finds no row in `SELECT ... FOR UPDATE`, and throws `IllegalStateException("a referenced chunk is no longer stored")`, causing `CaptureSink.accept` to drop the capture with `Outcome.FAILED` and degrade Health. | **P2** | When `CaptureStore.insert` finds that a deduplicated chunk (`c.wrappedKey() == null`) was deleted between `existingChunks` and `SELECT ... FOR UPDATE` (or when `cap.makeRoom` had to evict records), throw a dedicated retryable exception (or return a status) and have `CaptureSink.decideAndStore` re-run `vault.prepare` + `cap.makeRoom` + `prepared.store` once so the newly missing chunk is sealed, counted in `newBytes`, and stored cleanly. |
| **D-09** | `java/control/src/main/java/io/rwsafe/control/capture/CaptureRetentionJob.java` lines 98–137 (`rewrap`), `java/persistence/src/main/java/io/rwsafe/persistence/CaptureStore.java` lines 264–278, 321–329 (`recordsToRewrap`, `chunksToRewrap`, `totals`), `java/control/src/main/java/io/rwsafe/control/capture/CaptureHealth.java` lines 64–73 (`store`) | `recordsToRewrap` and `chunksToRewrap` select `CAP_KEY_ID.ne(activeKeyId)` / `CH_KEY_ID.ne(activeKeyId)` with `ORDER BY event_id / chunk_id LIMIT 500` without restricting `key_id` to mounted keys (`keys.ids()`). If `legal_hold` records (and their referenced chunks) remain under a previously shredded or unmounted key, they are never updated by `applyRewrap` and are re-selected on every pass; 500 such rows sorting first cause `n == 0` on pass 0 and starve re-wrapping of rotatable keys. In addition, `CaptureStore.totals` counts held rows under shredded keys in `recordsUnderOtherKeys` / `chunksUnderOtherKeys`, keeping `CaptureHealth` permanently `DEGRADED` (`rotationPending = true`) after an emergency shred of a key that had a held record. | **P2** | Filter `recordsToRewrap` and `chunksToRewrap` by mounted non-active keys (`CAP_KEY_ID.in(rotatableKeys)` where `rotatableKeys = keys.ids() - active`), and in `CaptureStore.totals` (and `CaptureRetentionJob.rewrap`) count rows under mounted non-active keys separately from stranded/shredded-held rows (`notIn(keys.ids())`). |

---

### (3) QUESTIONS FOR THE PRODUCT OWNER

None.

---

### (4) VERDICT

**MERGE WITH CORRECTIONS**

---

### (5) INSTRUCTIONS RECEIVED (VERBATIM)

```text
/plan REVIEW: confirmation review of pull request 25 after corrections (AGENTS.md section 9, security-sensitive: the inline path, raw and
redacted content, encryption, masking, the read path), branch `feature/redacted-capture`
LENS: whether the corrections for D-01 to D-07 and the three answered questions (storage outside PostgreSQL per ADR-009, reader roles, key rotation versus shredding) close each finding, and whether redacted content capture, its encryption and retention, the notice-acknowledgement gate, the disk watermark
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
control-character injection in served text. For each earlier finding and question say CLOSED or OPEN with the reason. Also check the chunk store: content-addressing that could act as an existence oracle, reference counting under concurrency, eviction order, deletion that leaves orphan chunk files, re-wrap without decryption, and the shred list. Return exactly: (1) a table (earlier finding or question, CLOSED or OPEN, reason), (2) a DISSENT table for new findings
(finding id, file and line or symbol, what is wrong, severity P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE
PRODUCT OWNER (question, your recommendation), (4) a one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then
(5) list every instruction you received, verbatim. Be concrete and short. Never quote or invent an address, host name,
account, serial or secret; the repository holds none and neither should your output. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 5, 8)
- docs/reviews/PR25_2026_10_31_ARGON_REDACTED_CAPTURE.md (the earlier findings)
- docs/reviews/PR25_2026_10_31_RESPONSE.md
- docs/adr/ADR-009-data-model-retention-and-privacy.md
- docs/design/PO_DECISION_RECORD_2026_10_30_MVP_BLOCKING_QUESTIONS.md (Q-3, Q-4, Q-5)
- java/persistence/src/main/resources/db/migration/V8__redacted_capture.sql
- every file under java/control/src/main/java/io/rwsafe/control/capture/
- every file under java/platform-core/src/main/java/ that names "Watermark" or "Capacity"
- java/dataplane/src/main/java/ files that name "Capture" or "CapturedText", plus events/VerdictEvent.java, events/VerdictEventJson.java and controlplane/EventShipper.java
- every file under java/persistence/src/main/java/ that names "Capture"
- java/control/src/main/java/io/rwsafe/control/siem/SiemRecords.java
- every test that names "Capture", "Watermark" or "Keyring"
```
