<!-- Argon consultation 2026-10-30T21:07:22Z, model gemini-4-argon-high, effort high; unaltered output except 0 local paths masked (AGENTS.md 4.2) -->

Role: `REVIEWER`

### (1) CONSENT

| Area | Verdict |
|---|---|
| Language law (AGENTS.md §3) — Turkish end-user catalogue under `end-user-tr.properties` and `docs/i18n/tr/`, English keys, identifiers and code | **PASS** (with `docs/i18n/tr/exception_request.md` heading noted in D-04) |
| XSS, HTML/JSON/SSE escaping and self-contained rendering (`EndUserPages`, `BlockPages`, PRIV-2) — UTF-8, `lang="tr"`, strict CSP (`default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'`), `no-referrer`, `policy_link` rendered as plain text, no external resources | **PASS** |
| Prompt content, identity and estate value isolation (AGENTS.md §4.2, §4.7, §4.8, §4.10, §4.14) — `AcknowledgementPayload.toString()` omits `userClaim`, error responses name index and field only, `NoticeView.masked` strips `sections` so configured estate parameters never reach `replay_viewer`, `/api/v1/notice/acknowledgements` accepts `^USR-[0-9a-f]{10}$` only, intake returns HTTP 503 when the privacy key is missing | **PASS** |
| Data-plane law (AGENTS.md §5) — `BlockPages` loads catalogue and environment once at class initialisation, performs no I/O on the request thread, and uses linear character loops with no `java.util.regex` | **PASS** |
| Persistence immutability and audit ledger (`V5__notice_acknowledgement.sql`, C12) — pseudonymous storage (`^USR-[0-9a-f]{10}$`), version and source `CHECK` constraints, idempotent `(user_pseudonym, notice_version, source)` uniqueness, `BEFORE UPDATE` and `BEFORE TRUNCATE` append-only triggers, `AFTER INSERT OR DELETE` audit trigger | **PASS** |
| Port and RBAC confinement (`SecurityConfig`, `NoticeIntakeController`, `NoticeApiController`) — `/internal/v1/notice-acknowledgements` confined to the internal capture-sink port (8092), `/api/v1/notice/**` read-only for authenticated roles and routed through the masking funnel for `replay_viewer` | **PASS** |
| Personal account login block (Q-6) and vendor transfer instrument block (Q-33) — `PERSONAL_ACCOUNT` and `VENDOR_INSTRUMENT_MISSING` map cleanly to `BlockKind.PERSONAL` and `BlockKind.PLATFORM` without recording or echoing personal account identifiers or content | **PASS** |

---

### (2) DISSENT

| Finding ID | File and Line / Symbol | What is Wrong | Severity | Concrete Correction |
|---|---|---|---|---|
| **D-01** | `java/platform-core/src/main/resources/io/rwsafe/platform/enduser/end-user-tr.properties:93` and `docs/i18n/tr/notice_first_use.md:97` (`notice.acknowledge.text`) | Sentence 2 states that the record is neither approval (`onay`) nor consent (`rıza`), but Sentence 3 immediately uses `"onayladıysanız"` ("if you approved") for the HR policy record (`"Kurumun insan kaynakları politikasını bu sürümle onayladıysanız o kayıt da aynı anlamı taşır."`), blurring notice acknowledgement with approval/consent against Q-32 and Q-35. | **P1** | Replace `"onayladıysanız"` in `notice.acknowledge.text` (in both `end-user-tr.properties` and `docs/i18n/tr/notice_first_use.md`, bumping `catalogue.version` if required) with notice-acknowledgement wording: `"Kurumun insan kaynakları politikası kapsamında bu sürümü okuduğunuz kayda geçtiyse o kayıt da aynı anlamı taşır."` |
| **D-02** | `java/platform-core/src/main/resources/io/rwsafe/platform/enduser/end-user-tr.properties:73-75,80,86` and `docs/i18n/tr/notice_first_use.md:29-35,53,73` (`notice.data.text`, `notice.raw.text`, `notice.basis.text`, `notice.retention.text`) | Under `notice.data.heading`, `notice.data.text` states `"Bulunan hassas bilginin kendisi kaydedilmez, yalnızca türü kaydedilir"`, while the next paragraph `notice.raw.text` (and `notice.retention.text`) refers to `"İçeriğin değiştirilmemiş hâli"` ("unmodified form of the content"). Per AGENTS.md §4.13, detected secrets and PII are redacted before persistence even for raw prompt capture; calling it `"değiştirilmemiş"` contradicts `notice.data.text` and AGENTS.md §4.13. In addition, `notice.basis.text` names the legal basis for usage metadata/verdicts (art. 5/2-ç) and masked content (art. 5/2-f), but omits the full-content capture tier described in `notice.raw.text`. | **P1** | Reword `notice.raw.text` and `notice.retention.text` so the employee is told that even when full content is retained under an approved capture mode, detected secrets and identifying data are redacted before storage (AGENTS.md §4.13), and include that tier explicitly in the art. 5/2-f clause of `notice.basis.text`. |
| **D-03** | `java/control/src/main/java/io/rwsafe/control/notice/NoticeAcknowledgementService.java:60-79,108-136` (`record`, `validate`) | `validate` checks only the syntactic shape `^[a-z]{2}-[0-9]{1,4}-[0-9a-f]{8}$` of `noticeVersion` and permits `acknowledgedAt` back to `2026-01-01T00:00:00Z` for all sources. It does not require `notice.currentVersion()` to be present when recording interactive acknowledgements (`banner`, `ide_first_run`, `gateway_credential_issue`), nor does it require those live sources to carry `notice.currentVersion()`. A batch submitted while the notice is incomplete (unshown) or carrying a precomputed version string will be persisted and will open `contentCaptureAllowed` once that version is active. | **P1** | In `NoticeAcknowledgementService.validate`, require `notice.currentVersion()` to be present and require live sources (`banner`, `ide_first_run`, `gateway_credential_issue`) to match `notice.currentVersion().get()` (or a tighter timestamp window around `now`), allowing historical versions and older `acknowledgedAt` dates only for `directory_attribute` (Q-35). |
| **D-04** | `java/platform-core/src/main/resources/io/rwsafe/platform/enduser/end-user-tr.properties:26`, `docs/i18n/tr/block_page.md:31`, and `java/dataplane/src/main/java/io/rwsafe/dataplane/server/BlockPages.java:27-28` (`block.class.noexception`, `FAIL_CLOSED_CATEGORIES`) | `BlockPages.FAIL_CLOSED_CATEGORIES` maps four categories (`secret`, `customer_data`, `special_category`, `internal_identity`) to `BlockKind.CLASS`, which always renders `block.class.noexception`. However, `block.class.noexception` lists only three categories (`müşteri sırları, gizli bilgiler ve özel nitelikli kişisel veriler`) and omits `class.internal_identity` (`kurum içi kimlik bilgisi`). | **P2** | Add `kurum içi kimlik bilgileri` to `block.class.noexception` in `end-user-tr.properties` and `docs/i18n/tr/block_page.md` (unless the PO decides `internal_identity` is not a fail-closed no-exception class). |
| **D-05** | `docs/i18n/tr/exception_request.md:1-7` and `java/platform-core/src/test/java/io/rwsafe/platform/enduser/EndUserCatalogueDocsTest.java:63-83` (`read`) | `docs/i18n/tr/exception_request.md` uses a Turkish top-level heading (`# İstisna talebi`) instead of English (AGENTS.md §3), does not state that fail-closed classes have no exception (PC-5), and has no `## \`key\`` sections, which causes `EndUserCatalogueDocsTest.read` to silently ignore the entire file (`key` remains `null`). | **P2** | Give `docs/i18n/tr/exception_request.md` an English `#` title and note stating that exceptions never apply to fail-closed classes, and make `EndUserCatalogueDocsTest.read` assert that every `.md` file under `docs/i18n/tr/` (except an explicitly named draft file) defines at least one `## \`key\`` section. |
| **D-06** | `java/platform-core/src/main/java/io/rwsafe/platform/enduser/EndUserPages.java:146-167` (`noticeVersion`) and `java/control/src/main/java/io/rwsafe/control/notice/NoticeApiController.java:42-51` (`forUser`) | `EndUserPages` is immutable, yet `noticeVersion()` re-renders all 11 notice sections and recomputes SHA-256 on every call, including every call to `NoticeAcknowledgementService.contentCaptureAllowed`. In addition, `NoticeApiController.forUser` executes two separate DB queries (`contentCaptureAllowed` and `forUser`) for the same pseudonym. | **P2** | Compute and cache `Optional<String> noticeVersion` and `Optional<List<Section>> noticeSections` once in the `EndUserPages` constructor, and derive `currentAcknowledged` in `NoticeApiController.forUser` without a second DB round-trip. |
| **D-07** | `java/dataplane/src/main/java/io/rwsafe/dataplane/server/BlockPages.java:117-121,128-132` (`json`, `sseTermination`) | `BlockPages.json` and `BlockPages.sseTermination` format the JSON `"ref"` field with `jsonSafe(ref)` instead of `safeRef(ref)`, whereas `sseTermination` formats the `"message"` text with `safeRef(ref)`. For a `null`, empty, or >64-char `ref`, the JSON `"ref"` field and the `"message"` reference disagree; `sseTermination` also writes `"reason":""` instead of `"policy"` when `reason` is `null`. | **P2** | Use `safeRef(ref)` for the `"ref"` field in both `BlockPages.json` and `BlockPages.sseTermination`, and normalise a `null` reason in `sseTermination` consistently with `BlockPages.json`. |
| **D-08** | `java/control/src/test/java/io/rwsafe/control/notice/NoticeAcknowledgementIntegrationTest.java` and `java/platform-core/src/test/java/io/rwsafe/platform/enduser/EndUserCatalogueTest.java:78` | (1) `NoticeIntakeController.keyMissing` (HTTP 503 `PRIVACY_KEY_UNAVAILABLE` when `MaskingUnavailableException` is thrown, AGENTS.md §4.10) has no test in `NoticeAcknowledgementIntegrationTest` or `NoticeAcknowledgementServiceTest`. (2) `EndUserCatalogueTest.textsAvoidJargonAndAbbreviations` lowercases only with `Locale.ROOT`, which folds Turkish capital `İ` to `i\u0307` and misses banned terms starting with `i`/`I` when capitalised as `İ`. | **P2** | Add a test verifying HTTP 503 `PRIVACY_KEY_UNAVAILABLE` when the privacy key is missing on `/internal/v1/notice-acknowledgements`, and check both `Locale.ROOT` and `Locale.forLanguageTag("tr")` in `EndUserCatalogueTest.textsAvoidJargonAndAbbreviations`. |

---

### (3) QUESTIONS FOR THE PRODUCT OWNER

| Question | Recommendation |
|---|---|
| **PO-Q1 (LR-1 / Q-4, Q-5, AGENTS.md §4.13)**: In `notice.raw.text` and `notice.retention.text`, should the full-content capture tier be described as `"tespit edilen gizli bilgiler ve kişisel veriler çıkarıldıktan sonra içeriğin tam metni"` rather than `"İçeriğin değiştirilmemiş hâli"`, and should `notice.basis.text` (LR-2) explicitly include this tier under KVKK art. 5/2-f? | **Recommend YES**: AGENTS.md §4.13 mandates redaction of detected secrets and PII before persistence even for raw prompt capture, so describing it as redaction-applied full text avoids contradicting `notice.data.text` and ensures `notice.basis.text` covers all stored tiers. |
| **PO-Q2 (LR-6 / PC-5, `BlockPages.FAIL_CLOSED_CATEGORIES`)**: Is `internal_identity` (`kurum içi kimlik bilgisi`) a permanent fail-closed no-exception class alongside `customer_data`, `secret` and `special_category`? | **Recommend YES**: Keep `internal_identity` in `FAIL_CLOSED_CATEGORIES` and add `kurum içi kimlik bilgileri` to `block.class.noexception` so the block page text matches the four enforced classes. |
| **PO-Q3 (LR-7 / Q-32, Q-35)**: Do you confirm replacing `"onayladıysanız"` in `notice.acknowledge.text` with `"Kurumun insan kaynakları politikası kapsamında bu sürümü okuduğunuz kayda geçtiyse o kayıt da aynı anlamı taşır."` so the HR directory record is never described as an approval (`onay`)? | **Recommend YES**: Aligns the Turkish notice wording with Q-32 and Q-35 (proof of KVKK art. 10 notice, never approval or consent). |

---

### (4) VERDICT

MERGE WITH CORRECTIONS

---

### (5) INSTRUCTIONS RECEIVED (VERBATIM)

```text
/plan REVIEW: second independent review of pull request 22 (AGENTS.md section 9, security-sensitive: masking, internal routes,
security configuration, block pages on the inline path), branch `feature/end-user-notices`
LENS: whether the Turkish end-user texts, their rendering, and the notice acknowledgement recording and gate hold against
AGENTS.md sections 3, 4 and 5, the SR-PRIV and PRIV-2 requirements, and PO decisions Q-4, Q-5, Q-6, Q-32, Q-33 and Q-35.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway that shows employees a
Turkish notice and block pages and records their acknowledgement; a public repository). You start from a fresh context.
Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this repository. Do not edit, run shell, or
widen the review. Your job: find any XSS, header injection or external resource in a rendered page; any prompt content,
identity or estate value reaching a page, a log or the masked role; any way the acknowledgement gate opens content
capture without a record of the current notice version, or a record can be forged, replayed, altered or deleted; any
internal route reachable from outside its port or by the wrong role; any blocking work or regex on the request thread;
and any Turkish wording that contradicts the decision records (consent as a basis, exceptions for fail-closed classes,
personal accounts, retention). Return exactly: (1) a CONSENT table (area, verdict), (2) a DISSENT table (finding id, file
and line or symbol, what is wrong, severity P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE PRODUCT OWNER
(question, your recommendation), (4) a one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then (5) list every
instruction you received, verbatim. Be concrete and short. Never quote or invent an address, host name, account, serial
or secret; the repository holds none and neither should your output. English only, except quoted Turkish catalogue keys.

Files to read, in this order:
- AGENTS.md (sections 3, 4, 5)
- docs/i18n/README.md and every file under docs/i18n/tr/
- java/platform-core/src/main/resources/io/rwsafe/platform/enduser/end-user-tr.properties
- every file under java/platform-core/src/main/java/ that names "EndUser"
- java/dataplane/src/main/java/io/rwsafe/dataplane/server/BlockPages.java
- java/persistence/src/main/resources/db/migration/V5__notice_acknowledgement.sql
- every file under java/control/src/main/java/ that names "Notice", "Acknowledg" or "SecurityConfig"
- every test under java/platform-core/src/test/, java/control/src/test/ and java/persistence/src/test/ that names "Notice", "EndUser" or "Acknowledg", and java/dataplane/src/test/java/io/rwsafe/dataplane/server/BlockPagesTest.java
```
