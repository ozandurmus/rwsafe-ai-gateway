<!-- Argon consultation 2026-10-30T20:43:29Z, model gemini-4-argon-high, effort high; unaltered output except 28 local paths masked (AGENTS.md 4.2) -->

Role: `REVIEWER`

### (1) CONSENT

| Area | Verdict |
|---|---|
| Two-person, two-role activation (`security_admin` + `privacy_officer`) across API, store, DB triggers and compiler (`SnapshotCompiler.approved`) | **CONSENT** |
| Fail-closed DLP classes (`SECRET`, `TCKN`, `TR_IBAN`, `PAYMENT_CARD`) and `flow.ai-category` never reach `ALLOW`, `WARN` or an exception in any scope (`ANY` or `GROUPS`) or mode (`enforce` or `monitor`) | **CONSENT** |
| Append-only audit ledger, approvals and monotonic snapshots (`PolicySnapshotStore.reusable` refuses forged or future-dated rows; unsigned snapshots never issued) | **CONSENT** |
| Snapshot format 2 determinism (canonical sorting of `baseline`, `scopedRules` and `groups`; `rulesDigest` independent of input order, version and timestamp) | **CONSENT** |
| Frontend XSS safety in [PoliciesPage.tsx](file://<workspace-root>/frontend/src/pages/PoliciesPage.tsx) and [PlatformsPage.tsx](file://<workspace-root>/frontend/src/pages/PlatformsPage.tsx) (all group names and retirement reasons rendered as React text nodes; group names never persisted to browser storage) | **CONSENT** |
| Streaming batch bound (`MAX_BATCH = 1000`) and per-field length bounds in [IngestionController.java](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/ingest/IngestionController.java) and [IngestionService.java](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/ingest/IngestionService.java) | **CONSENT** |

---

### (2) DISSENT

| Finding ID | File and Line / Symbol | What Is Wrong | Severity | Concrete Correction |
|---|---|---|---|---|
| **D-01** | [PolicyRegistryStore.java](file://<workspace-root>/java/persistence/src/main/java/io/rwsafe/persistence/PolicyRegistryStore.java#L180-L198) (`retirePlatform`), [V3__policy_scope_and_retirement.sql](file://<workspace-root>/java/persistence/src/main/resources/db/migration/V3__policy_scope_and_retirement.sql#L135-L139) (`rwsafe_policy_rule_version_guard`) | `retirePlatform` only transitions `status = 'active'` rows to `'retired'`. If the platform rule also has an in-flight `pending` draft that already holds one approval (e.g. from `security_admin`), that `pending` row and its approval survive retirement. A single `privacy_officer` can then approve that pre-retirement draft and reactivate the retired platform alone, violating PO decision Q-40 ("Bringing a platform back is a new version under the normal two approvals"). | **P1** | In [V3__policy_scope_and_retirement.sql](file://<workspace-root>/java/persistence/src/main/resources/db/migration/V3__policy_scope_and_retirement.sql#L135-L139), allow `OLD.status = 'pending' AND NEW.status = 'superseded'` when `EXISTS (SELECT 1 FROM policy_rule_version r WHERE r.rule_id = OLD.rule_id AND (r.version > OLD.version OR r.status = 'retired'))`. In [`PolicyRegistryStore.retirePlatform`](file://<workspace-root>/java/persistence/src/main/java/io/rwsafe/persistence/PolicyRegistryStore.java#L192-L195), supersede any `pending` version of `ruleId` in the same transaction. |
| **D-02** | [VerdictQueries.java](file://<workspace-root>/java/persistence/src/main/java/io/rwsafe/persistence/VerdictQueries.java#L205-L209) (`eventFields`), [VerdictQueries.java](file://<workspace-root>/java/persistence/src/main/java/io/rwsafe/persistence/VerdictQueries.java#L224-L229) (`toEvent`) | `VerdictEventStore.insert` writes `APPLIED_RULE_IDS` and `MONITOR_RULE_IDS`, but `VerdictQueries.eventFields()` omits both columns and `VerdictQueries.toEvent` calls the 17-argument [`StoredVerdictEvent`](file://<workspace-root>/java/persistence/src/main/java/io/rwsafe/persistence/StoredVerdictEvent.java#L29-L35) constructor, which hardcodes `List.of(), List.of()`. Every read through `VerdictQueries.traffic` and `VerdictQueries.event` silently drops `appliedRuleIds` and `monitorRuleIds`. | **P1** | Add `APPLIED_RULE_IDS` and `MONITOR_RULE_IDS` to `eventFields()`, pass `List.of(r.get(APPLIED_RULE_IDS))` and `List.of(r.get(MONITOR_RULE_IDS))` to the 19-argument `StoredVerdictEvent` constructor in `toEvent`, and assert round-trip read in [VerdictEventStoreTest.java](file://<workspace-root>/java/persistence/src/test/java/io/rwsafe/persistence/VerdictEventStoreTest.java). |
| **D-03** | [Pseudonymiser.java](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/Pseudonymiser.java#L73-L78) (`group`) | `Pseudonymiser.group(String)` hashes `name.strip().toLowerCase(Locale.ROOT)` instead of applying [`GroupNames.normalise`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/policy/GroupNames.java#L31-L48). Under `Locale.ROOT`, Turkish `İ` lowers to `i\u0307`, `ı` stays `ı`, `I` lowers to `i`, and NFD strings stay un-normalised; spellings that [`GroupNames.normalise`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/policy/GroupNames.java#L31-L48) folds to the same group yield different `GRP-<10 hex>` pseudonyms when passed to `Pseudonymiser.group`. | **P1** | Normalise `name` in `Pseudonymiser.group` using `GroupNames.normalise` (with NFC + Turkish `İ`/`I`/`ı`/`\u0307` folding) before computing `keys.hmac("group", ...)`. |
| **D-04** | [IngestionService.java](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/ingest/IngestionService.java#L131-L152) (`RULE_ID`, `ruleIds`), [V3__policy_scope_and_retirement.sql](file://<workspace-root>/java/persistence/src/main/resources/db/migration/V3__policy_scope_and_retirement.sql#L169-L174) (`rwsafe_rule_id_list_ok`) | `RULE_ID` and `rwsafe_rule_id_list_ok` accept `(class\|platform\|flow)\.[A-Za-z0-9_-]{1,64}@[1-9][0-9]{0,9}` without scanning through `DETECTORS.scan(...)` (unlike `token()` at line 226), without restricting to scoped DLP class rules (`class.<DATA_CLASS>@<version>`), and without rejecting duplicate elements (unlike `findings()` at line 161). A TCKN, TR IBAN, payment card, secret token or estate identifier can ride along inside the 64-character suffix into `verdict_event`. | **P1** | Restrict `RULE_ID` and `rwsafe_rule_id_list_ok` to `^class\.[A-Z][A-Z0-9_]{1,31}@[1-9][0-9]{0,9}$` (and in `IngestionService.ruleIds`, verify `RegistryVocabulary.dataClassOf` or `DETECTORS.scan(id).isEmpty()`), and reject duplicate IDs in both `IngestionService.ruleIds` and `rwsafe_rule_id_list_ok`. |
| **D-05** | [V3__policy_scope_and_retirement.sql](file://<workspace-root>/java/persistence/src/main/resources/db/migration/V3__policy_scope_and_retirement.sql#L30-L36) (`rwsafe_scope_groups_ok`), [V3__policy_scope_and_retirement.sql](file://<workspace-root>/java/persistence/src/main/resources/db/migration/V3__policy_scope_and_retirement.sql#L108-L147) (`rwsafe_policy_rule_version_guard`) | (1) `rwsafe_scope_groups_ok` forbids `'I'`, `U+0130`, `U+0131` and `U+0307` but never checks `g = lower(g)`, allowing uppercase group names (e.g. `'GRP-ALPHA'`) and case-insensitive duplicates (`ARRAY['grp-alpha','GRP-ALPHA']`) into storage that [`SnapshotCompiler.groups`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/policy/SnapshotCompiler.java#L188-L193) (`GroupNames.storedFormOk`) refuses to compile. (2) In `rwsafe_policy_rule_version_guard`, line 108 only guards `activated_at` when `OLD.status = NEW.status`, and line 141 strips `activated_at` from the `to_jsonb` immutability check, allowing a direct SQL `UPDATE` during `active -> superseded`, `active -> retired` or `pending -> superseded` to overwrite or clear `activated_at`. | **P1** | (1) Add `AND g = lower(g)` to `rwsafe_scope_groups_ok` (and pass normalised lowercase groups in [PolicyRegistryStoreTest.java](file://<workspace-root>/java/persistence/src/test/java/io/rwsafe/persistence/PolicyRegistryStoreTest.java#L143-L166)). (2) In `rwsafe_policy_rule_version_guard`, require `NEW.activated_at IS NOT DISTINCT FROM OLD.activated_at` whenever `NOT (OLD.status = 'pending' AND NEW.status = 'active')`, and `NEW.superseded_at IS NOT DISTINCT FROM OLD.superseded_at` whenever `NEW.status <> 'superseded'`. |
| **D-06** | [PolicyRegistryService.java](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/policy/PolicyRegistryService.java#L143-L182) (`draft`), [#L242-L268](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/policy/PolicyRegistryService.java#L242-L268) (`platformDraft`), [#L330-L340](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/policy/PolicyRegistryService.java#L330-L340) (`retirePlatform`) | (1) Unlike `approve` and `retirePlatform`, `draft` does not check `sessionRoles.contains(Roles.SECURITY_ADMIN) && !sessionRoles.contains(Roles.REPLAY_VIEWER)` in the service layer. (2) `platformDraft` accepts `mode = "monitor"`, which `SnapshotCompiler` never compiles into snapshots but `PlatformsPage` (`shownVersion`) displays as active. (3) `retirePlatform` checks `namesEstate(reason)` on the 500-char free-text `reason`, but does not scan `reason` with `DetectorSet.standard()` or IP/identifier checks before persisting it in `policy_rule_version.retired_reason` and `audit_event.reason_code`, where unmasked roles read it in full (AGENTS.md 4.2, 4.13). | **P1** | (1) Pass `Set<String> sessionRoles` into `draft` and enforce `SECURITY_ADMIN` and non-`REPLAY_VIEWER`. (2) Require `mode = "enforce"` for `platform` (and `flow`) rules in `draft` and DB check constraints. (3) In `retirePlatform`, refuse `reason` if `DetectorSet.standard().scan(reason)` is non-empty or if `TextMasker` / IP detection alters it. |
| **D-07** | [PoliciesPage.tsx](file://<workspace-root>/frontend/src/pages/PoliciesPage.tsx#L592-L600) (`ScopePicker.add`), [SnapshotCompilerTest.java](file://<workspace-root>/java/control/src/test/java/io/rwsafe/control/policy/SnapshotCompilerTest.java#L112-L120) | (1) `ScopePicker.add` deduplicates with `g.toLowerCase() === name.toLowerCase()`, which misses NFC and Turkish `İ`/`I`/`ı`/`\u0307` folding, allowing duplicate chips that the server then refuses with HTTP 400. (2) [`SnapshotCompiler`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/policy/SnapshotCompiler.java#L37) unconditionally emits `"format": 2`, which `io.rwsafe.policy.SnapshotCodec` on this branch refuses (skipped via `Assumptions.assumeFalse` in `SnapshotCompilerTest`); merging before the data-plane format-2 codec lands violates [POLICY_SNAPSHOT_CONTRACT.md](file://<workspace-root>/docs/architecture/POLICY_SNAPSHOT_CONTRACT.md#L4-L5) and breaks snapshot loading on `main`. | **P2** | (1) Normalise with `.trim().normalize('NFC').replace(/[İIı]/g, 'i').toLowerCase().replace(/\u0307/g, '').normalize('NFC')` when deduplicating in `ScopePicker.add`. (2) Land the `java/policy` format-2 codec before or together with this branch so `theDocumentIsOneTheDataPlaneCodecAccepts` passes without skipping. |

---

### (3) QUESTIONS FOR THE PRODUCT OWNER

| Question | Recommendation |
|---|---|
| **Q-41:** Once a group-scoped version of a DLP class rule (`scope_kind = 'GROUPS'`) is activated in `enforce` or `monitor` mode, the V3 schema only permits `platform` rows to be `retired` and only permits an `active` class version to be `superseded` by a newer version of the exact same `(rule_id, mode, scope_key)`. How should an operator remove a finished group scope so that those directory groups return to following the `ANY` baseline (and do not stay pinned in `scopedRules` forever)? | **(Recommended)** Allow retiring an active group-scoped `class_action` version (with a required reason and ledger entry, keeping history as `retired`, just like platform retirement) so the group scope leaves the next snapshot and those groups fall back to `ANY`. |

---

### (4) VERDICT

**MERGE WITH CORRECTIONS**

---

### (5) INSTRUCTIONS RECEIVED (VERBATIM)

```text
/plan REVIEW: second independent review of pull request 21 (AGENTS.md section 9, security-sensitive: policy registry,
approvals, RBAC, masking, snapshot compilation), branch `feature/scoped-policy-control`
LENS: whether group-scoped rule versions, platform retirement by one administrator, snapshot format 2 compilation and the
new verdict-event fields hold against AGENTS.md sections 4 and 6, docs/architecture/POLICY_SNAPSHOT_CONTRACT.md (format 2)
and docs/design/PO_DECISION_RECORD_2026_10_30_POLICY_SCOPE_AND_PLATFORM_RETIREMENT.md.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway: a Spring Boot control
plane with a React admin UI that manages the policy the data plane enforces; a public repository). You start from a fresh
context. Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this repository. Do not edit, run
shell, or widen the review. Your job: find any way one person, one role, a replayed request or a direct database write
can activate, weaken, retire or roll back policy outside the decision record (two approvals for activation, one
security_admin with a reason for platform retirement, nothing deleted); any way a fail-closed class reaches ALLOW or WARN
in any scope or mode; any snapshot the compiler emits that the format 2 contract refuses, or that differs for the same
registry; any group-name normalisation gap between storage, API and compiler (Unicode NFC, Turkish dotted and dotless i,
commas, control characters, duplicates); any RBAC or masking gap (a viewer or the masked role reaching a write, a real
group name or a retirement reason unmasked); any XSS or injection through group names or reasons; any audit-ledger gap;
and any unbounded input in event ingestion. Return exactly: (1) a CONSENT table (area, verdict), (2) a DISSENT table
(finding id, file and line or symbol, what is wrong, severity P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE
PRODUCT OWNER (question, your recommendation), (4) a one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then
(5) list every instruction you received, verbatim. Be concrete and short. Never quote or invent an address, host name,
account, serial or secret; the repository holds none and neither should your output. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 6, 9)
- docs/design/PO_DECISION_RECORD_2026_10_30_POLICY_SCOPE_AND_PLATFORM_RETIREMENT.md
- docs/architecture/POLICY_SNAPSHOT_CONTRACT.md
- java/persistence/src/main/resources/db/migration/V2__policy_registry.sql and V3__policy_scope_and_retirement.sql
- every file under java/persistence/src/main/java/ that names "Policy", "Verdict" or "Event"
- every file under java/control/src/main/java/io/rwsafe/control/policy/
- java/control/src/main/java/io/rwsafe/control/ files that name "GroupNames", "Pseudonymiser", "Verdict" or "Ingest"
- frontend/src/pages/PoliciesPage.tsx, frontend/src/pages/PlatformsPage.tsx
- every test under java/control/src/test/java/ and java/persistence/src/test/java/ that names "Policy", "Snapshot", "Registry", "Group" or "Retire"
```
