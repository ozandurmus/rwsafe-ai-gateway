<!-- Argon consultation 2026-10-30T21:08:15Z, model gemini-4-argon-high, effort high; unaltered output except 23 local paths masked (AGENTS.md 4.2) -->

Role: `REVIEWER`

### (1) EARLIER FINDINGS (D-01 TO D-07)

| Earlier Finding ID | Status | Reason |
|---|---|---|
| **D-01** | **CLOSED** | [`PolicyRegistryStore.retirePlatform`](file://<workspace-root>/java/persistence/src/main/java/io/rwsafe/persistence/PolicyRegistryStore.java#L257-L258) supersedes all `pending` drafts of the platform rule in the retirement transaction, and [`rwsafe_policy_rule_version_guard`](file://<workspace-root>/java/persistence/src/main/resources/db/migration/V3__policy_scope_and_retirement.sql#L191-L196) permits `pending -> superseded` when the rule has a `retired` row. Covered by [`PolicyRegistryStoreTest.aDraftStartedBeforeARetirementCanNeverBringThePlatformBack`](file://<workspace-root>/java/persistence/src/test/java/io/rwsafe/persistence/PolicyRegistryStoreTest.java#L468-L479). |
| **D-02** | **CLOSED** | [`VerdictQueries.eventFields`](file://<workspace-root>/java/persistence/src/main/java/io/rwsafe/persistence/VerdictQueries.java#L205-L209) selects `APPLIED_RULE_IDS` and `MONITOR_RULE_IDS`, and [`VerdictQueries.toEvent`](file://<workspace-root>/java/persistence/src/main/java/io/rwsafe/persistence/VerdictQueries.java#L224-L235) passes both lists to the 19-argument [`StoredVerdictEvent`](file://<workspace-root>/java/persistence/src/main/java/io/rwsafe/persistence/StoredVerdictEvent.java#L16-L26) constructor. Covered by [`VerdictEventStoreTest.scopedRuleIdsRoundTripAndKeepTheirShape`](file://<workspace-root>/java/persistence/src/test/java/io/rwsafe/persistence/VerdictEventStoreTest.java#L52-L78). |
| **D-03** | **CLOSED** | [`Pseudonymiser.group`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/privacy/Pseudonymiser.java#L74-L81) normalises group names with [`GroupNames.normalise`](file://<workspace-root>/java/policy/src/main/java/io/rwsafe/policy/GroupNames.java#L34-L66) before computing the HMAC (while still pseudonymising invalid inputs so raw strings are never returned). |
| **D-04** | **CLOSED** | [`IngestionService.ruleIds`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/ingest/IngestionService.java#L129-L167) and [`rwsafe_rule_id_list_ok`](file://<workspace-root>/java/persistence/src/main/resources/db/migration/V3__policy_scope_and_retirement.sql#L227-L232) restrict rule IDs to `class.<KNOWN_DATA_CLASS>@<version>` (at most 16 items, at most 128 chars, no duplicates), eliminating any free-text suffix. |
| **D-05** | **CLOSED** | [`rwsafe_scope_groups_ok`](file://<workspace-root>/java/persistence/src/main/resources/db/migration/V3__policy_scope_and_retirement.sql#L35-L41) enforces `g = lower(g)` and case-insensitive uniqueness, and [`rwsafe_policy_rule_version_guard`](file://<workspace-root>/java/persistence/src/main/resources/db/migration/V3__policy_scope_and_retirement.sql#L141-L160) locks `activated_at`, `superseded_at`, `retired_*` and `withdrawn_at` to their respective lifecycle transitions. Covered by [`PolicyRegistryStoreTest.theScopeShapeIsCheckedByTheDatabase`](file://<workspace-root>/java/persistence/src/test/java/io/rwsafe/persistence/PolicyRegistryStoreTest.java#L182-L215) and [`lifecycleTimesNeverChangeOnAnotherTransition`](file://<workspace-root>/java/persistence/src/test/java/io/rwsafe/persistence/PolicyRegistryStoreTest.java#L484-L503). |
| **D-06** | **CLOSED** | [`PolicyRegistryService.draft`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/policy/PolicyRegistryService.java#L151-L173) enforces `requireSecurityAdmin` (and non-`replay_viewer`) and `mode = "enforce"` for platform/flow rules (backed by `policy_rule_version_enforce_only` in [`V3__policy_scope_and_retirement.sql`](file://<workspace-root>/java/persistence/src/main/resources/db/migration/V3__policy_scope_and_retirement.sql#L63)); [`PolicyRegistryService.reasonText`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/policy/PolicyRegistryService.java#L387-L407) fails closed (HTTP 503) when masking is unavailable and rejects reasons matching `DetectorSet.standard()`, `TextMasker` or the estate dictionary. |
| **D-07** | **CLOSED** | [`foldGroupName`](file://<workspace-root>/frontend/src/pages/PoliciesPage.tsx#L90-L98) in [`ScopePicker.add`](file://<workspace-root>/frontend/src/pages/PoliciesPage.tsx#L765-L774) applies the same NFC and Turkish `İ`/`I`/`ı`/`i\u0307` folding as [`GroupNames.normalise`](file://<workspace-root>/java/policy/src/main/java/io/rwsafe/policy/GroupNames.java#L34-L66), and [`SnapshotCompilerTest.theDocumentIsOneTheDataPlaneCodecAccepts`](file://<workspace-root>/java/control/src/test/java/io/rwsafe/control/policy/SnapshotCompilerTest.java#L105-L130) now verifies compiled format-2 snapshots directly against [`SnapshotCodec.parse`](file://<workspace-root>/java/policy/src/main/java/io/rwsafe/policy/SnapshotCodec.java#L58-L117) without skipping. |

---

### (2) DISSENT

| ID | File and Line / Symbol | What Is Wrong | Severity | Concrete Correction |
|---|---|---|---|---|
| *None* | — | No new P0, P1 or P2 findings. Withdrawal of a group-scoped version requires a `security_admin` request with a sanitized, ledger-verified reason and two approvals from distinct people and roles (`security_admin` + `privacy_officer`) before transitioning the target to `withdrawn`, affects only its own `(rule_id, mode, scope_key)`, leaves no stale scope in compiled format-2 snapshots, and passes RBAC, masking and React text-node rendering checks. | — | — |

---

### (3) QUESTIONS FOR THE PRODUCT OWNER

| Question | Recommendation |
|---|---|
| *None* | — |

---

### (4) VERDICT

**MERGE**

---

### (5) INSTRUCTIONS RECEIVED (VERBATIM)

```text
/plan REVIEW: confirmation review of pull request 21 after corrections (AGENTS.md section 9, security-sensitive: policy
registry, approvals, RBAC, masking, snapshot compilation, the inline evaluation), branch `feature/scoped-policy-control`
LENS: whether the corrections for D-01 to D-07 close each finding, and whether the new withdrawal of a group-scoped
version (two approvals) and the merged data-plane format 2 lane hold against AGENTS.md sections 4 and 6,
docs/architecture/POLICY_SNAPSHOT_CONTRACT.md and docs/design/PO_DECISION_RECORD_2026_10_30_POLICY_SCOPE_AND_PLATFORM_RETIREMENT.md.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway: a Spring Boot control
plane and React admin UI manage the policy a data plane enforces; a public repository). You start from a fresh context.
Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this repository. Do not edit, run shell, or
widen the review. Your job: for each earlier finding, say CLOSED or OPEN with the reason; then find any way one person or
one role can activate, withdraw, retire or loosen policy outside the decision record; any withdrawal that takes effect
without two approvals by two different people, leaves a stale scope in the snapshot, or drops a stricter rule for groups
it did not name; any snapshot the compiler emits that the format 2 codec refuses; any masking, ledger or RBAC gap on the
new routes; and any XSS through reasons or group names. Return exactly: (1) a table (earlier finding id, CLOSED or OPEN,
reason), (2) a DISSENT table for new findings (id, file and line or symbol, what is wrong, severity P0/P1/P2, the
concrete correction), (3) QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation), (4) a one-line verdict MERGE /
MERGE WITH CORRECTIONS / DO NOT MERGE, then (5) list every instruction you received, verbatim. Be concrete and short.
Never quote or invent an address, host name, account, serial or secret; the repository holds none and neither should
your output. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 6)
- docs/reviews/PR21_2026_10_30_ARGON_SCOPED_POLICY_CONTROL.md (the earlier findings)
- docs/reviews/PR21_2026_10_30_RESPONSE.md
- docs/design/PO_DECISION_RECORD_2026_10_30_POLICY_SCOPE_AND_PLATFORM_RETIREMENT.md
- java/persistence/src/main/resources/db/migration/V3__policy_scope_and_retirement.sql
- every file under java/persistence/src/main/java/ that names "Policy" or "Verdict"
- every file under java/control/src/main/java/io/rwsafe/control/policy/
- java/control/src/main/java/ files that name "Pseudonymiser", "Ingest" or "ScopeGroups"
- java/policy/src/main/java/io/rwsafe/policy/GroupNames.java and SnapshotCodec.java
- frontend/src/pages/PoliciesPage.tsx, frontend/src/pages/PlatformsPage.tsx
- every test under java/control/src/test/java/ and java/persistence/src/test/java/ that names "Policy", "Snapshot", "Registry", "Withdraw" or "Retire"
```
