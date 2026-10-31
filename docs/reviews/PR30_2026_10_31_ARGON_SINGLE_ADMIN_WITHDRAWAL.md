<!-- Argon consultation 2026-10-31T08:33:51Z, model gemini-4-argon-high, effort high; unaltered output except 13 local paths masked (AGENTS.md 4.2) -->

**Role:** `REVIEWER`

### (1) CONSENT

| Area | Verdict |
|---|---|
| RBAC on withdrawal (`security_admin` only; viewer, `privacy_officer` alone, and `replay_viewer` / dual masked sessions refused with HTTP 403) | CONSENT |
| Target scope & fail-closed invariants (only active `GROUPS`-scoped `class_action` versions withdrawable; `ANY` baselines, `platform` rows, `flow` rows, and V3 marker rows refused; fail-closed baselines untouched; other active group scopes untouched) | CONSENT |
| Reason validation & privacy (1–500 chars, single-line, trimmed, `IdentifierCheck`, free-text masking layers, estate dictionary check, fail-closed HTTP 503 when masking key/dictionary unavailable, masked view withholds `withdrawal.reason`) | CONSENT |
| Database immutability & ledger backstop (`withdrawn_by` format `^USR-[0-9a-f]{10}$`, `rwsafe_reason_text_ok`, `POLICY_WITHDRAWAL_REFUSED` when ledger `app.actor_fingerprint` or `app.reason_code` disagrees, `POLICY_WITHDRAWN_FINAL` and `POLICY_LIFECYCLE` preventing un-withdrawal, re-withdrawal, or field tampering, append-only row retention) | CONSENT |
| Snapshot compilation (`SnapshotCompiler` excludes `withdrawn` versions and historical V3 withdrawal-request markers; groups fall back to `ANY` baseline on next snapshot; transactional `checkWithdrawal` rollback on compile failure) | CONSENT |
| V9 migration & V3 history preservation (`V9__single_admin_withdrawal.sql` supersedes pending V3 withdrawal requests under a ledgered migration event, blocks activation of retired withdrawal requests, and preserves active V3 markers and V3 withdrawn targets) | CONSENT |
| Frontend UI (`PoliciesPage.tsx` offers withdrawal only to unmasked `security_admin` on active `GROUPS` versions, requires a trimmed 1–500 char reason and in-page confirmation, shows server refusal reasons via `ErrorPanel`, and displays withdrawal history) | CONSENT |

---

### (2) DISSENT

| Finding ID | File and line or symbol | What is wrong | Severity | Concrete correction |
|---|---|---|---|---|
| D-01 | [`PolicyRegistryStore.java`](file://<workspace-root>/java/persistence/src/main/java/io/rwsafe/persistence/PolicyRegistryStore.java#L111-L129) (`withdrawScope`), [`V9__single_admin_withdrawal.sql`](file://<workspace-root>/java/persistence/src/main/resources/db/migration/V9__single_admin_withdrawal.sql#L130-L136) (`rwsafe_policy_rule_version_guard`), [`PolicyRegistryStoreTest.java`](file://<workspace-root>/java/persistence/src/test/java/io/rwsafe/persistence/PolicyRegistryStoreTest.java#L501-L515) | Unlike `retirePlatform` (PR 21 D-01, [`PolicyRegistryStore.java`](file://<workspace-root>/java/persistence/src/main/java/io/rwsafe/persistence/PolicyRegistryStore.java#L243-L246)), `withdrawScope` does not supersede a `pending` draft of the same `(rule_id, mode, scope_key)` when the active version of that scope is withdrawn. If a draft for the same rule, mode, and group scope was created before the withdrawal and already holds one approval (e.g. `security_admin`), a `privacy_officer` alone can approve that pre-withdrawal draft after the withdrawal and immediately restore the withdrawn group scope into the active set and snapshot without a post-withdrawal `security_admin` approval (violating Q-41 Decision 4 and Decision 6). In addition, the trigger check on `OLD.status = 'pending' AND NEW.status = 'superseded'` at [`V9__single_admin_withdrawal.sql`](file://<workspace-root>/java/persistence/src/main/resources/db/migration/V9__single_admin_withdrawal.sql#L132-L135) checks `r.rule_id = OLD.rule_id AND (r.version > OLD.version OR r.status = 'retired')` without matching `OLD`'s `mode` and `scope_key`. | P1 | 1. In [`PolicyRegistryStore.withdrawScope`](file://<workspace-root>/java/persistence/src/main/java/io/rwsafe/persistence/PolicyRegistryStore.java#L124-L127), supersede any `pending` version of the same `rule_id`, `mode`, and `scope_key` (leaving pending drafts of other scopes/modes untouched).<br>2. In [`V9__single_admin_withdrawal.sql`](file://<workspace-root>/java/persistence/src/main/resources/db/migration/V9__single_admin_withdrawal.sql#L132-L136), require a pending-to-superseded transition (`OLD.withdraws_version IS NULL`) to match a row `r` with `r.rule_id = OLD.rule_id AND ((r.mode = OLD.mode AND rwsafe_scope_key(r.scope_kind, r.scope_groups) = rwsafe_scope_key(OLD.scope_kind, OLD.scope_groups) AND (r.version > OLD.version OR r.status = 'withdrawn')) OR r.status = 'retired')`.<br>3. In [`PolicyRegistryStoreTest.java`](file://<workspace-root>/java/persistence/src/test/java/io/rwsafe/persistence/PolicyRegistryStoreTest.java#L501-L515), verify that a pre-withdrawal pending draft of the withdrawn `(rule_id, mode, scope_key)` holding one approval is superseded on withdrawal and cannot be completed by `privacy_officer` alone, while pending drafts of other scopes/modes remain pending. |
| D-02 | [`PolicyRegistryIntegrationTest.java`](file://<workspace-root>/java/control/src/test/java/io/rwsafe/control/policy/PolicyRegistryIntegrationTest.java#L584-L648) (`oneSecurityAdministratorWithdrawsAGroupScopeWithAReasonAndItLeavesTheSnapshot`, `theMaskedRetirementReasonPassesTheMasker`) | [`PolicyViews.VersionView.masked`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/policy/PolicyViews.java#L85-L86) withholds `withdrawal.reason` for the masked role as required by Q-41 Decision 2, but `PolicyRegistryIntegrationTest` only asserts masked withholding on `retirement.reason` (line 640) and checks only the unmasked `viewer` response after a scope withdrawal (line 625). | P2 | In [`PolicyRegistryIntegrationTest.oneSecurityAdministratorWithdrawsAGroupScopeWithAReasonAndItLeavesTheSnapshot`](file://<workspace-root>/java/control/src/test/java/io/rwsafe/control/policy/PolicyRegistryIntegrationTest.java#L625-L629), also query `GET /api/v1/policy/rules` as the masked role and assert that `withdrawal.reason` equals `PolicyViews.FREE_TEXT_WITHHELD` (and does not contain `"Pilot finished"`), while `withdrawal.withdrawnBy` and `withdrawal.withdrawnAt` remain present. |

---

### (3) QUESTIONS FOR THE PRODUCT OWNER

| Question | Recommendation |
|---|---|
| None. Q-41 Decisions 1–6 in [`PO_DECISION_RECORD_2026_10_31_Q41_Q42_Q44.md`](file://<workspace-root>/docs/design/PO_DECISION_RECORD_2026_10_31_Q41_Q42_Q44.md#L31-L45) are unambiguous, and superseding a pre-withdrawal pending draft of the withdrawn `(rule_id, mode, scope_key)` follows the ratified D-01 precedent for platform retirement. | Apply D-01 and D-02 and merge without a new PO decision record. |

---

### (4) VERDICT

MERGE WITH CORRECTIONS

---

### (5) INSTRUCTIONS RECEIVED (VERBATIM)

#### User Request (`<USER_REQUEST>`)

```text
/plan REVIEW: second independent review of pull request 30 (AGENTS.md section 9, security-sensitive: policy registry,
RBAC, database triggers), branch `feature/q41-single-admin-withdrawal`
LENS: whether the single-administrator withdrawal of a group-scoped rule version holds against AGENTS.md sections 4 and 6
and docs/design/PO_DECISION_RECORD_2026_10_31_Q41_Q42_Q44.md (one security_admin, a checked reason, immediate effect,
ledgered, history kept, nothing deleted).

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway: a control plane with a
policy registry that the data plane enforces; a public repository). You start from a fresh context. Read AGENTS.md and
ONLY the files listed below, with the Read tool, inside this repository. Do not edit, run shell, or widen the review.
Your job: find any way someone other than a security_admin (a viewer, the privacy officer, the masked role, a direct SQL
write without the ledger, a replayed request) withdraws, un-withdraws or alters a version; any withdrawal that touches
another scope, a baseline ANY version, a platform or flow row, or a fail-closed invariant; any reason that stores an
identifier; any snapshot that keeps a withdrawn scope; any migration step that loses history or breaks old V3 rows; and
any UI path that hides the server's refusal. Return exactly: (1) a CONSENT table (area, verdict), (2) a DISSENT table
(finding id, file and line or symbol, what is wrong, severity P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE
PRODUCT OWNER (question, your recommendation), (4) a one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then
(5) list every instruction you received, verbatim. Be concrete and short. Never quote or invent an address, host name,
account, serial or secret; the repository holds none and neither should your output. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 6)
- docs/design/PO_DECISION_RECORD_2026_10_31_Q41_Q42_Q44.md
- java/persistence/src/main/resources/db/migration/V3__policy_scope_and_retirement.sql and V9__single_admin_withdrawal.sql
- java/persistence/src/main/java/io/rwsafe/persistence/PolicyRegistryStore.java
- every file under java/control/src/main/java/io/rwsafe/control/policy/
- frontend/src/pages/PoliciesPage.tsx
- every test that names "Withdraw", "PolicyRegistry" or "SnapshotCompiler"
```

#### Additional Metadata & User Rules (`<user_rules>`)
- Workspace rule loaded from [`AGENTS.md`](file://<workspace-root>/AGENTS.md#L1-L187) (sections 1–14, verbatim in repository root).
- Slash-command wrapper metadata `/plan` attached by the CLI harness.
