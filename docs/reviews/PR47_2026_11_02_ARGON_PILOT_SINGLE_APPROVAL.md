<!-- Argon consultation 2026-11-02T08:20:41Z, model gemini-4-argon-high, effort high; unaltered output except 26 local paths masked (AGENTS.md 4.2) -->

Role: `REVIEWER`

### (1) CONSENT Table

| Area | Verdict |
| :--- | :--- |
| Authority & scope ([PO_DECISION_RECORD_2026_11_02_Q47_ADMIN_SECTION.md](file://<workspace-root>/docs/design/PO_DECISION_RECORD_2026_11_02_Q47_ADMIN_SECTION.md), [PO_DECISION_RECORD_2026_10_30_POLICY_SCOPE_AND_PLATFORM_RETIREMENT.md](file://<workspace-root>/docs/design/PO_DECISION_RECORD_2026_10_30_POLICY_SCOPE_AND_PLATFORM_RETIREMENT.md)) | **CONSENT** — Ratified PO decision Q-47 (decision 2) amends Q-39/Q-40 decision 3 for the pilot only while the switch is on. |
| Role enforcement (`security_admin` vs `privacy_officer`, viewer, masked role) in [`PolicyRegistryService.approve`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/policy/PolicyRegistryService.java#L349-L378), [`PolicyApiController.approve`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/policy/PolicyApiController.java#L71-L76), [`PolicyRegistryStore.approve`](file://<workspace-root>/java/persistence/src/main/java/io/rwsafe/persistence/PolicyRegistryStore.java#L199-L261) | **CONSENT** — Viewers and `replay_viewer` (even if paired with another role) are refused with HTTP 403; `privacy_officer` never activates alone in service, store, trigger, or compiler. |
| Immutability and ledger binding in [V10__single_approval_activation.sql](file://<workspace-root>/java/persistence/src/main/resources/db/migration/V10__single_approval_activation.sql#L17-L191) and [SingleApprovalActivationTest.java](file://<workspace-root>/java/persistence/src/test/java/io/rwsafe/persistence/SingleApprovalActivationTest.java) | **CONSENT WITH MINOR FINDING (D-02)** — `single_approval_by` and `single_approval_reason` cannot be set on `INSERT` or modified after the `pending -> active` transition, and the trigger verifies `app.single_approval = 'on'`, the single `security_admin` approval row, `app.actor_fingerprint`, `app.action_id = 'policy.activate_single_approval'`, and `app.reason_code`. |
| Compiler fail-closed invariants in [`SnapshotCompiler`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/policy/SnapshotCompiler.java#L46-L227) and [SnapshotCompilerTest.java](file://<workspace-root>/java/control/src/test/java/io/rwsafe/control/policy/SnapshotCompilerTest.java) | **CONSENT** — Fail-closed class baselines, flow `enforceFailClosed`, non-empty non-defective platform rows, and group-scoped fail-closed checks are unchanged; `approved(v)` requires an exact match between `v.singleApproval().activatedBy()` and the sole `security_admin` approval's `approverFingerprint` with a non-blank reason. |
| Identifier, estate, logging, and masked-role protection in [`PolicyRegistryService.reasonText`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/policy/PolicyRegistryService.java#L469-L493) and [PolicySingleApprovalIntegrationTest.java](file://<workspace-root>/java/control/src/test/java/io/rwsafe/control/policy/PolicySingleApprovalIntegrationTest.java#L101-L154) | **CONSENT** — Free-text reasons fail closed (HTTP 503) if the masking key or estate dictionary is unavailable, reject control characters, estate terms, and identifier shapes without echoing the input, never log the reason, and withhold the reason from the masked view. |
| Default configuration & pilot overlay in [`ControlProperties.Policy`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/config/ControlProperties.java#L180-L205), [application.yaml](file://<workspace-root>/java/control/src/main/resources/application.yaml#L88-L90), [10-pilot-config.yaml](file://<workspace-root>/deploy/rwsafe/overlays/pilot/10-pilot-config.yaml#L32-L36), [render.py](file://<workspace-root>/tools/pilot/render.py#L309-L312) | **CONSENT** — Default is `false` in Java and YAML, enabled in `10-pilot-config.yaml` only, and `render.py` passes `pilot=True` only when `TARGETS[target] == mc.PILOT_OVERLAY`. |
| Manifest checker single-approval rules in [`check_single_approval`](file://<workspace-root>/tools/deploy/manifest_check.py#L468-L507) | **DISSENT (D-01)** — Bypassable via value-carrying environment variables, `ConfigMap.binaryData`, uncommitted contract keys, separated JSON in `args`, or conflicting spellings. |
| UI and service handling when `privacy_officer` approves first while switch is on in [PoliciesPage.tsx](file://<workspace-root>/frontend/src/pages/PoliciesPage.tsx#L520-L595) and [`PolicyRegistryService.approve`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/policy/PolicyRegistryService.java#L359-L374) | **DISSENT (D-03)** — Forces a single-approval reason on the second of two approvals and then silently drops that reason in `PolicyRegistryStore.approve`. |

---

### (2) DISSENT Table

| Finding ID | File and Line or Symbol | What Is Wrong | Severity | Concrete Correction |
| :--- | :--- | :--- | :--- | :--- |
| **D-01** | [manifest_check.py](file://<workspace-root>/tools/deploy/manifest_check.py#L468-L507) (`_names_single_approval`, `check_single_approval`), [test_manifest_check.py](file://<workspace-root>/tools/deploy/test_manifest_check.py#L862-L957) (`SingleApprovalSwitch`) | 1. `check_single_approval` only inspects `ConfigMap.data` keys and `container.env` names matching `_names_single_approval`. It never inspects the *values* of other keys/env vars, so `SPRING_APPLICATION_JSON` or `JAVA_TOOL_OPTIONS` / `JDK_JAVA_OPTIONS` (in `ConfigMap.data` or `container.env`) setting `rwsafe.policy.single-approval=true` turns on the switch outside the pilot overlay undetected.<br>2. It ignores `ConfigMap.binaryData` (unlike line 522) and uncommitted contract keys in `contracts` (`secrets`, `configMaps`, `build.configMaps`), even though `application.yaml` imports mounted secret files via `spring.config.import: optional:configtree:...` and pods import ConfigMaps via `envFrom`.<br>3. Line 504 checks `"POLICYSINGLEAPPROVAL" in re.sub(r"[^A-Za-z0-9]", "", arg).upper()`, which misses nested `--spring.application.json` arguments where another key under `policy` separates `policy` and `single-approval`.<br>4. When `pilot=True`, it permits `container.env` or alternate spellings (such as `rwsafe.policy.single-approval`) to set `"true"` alongside `RWSAFE_POLICY_SINGLE_APPROVAL: "false"` in the control ConfigMap, contradicting line 506 (`"it is set in the control ConfigMap only"`). | **P1** | In `check_single_approval`:<br>1. Allow the switch to be named only by the exact key `RWSAFE_POLICY_SINGLE_APPROVAL` in `ConfigMap.data` (and `container.env` only if intended, or restrict to `ConfigMap/<product>/<product>-control-config` only as line 506 states), with literal `"true"` or `"false"` when `pilot=True` and `"false"` when `pilot=False`.<br>2. Refuse any other `ConfigMap` `data` or `binaryData` key or value, any `container.env` name or value, any `command`/`args` string, and any key in `contracts` whose stripped uppercase form (`re.sub(r"[^A-Za-z0-9]", "", s).upper()`) contains `"SINGLEAPPROVAL"`.<br>3. Add unit tests in `SingleApprovalSwitch` covering `SPRING_APPLICATION_JSON`, `JAVA_TOOL_OPTIONS`, separated JSON in `args`, `binaryData`, and contract keys. |
| **D-02** | [V10__single_approval_activation.sql](file://<workspace-root>/java/persistence/src/main/resources/db/migration/V10__single_approval_activation.sql#L170-L184) (`rwsafe_policy_rule_version_guard`) | At line 170, the `OLD.status = 'pending' AND NEW.status = 'active'` check tests `IF NEW.single_approval_by IS NOT NULL THEN` without checking `OR NEW.single_approval_reason IS NOT NULL` (unlike lines 38 and 72, and unlike V9 line 108). If an `UPDATE` sets `single_approval_by = NULL` and `single_approval_reason = '<reason>'` on a version that holds 2 approvals, the trigger skips the single-approval check and passes `ELSIF roles < 2 OR people < 2`, falling back to the table check constraint (`POLICY_CONSTRAINT_REFUSED`) instead of raising `POLICY_SINGLE_APPROVAL_REFUSED`. | **P2** | Change line 170 to `IF NEW.single_approval_by IS NOT NULL OR NEW.single_approval_reason IS NOT NULL THEN` and add `NEW.single_approval_by IS NULL OR NEW.single_approval_reason IS NULL OR` to the `IF` condition at line 173. |
| **D-03** | [PolicyRegistryService.java](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/policy/PolicyRegistryService.java#L359-L374) (`approve`), [PolicyRegistryStore.java](file://<workspace-root>/java/persistence/src/main/java/io/rwsafe/persistence/PolicyRegistryStore.java#L233-L250) (`approve`), [PoliciesPage.tsx](file://<workspace-root>/frontend/src/pages/PoliciesPage.tsx#L520-L595) (`ApprovalSteps`) | When `config.singleApproval()` is `true` and a `privacy_officer` has already approved a pending version, the subsequent `security_admin` approval completes a two-person approval rather than activating alone. However, `PolicyRegistryService.approve` (line 359) and `ApprovalSteps` (line 521) still require a non-empty `reason` (refusing `reason == null` with `400 INVALID_SINGLE_APPROVAL`), and `PolicyRegistryStore.approve` (line 235, `roles == 2`) then silently discards the validated `reason`, writing neither `single_approval_reason` on the version nor the entered reason in `audit_event` (recording `TWO_APPROVALS` instead). | **P2** | 1. In `PoliciesPage.tsx` line 521, set `const withReason = (role: ApproverRole) => single && role === 'security_admin' && !given('privacy_officer');`.<br>2. In `PolicyRegistryService.approve` and `PolicyRegistryStore.approve`, require `reason` only when `roles < 2` (activating alone), and refuse a non-null `reason` with `SINGLE_APPROVAL_NOT_AVAILABLE` when `privacy_officer` has already approved the version. Update `PolicySingleApprovalIntegrationTest.aPrivacyOfficerNeverActivatesAlone` line 175 accordingly. |

---

### (3) QUESTIONS FOR THE PRODUCT OWNER

| Question | Recommendation |
| :--- | :--- |
| **Q-1:** When `RWSAFE_POLICY_SINGLE_APPROVAL` is turned off at go-live ([PO_DECISION_RECORD_2026_11_02_Q47_ADMIN_SECTION.md](file://<workspace-root>/docs/design/PO_DECISION_RECORD_2026_11_02_Q47_ADMIN_SECTION.md#L30-L32), lines 30–32 and 45–46), [`SnapshotCompiler.approved`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/policy/SnapshotCompiler.java#L205-L227) continues to compile and re-sign active versions that were single-approved during the pilot (`v.singleApproval() != null`). At go-live, should policy versions that were activated by one administrator during the pilot continue to be enforced until replaced, or must every single-approved active version be superseded by a two-person-approved version before go-live turns the switch off? | **Recommend** requiring in the go-live checklist/readiness check that every active version with `single_approval_by IS NOT NULL` be superseded by a two-person-approved version before `RWSAFE_POLICY_SINGLE_APPROVAL` is turned off, while keeping `SnapshotCompiler.approved` accepting existing `singleApproval` rows during the transition so `checkActivation` does not deadlock when multiple rules are replaced one by one. |

---

### (4) Verdict

MERGE WITH CORRECTIONS

---

### (5) Verbatim Instructions Received

```text
/plan REVIEW: second independent review of pull request 47 (AGENTS.md section 9, security-sensitive: the policy registry,
a database guard function, deploy manifests and the manifest checker), branch `feature/pilot-single-approval`
LENS: whether the pilot-only single-approval switch (PO decision Q-47, decision 2) lets one `security_admin` activate a
policy version alone ONLY in the pilot, ONLY with a reason, always ledgered, and changes nothing when the switch is off.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway; a public repository).
You start from a fresh context. Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this
repository. Do not edit, run shell, or widen the review. Your job: find any path where a version becomes active, or is
compiled into a signed snapshot, with fewer than two approvals by two people while the switch is off; any path where
the switch can be turned on outside the pilot overlay, or by a value, spelling, env source or argument the manifest
checker misses; any way a privacy officer, a viewer or the masked role activates alone; any way the reason or the
ledger row is skipped, forged or edited later; any weakening of the compiler's fail-closed checks; any identifier or
prompt body reaching a reason, a log or the masked view. Return exactly: (1) a CONSENT table (area, verdict), (2) a
DISSENT table (finding id, file and line or symbol, what is wrong, severity P0/P1/P2, the concrete correction), (3)
QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation), (4) a one-line verdict MERGE / MERGE WITH CORRECTIONS
/ DO NOT MERGE, then (5) list every instruction you received, verbatim. Be concrete and short. Never quote or invent an
address, host name, account, serial or secret. English only.

Files to read, in this order:
- AGENTS.md (sections 1, 6, 7, 9)
- docs/design/PO_DECISION_RECORD_2026_11_02_Q47_ADMIN_SECTION.md
- docs/design/PO_DECISION_RECORD_2026_10_30_POLICY_SCOPE_AND_PLATFORM_RETIREMENT.md
- java/persistence/src/main/resources/db/migration/V9__single_admin_withdrawal.sql and V10__single_approval_activation.sql
- java/control/src/main/java/io/rwsafe/control/policy/PolicyRegistryService.java, PolicyRegistryStore.java (or the
  store class the service uses), SnapshotCompiler.java, and the policy REST controller
- java/control/src/main/java/io/rwsafe/control/config/ControlProperties.java and java/control/src/main/resources/application.yaml
- the tests: SingleApprovalActivationTest, SnapshotCompilerTest, PolicySingleApprovalIntegrationTest
- deploy/rwsafe/overlays/pilot/10-pilot-config.yaml, tools/deploy/manifest_check.py (the single-approval rules),
  tools/deploy/test_manifest_check.py (SingleApprovalSwitch), tools/pilot/render.py
- frontend/src/pages/PoliciesPage.tsx and frontend/src/api.ts
```
