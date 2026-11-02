REVIEW: second independent review of pull request 47 (AGENTS.md section 9, security-sensitive: the policy registry,
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
