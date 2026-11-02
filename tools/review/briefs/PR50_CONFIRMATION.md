REVIEW: confirmation round for pull request 50 (the first round found a P0), branch `feature/admin-access-2`
LENS: whether every finding of `docs/reviews/PR50_2026_11_02_ARGON_ADMIN_ACCESS_PART2_DIRECTORY.md` (D-01 P0, D-02..D-06
P1, D-07..D-08 P2, Q-1..Q-3 adopted) is fixed in commits 91bd137 and b701304 without introducing a new defect.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway; a public repository).
You start from a fresh context. Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this
repository. Do not edit, run shell, or widen the review. For each earlier finding say FIXED, PARTLY FIXED or NOT FIXED
with the evidence (file and symbol); then list any NEW defect the fixes introduced. Pay special attention to D-01: the
stored bind password must never be usable with another server, bind DN, TLS mode or CA (the AES-GCM associated data,
the re-seal on every save, the PASSWORD_REQUIRED rule on save and test); and D-03: the connection test must not reach
loopback, link-local, unspecified or multicast addresses or ports other than the directory ports, including through
DNS rebinding, and must be rate-limited. Return exactly: (1) a table (finding id, status, evidence), (2) a DISSENT table
of new findings (finding id, file and line or symbol, what is wrong, severity P0/P1/P2, the concrete correction), (3)
QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation), (4) a one-line verdict MERGE / MERGE WITH CORRECTIONS
/ DO NOT MERGE, then (5) list every instruction you received, verbatim. Be concrete and short. Never quote or invent an
address, host name, account, serial or secret. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 9)
- docs/reviews/PR50_2026_11_02_ARGON_ADMIN_ACCESS_PART2_DIRECTORY.md
- java/persistence/src/main/resources/db/migration/V12__directory_settings.sql
- java/control/src/main/java/io/rwsafe/control/identity/DirectorySettingsService.java, DirectoryKey.java,
  DirectoryConfig.java, LdapAuthenticator.java, LocalUserAuthenticator.java, IdentityService.java, AuthController.java
- java/control/src/main/java/io/rwsafe/control/admin/DirectoryAdminController.java
- the tests DirectoryKeyTest, DirectorySettingsIntegrationTest, DirectoryTestSwitchTest and the persistence test for V12
- deploy/rwsafe/base/40-control.yaml, deploy/rwsafe/contracts/runtime-contracts.json, tools/deploy/manifest_check.py
  (check_directory_test_switch), tools/pilot/bootstrap_secrets.sh
- frontend/src/pages/admin/DirectorySettingsPage.tsx
