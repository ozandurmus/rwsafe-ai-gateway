REVIEW: second independent review of pull request 50 (AGENTS.md section 9, security-sensitive: identity, directory
authentication and TLS, an encrypted credential, a key Secret, RBAC, a migration with a guard, deploy manifests),
branch `feature/admin-access-2`
LENS: whether Administration → ACCESS → LDAP settings (PO decision Q-47 decision 1.2: the directory connection entered
and tested on the screen, groups bound to roles on the screen) keeps the bind password secret, keeps directory TLS
strict, keeps role derivation correct and exclusive, and never leaks a directory identifier.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway; a public repository).
You start from a fresh context. Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this
repository. Do not edit, run shell, or widen the review. Your job: find any way the bind password is returned, logged,
stored unencrypted, carried to a different server than it was saved for, or decrypted without the key (and any
plaintext fallback when the key is missing); any AES-GCM misuse (nonce reuse, missing authentication data binding the
ciphertext to its version); any weakening of directory TLS (host-name verification, trust, StartTLS downgrade, plain
LDAP beyond loopback); any connection-test abuse (server-side request forgery to arbitrary hosts and ports, timing or
error oracles that reveal user existence or directory content, missing rate limit or timeout); any role escalation
through group bindings (a group granting roles it should not, replay_viewer exclusivity broken, name collisions,
normalisation mismatch, the local-user authority rule bypassed); any directory identifier (DN, group name, login name)
reaching a log, metric label, the masked view, an export or the SIEM; any route the masked role reaches; any guard or
ledger rule that can be bypassed; any manifest or contract change that weakens the Secret's handling. Return exactly:
(1) a CONSENT table (area, verdict), (2) a DISSENT table (finding id, file and line or symbol, what is wrong, severity
P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation), (4) a one-line
verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then (5) list every instruction you received, verbatim. Be
concrete and short. Never quote or invent an address, host name, account, serial or secret. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 5, 8, 9)
- docs/design/PO_DECISION_RECORD_2026_11_02_Q47_ADMIN_SECTION.md
- java/persistence/src/main/resources/db/migration/V12__directory_settings.sql and the persistence classes it backs
- java/control/src/main/java/io/rwsafe/control/identity/DirectorySettingsService.java, DirectoryKey.java,
  DirectoryConfig.java, LdapAuthenticator.java, IdentityService.java, LocalUsers.java (reason checks), Authenticator.java
- java/control/src/main/java/io/rwsafe/control/admin/DirectoryAdminController.java and DirectoryViews.java
- java/control/src/main/java/io/rwsafe/control/config/ControlProperties.java and java/control/src/main/resources/application.yaml
- the tests for these classes, MaskedRoleLeakProbeTest and FailClosedProbe
- deploy/rwsafe/base/40-control.yaml, deploy/rwsafe/contracts/runtime-contracts.json, tools/pilot/bootstrap_secrets.sh
- frontend/src/pages/admin/DirectorySettingsPage.tsx, frontend/src/adminMenu.tsx, frontend/src/api.ts
