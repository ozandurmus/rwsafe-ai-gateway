<!-- Argon consultation 2026-11-02T09:18:52Z, model gemini-4-argon-high, effort high; unaltered output except 65 local paths masked (AGENTS.md 4.2) -->

Role: `REVIEWER`

### (1) CONSENT

| Area | Verdict |
| :--- | :--- |
| Bind password write-only API contract (`passwordSet` boolean, never echoed in [DirectoryViews.java](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/admin/DirectoryViews.java) or [DirectorySettingsPage.tsx](file://<workspace-root>/frontend/src/pages/admin/DirectorySettingsPage.tsx), `Cache-Control: no-store` on all [DirectoryAdminController.java](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/admin/DirectoryAdminController.java) routes) | **CONSENT** |
| AES-256-GCM key separation, 12-byte `SecureRandom` nonce per seal, 128-bit tag, key zeroisation after each operation, and fail-closed refusal when the key Secret is missing or invalid ([DirectoryKey.java](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/DirectoryKey.java), [DirectoryKeyTest.java](file://<workspace-root>/java/control/src/test/java/io/rwsafe/control/identity/DirectoryKeyTest.java)) | **CONSENT** |
| Certificate SAN verification (strict `dNSName` / `iPAddress` matching, no CN fallback, no StartTLS clear-text fallback, empty-password anonymous-bind refusal) in [`LdapAuthenticator.Verifier`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/LdapAuthenticator.java#L367-L446) | **CONSENT** |
| Append-only versioned persistence, advisory lock and optimistic concurrency (`expectedVersion`), and audit trigger wiring in [V12__directory_settings.sql](file://<workspace-root>/java/persistence/src/main/resources/db/migration/V12__directory_settings.sql) and [DirectorySettingsStore.java](file://<workspace-root>/java/persistence/src/main/java/io/rwsafe/persistence/DirectorySettingsStore.java) | **CONSENT** |
| RBAC and masked-role (`replay_viewer`) 403 refusal on all `/api/v1/admin/directory/**` routes, plus masked projection withholding in [DirectoryViews.java](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/admin/DirectoryViews.java#L126-L131), [MaskedRoleLeakProbeTest.java](file://<workspace-root>/java/control/src/test/java/io/rwsafe/control/privacy/MaskedRoleLeakProbeTest.java#L696-L702), and [FailClosedProbe.java](file://<workspace-root>/java/control/src/test/java/io/rwsafe/control/privacy/FailClosedProbe.java#L71-L107) | **CONSENT** |
| Redacted `toString()` implementations and identifier-free log statements across [DirectorySettings.java](file://<workspace-root>/java/persistence/src/main/java/io/rwsafe/persistence/DirectorySettings.java), [DirectoryConfig.java](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/DirectoryConfig.java), [DirectorySettingsService.java](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/DirectorySettingsService.java), and [LdapAuthenticator.java](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/LdapAuthenticator.java) | **CONSENT** |
| Secret generation and cleanup in [bootstrap_secrets.sh](file://<workspace-root>/tools/pilot/bootstrap_secrets.sh) and contract declaration in [runtime-contracts.json](file://<workspace-root>/deploy/rwsafe/contracts/runtime-contracts.json) | **CONSENT** |

---

### (2) DISSENT

| ID | File and line / symbol | What is wrong | Severity | Concrete correction |
| :--- | :--- | :--- | :--- | :--- |
| **D-01** | [`DirectorySettingsService.saveConnection`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/DirectorySettingsService.java#L332-L344), [`DirectorySettingsService.testConfig`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/DirectorySettingsService.java#L400-L408), [`DirectoryKey.seal` / `open`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/DirectoryKey.java#L49-L118) | **Stored bind password carried to a different server, bind DN, TLS mode, or CA bundle:** `testConfig` checks `x.urls().equals(v.urls()) && x.bindDn().equals(v.bindDn())` when `newPassword` is omitted, but `saveConnection` (`#L332-L336`) has no such check. Saving new `urls` or `bindDn` (or changing `tlsMode` / `caCertificatePem` / `clearCaCertificate`) with an empty `newPassword` copies the previous `bindPasswordSealed` into the new version and calls `reload()`, which immediately connects to the new server and binds with the old decrypted password (and allows a subsequent `test(null)` to send it). Even in `testConfig`, `tlsMode` and `caCertificatePem` / `clearCaCertificate` can be altered while reusing the stored password. In addition, [`DirectoryKey.AAD`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/DirectoryKey.java#L49) is a static constant that does not bind the ciphertext to the connection identity (`urls`, `tlsMode`, `bindDn`). | **P0** | 1. In both [`saveConnection`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/DirectorySettingsService.java#L332-L338) and [`testConfig`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/DirectorySettingsService.java#L400-L408), allow omitting `newPassword` **only** when `current` is present and `urls`, `bindDn`, `tlsMode`, and the effective `caCertificatePem` are all unchanged; otherwise refuse with `400 PASSWORD_REQUIRED`.<br>2. Pass canonical `(urls, tlsMode, bindDn)` into [`DirectoryKey.seal`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/DirectoryKey.java#L68-L85) and [`DirectoryKey.open`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/DirectoryKey.java#L88-L118) as part of the GCM AAD (and re-seal under the existing contexts when copying unchanged connection settings) so a sealed password cannot be decrypted for another server, TLS mode, or bind DN.<br>3. Also bound `newPassword` UTF-8 length (e.g. `<= 1024` bytes) in `validate()` and wipe the encoded `byte[]` in [`LdapAuthenticator.utf8`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/LdapAuthenticator.java#L516-L520) as [`DirectoryKey.utf8`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/DirectoryKey.java#L137-L145) does. |
| **D-02** | [40-control.yaml](file://<workspace-root>/deploy/rwsafe/base/40-control.yaml#L69-L74) (`#L69-L74`, `#L208-L213`), [bootstrap_secrets.sh](file://<workspace-root>/tools/pilot/bootstrap_secrets.sh#L15-L18) (`#L15-L18`, `#L178-L187`) | **Deploy manifest breaks startup when deploy-time LDAP seed objects are absent:** [bootstrap_secrets.sh](file://<workspace-root>/tools/pilot/bootstrap_secrets.sh#L15-L18) does not create Secret `rwsafe-ldap-bind` and creates ConfigMap `rwsafe-estate` with only `estate-dictionary.txt` because directory settings are entered on the screen (PO decision Q-47 decision 1.2). However, [40-control.yaml](file://<workspace-root>/deploy/rwsafe/base/40-control.yaml#L69-L74) still requires `ldap-url`, `ldap-bind-dn`, and `ldap-user-search-base` from `rwsafe-estate` without `optional: true`, and mounts Secret `rwsafe-ldap-bind` (`#L208-L213`) without `optional: true`, preventing pod creation whenever the optional seed is omitted. | **P1** | Mark the `ldap-bind` secret volume (`#L210`) and the `RWSAFE_LDAP_URL`, `RWSAFE_LDAP_BIND_DN`, and `RWSAFE_LDAP_USER_SEARCH_BASE` `configMapKeyRef` entries (`#L70, #L72, #L74`) with `optional: true` in [40-control.yaml](file://<workspace-root>/deploy/rwsafe/base/40-control.yaml). |
| **D-03** | [`DirectorySettingsService.urls`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/DirectorySettingsService.java#L563-L598), [`DirectorySettingsService.test` / `admit` / `run`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/DirectorySettingsService.java#L371-L464), [`LdapAuthenticator.connect`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/LdapAuthenticator.java#L325-L358) | **Connection-test SSRF to arbitrary ports/hosts and rate-limit/concurrency handling:** `urls()` accepts any port `1..65535` and any target address. Under `TlsMode.NONE` it connects to any loopback port (including the database, internal connectors, metrics, or co-hosted services); under `LDAPS`/`STARTTLS` it connects to loopback, link-local, or arbitrary internal host/port pairs and returns a detailed reachability/TLS oracle (`NAME_NOT_RESOLVED`, `TIMEOUT`, `CONNECTION_FAILED`, `STARTTLS_REFUSED`, `HANDSHAKE_FAILED`, `CERTIFICATE_UNTRUSTED`, `HOSTNAME_MISMATCH`, plus `server` index). Also, `admit()` (`#L373`) consumes a per-actor rate-limit token before `testConfig()` validates the request, and `test()` releases `oneTest` in `finally` (`#L381`) even if the worker thread in `testRunner` (`#L431`) is still blocked in an uninterruptible socket/DNS call after `f.cancel(true)`. | **P1** | 1. Restrict non-loopback directory URLs to standard directory ports (`389`, `636`, `3268`, `3269`), reject loopback, link-local, multicast, and unspecified addresses when `tlsMode != TlsMode.NONE`, and in `TlsMode.NONE` forbid the control plane's own ports (`5432`, `8080`, `8091`, `8092`, `9400`).<br>2. Validate `testConfig(input)` before consuming a rate-limit token in `admit()`, and release `oneTest` inside the submitted task's own `finally` block (with a bounded single-thread executor) so a timed-out socket cannot overlap with a new test. |
| **D-04** | [`DirectoryConfig.groupKey`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/DirectoryConfig.java#L64-L80), [`LdapAuthenticator.groups` / `roles`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/LdapAuthenticator.java#L252-L284), [`DirectorySettingsService.seedFromDeploy`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/DirectorySettingsService.java#L252-L268) | **Role escalation via cross-OU group RDN collision, `'='` normalisation mismatch, and `replay_viewer` non-exclusivity in `LdapAuthenticator`:**<br>1. `DirectoryConfig.groupKey` takes `first.getAttributeValues()[0]` of any DN without checking `!first.isMultiValued()` and [`LdapAuthenticator.groups`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/LdapAuthenticator.java#L254-L259) never checks `memberOf` DNs against `groupSearchBase` when `groupSearchBase` is configured, so an identically named group in an untrusted OU grants bound roles.<br>2. `DirectoryConfig.groupKey` treats any string with `'='` as a DN and, on `LDAPException`, passes `'='` through to `GroupNames.normalise` (which allows `'='`), whereas [`DirectorySettingsService.groups`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/DirectorySettingsService.java#L686) rejects `'='`. A seeded RDN value containing `'='` is re-parsed as a DN by `groupKey` and stored with `'='` in V12, breaking subsequent group saves.<br>3. [`LdapAuthenticator.roles`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/LdapAuthenticator.java#L274-L284) does not strip other roles when `replay_viewer` is present (unlike `probe` at `#L234-L236` and `IdentityService.exclusive`), so `LdapAuthenticator.authenticate` and `DirectorySettingsService.authenticate` return non-exclusive role sets. | **P1** | 1. Parse DNs only for DN sources (`memberOf` and group-search entry DNs), require `!first.isMultiValued()`, and when `groupSearchBase` is set, require `new DN(value).isDescendantOf(new DN(config.groupSearchBase()), false)` for `memberOf` values too.<br>2. Reject `'='` in short group names across `DirectoryConfig.groupKey` (after DN RDN extraction), `seedFromDeploy`, and [V12__directory_settings.sql](file://<workspace-root>/java/persistence/src/main/resources/db/migration/V12__directory_settings.sql#L79) (`name ~ '[[:cntrl:],=]'`).<br>3. Enforce `if (roles.contains(Roles.REPLAY_VIEWER)) return Set.of(Roles.REPLAY_VIEWER);` inside [`LdapAuthenticator.roles`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/LdapAuthenticator.java#L274-L284). |
| **D-05** | [`IdentityService.login`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/IdentityService.java#L51-L75), [`LdapAuthenticator.attempt`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/LdapAuthenticator.java#L141-L166) | **Local-user authority rule bypass via Turkish case-folding / whitespace or alternate filter attributes:** `LocalUserAuthenticator` normalises login names with `toLowerCase(Locale.ROOT)`. Signing in with uppercase Turkish dotted `İ` (`U+0130`, which `toLowerCase(Locale.ROOT)` turns into `i\u0307`) or surrounding whitespace misses the local user in PostgreSQL, so `front.authoritative(loginName)` (`IdentityService.java#L69`) returns `false` and the attempt falls through to LDAP, where directory case-folding or an alternate attribute in `userSearchFilter` can authenticate a disabled or lower-privileged local user. Also, the user search in `LdapAuthenticator.attempt` (`#L147`) and `probe` (`#L212`) sets no `sizeLimit`. | **P1** | 1. Strip and fold `loginName` (Turkish `İ`/`I`/`ı` fold and reject combining/control characters) at the start of [`IdentityService.login`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/IdentityService.java#L51) and in `LocalUserAuthenticator.authoritative`, and re-check `authoritative` against the matched LDAP entry's RDN attribute value before accepting an LDAP login.<br>2. Set `setSizeLimit(2)` on the user `SearchRequest` in [`LdapAuthenticator.attempt`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/LdapAuthenticator.java#L147) and [`probe`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/LdapAuthenticator.java#L212). |
| **D-06** | [`DirectorySettingsService.reason`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/DirectorySettingsService.java#L471-L482), [`saveConnection`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/DirectorySettingsService.java#L331), [`saveGroupRoles`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/DirectorySettingsService.java#L356) | **Directory identifiers in `reason` can reach the audit ledger and SIEM:** `directory_settings.reason` is written into `audit_event.reason_code` (`rwsafe_audit_row('version')`) and exported unmasked to the SIEM. `DirectorySettingsService.reason` only checks `folded.contains(IdentifierCheck.fold(g.group()))` as a contiguous substring (`#L475`), missing hyphenated/multi-word group names written as separate words or with Turkish suffixes (unlike [`LocalUsers.namesPerson`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/LocalUsers.java#L369-L389)), and `saveConnection` never checks RDN tokens of `bindDn`, `userSearchBase`, or `groupSearchBase` (from `input` and `current`). | **P1** | Pass all group names and the RDN values of `bindDn`, `userSearchBase`, and `groupSearchBase` (from both `current` and `input`) into [`LocalUsers.namesPerson`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/LocalUsers.java#L369-L389) inside [`DirectorySettingsService.reason`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/DirectorySettingsService.java#L471-L482) in addition to the substring check. |
| **D-07** | [`rwsafe_directory_settings_guard`](file://<workspace-root>/java/persistence/src/main/resources/db/migration/V12__directory_settings.sql#L78-L90), [`DirectorySettingsService.seedFromDeploy`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/DirectorySettingsService.java#L235-L287) | **Database guard gaps and uncaught persistence exceptions in `seedFromDeploy`:**<br>1. [`rwsafe_directory_settings_guard`](file://<workspace-root>/java/persistence/src/main/resources/db/migration/V12__directory_settings.sql#L87) checks `NEW.change_kind = 'seed'` for `system:%` actor, but does not forbid `system:%` actors on `'connection'` or `'group_roles'` inserts, does not forbid `'group_roles'` as version 1 (`latest IS NULL`), and allows duplicate role tokens (e.g. `'viewer viewer'`) in `group_role_sets` (`#L82`).<br>2. `seedFromDeploy` (`#L278-L281`) catches only `AccessRefusal` and `DirectoryKey.Unavailable`; if a deploy value violates a V12 `CHECK` constraint (e.g. `> 500` groups or a sealed password `> 2048` bytes), an uncaught `DataAccessException` aborts control-plane startup instead of skipping the seed with a warning. | **P2** | 1. In [V12__directory_settings.sql](file://<workspace-root>/java/persistence/src/main/resources/db/migration/V12__directory_settings.sql#L78-L90), enforce `(NEW.change_kind = 'seed') = (NEW.created_by LIKE 'system:%')`, forbid `NEW.change_kind = 'group_roles' AND latest IS NULL`, and reject duplicate roles in `group_role_sets`.<br>2. In [`seedFromDeploy`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/DirectorySettingsService.java#L252-L286), cap/validate seeded groups and catch `RuntimeException` (logging a fixed reason code only). |
| **D-08** | [`DirectorySettingsService.saveConnection` / `saveGroupRoles`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/DirectorySettingsService.java#L327-L362), [DirectorySettingsPage.tsx](file://<workspace-root>/frontend/src/pages/admin/DirectorySettingsPage.tsx#L156-L215) | **Open `"ldap"` sessions survive directory disablement / role revocation, and UI state issues:**<br>1. Unlike [`LocalUsers`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/LocalUsers.java#L154) (`sessions.endAll`), disabling the directory in `saveConnection` or removing roles in `saveGroupRoles` leaves existing `"ldap"` sessions active with old roles for up to 30 minutes.<br>2. In [DirectorySettingsPage.tsx](file://<workspace-root>/frontend/src/pages/admin/DirectorySettingsPage.tsx#L214), `bindingsReady` checks `!b.group.includes(',')` but omits `!b.group.includes('=')`, and `reload()` (`#L156-L162`, `#L194`) overwrites unsaved edits in the other section on save. | **P2** | 1. End open `"ldap"` sessions in `ActiveSessions` when `saveConnection` disables the directory or `saveGroupRoles` changes group-to-role bindings.<br>2. In [DirectorySettingsPage.tsx](file://<workspace-root>/frontend/src/pages/admin/DirectorySettingsPage.tsx#L214), add `!b.group.includes('=')` to `bindingsReady` and preserve unsaved edits in the non-saved section when updating from the `DirectoryView` response. |

---

### (3) QUESTIONS FOR THE PRODUCT OWNER

| # | Question | Recommendation |
| :--- | :--- | :--- |
| **Q-1** | Should `tls_mode = 'none'` (plain LDAP to a loopback test directory) be refused in production and hidden from the Administration → Access → LDAP settings dropdown unless an explicit test-only property is enabled? | **Yes.** Keep `tls_mode = 'none'` for automated loopback tests only, and restrict the production screen and runtime to `ldaps` and `starttls`. |
| **Q-2** | When an administrator disables the directory connection or changes group-to-role bindings on the LDAP settings screen, should open `"ldap"` sessions be ended immediately (matching local-user role changes and disablement)? | **Yes.** Ending open `"ldap"` sessions ensures revoked group privileges take effect immediately instead of after the 30-minute session timeout. |
| **Q-3** | When `groupSearchBase` is configured alongside `groupAttribute` (`memberOf`), should `memberOf` group DNs outside `groupSearchBase` be ignored? | **Yes.** Requiring every group DN to lie under `groupSearchBase` when set prevents a group with the same short name in another organizational unit from granting roles. |

---

### (4) VERDICT

**DO NOT MERGE** (resolve P0 finding **D-01** and P1 findings **D-02** through **D-06** before merge).

---

### (5) INSTRUCTIONS RECEIVED (VERBATIM)

1. System developer instruction (`<identity>`):
```text
You are Antigravity, a powerful agentic AI coding assistant designed by the Google Deepmind team working on Advanced Agentic Coding.
You are pair programming with a USER to solve their coding task. The task may require creating a new codebase, modifying or debugging an existing codebase, or simply answering a question.
The USER will send you requests, which you must always prioritize addressing. User requests are enclosed within <USER_REQUEST> tags.
```

2. System developer instruction (`<artifacts>`):
```text
Artifacts are special markdown (.md) documents that you can create to present structured information to the user.
All artifacts should be written to the artifact directory: `<appDataDir>/brain/<conversation-id>`. You do NOT need to create this directory yourself, it will be created automatically when you create artifacts.

# When to Use Artifacts

**Use artifacts for:**
- Extensive reports and analysis summaries
- Persistent information you'll update over time (task lists, experiment logs)
- Code changes formatted as diffs

**Don't use artifacts for:**
- Simple one-off answers or very short paragraph content - just respond directly
- Asking questions or requesting user input - just ask directly

**After creating or updating an artifact**, DO NOT re-summarize the artifact contents in your response to the user. Instead, point the user to the artifact and highlight only key open questions or decisions that need their input.


# Artifact Formatting Tips
When creating markdown artifacts, use standard markdown and GitHub Flavored Markdown formatting.

## Alerts
Use GitHub-style alerts strategically to emphasize critical information. Do not place consecutively or nest:
  > [!NOTE] Background context, implementation details, or explanations
  > [!TIP] Performance optimizations, best practices, or efficiency suggestions
  > [!IMPORTANT] Essential requirements, critical steps, or must-know information
  > [!WARNING] Breaking changes, compatibility issues, or potential problems
  > [!CAUTION] High-risk actions that could cause data loss or security vulnerabilities


## Mermaid Diagrams
Create mermaid diagrams using fenced code blocks with language `mermaid` to visualize relationships, workflows, and architectures.
- Only use supported diagram types:
  - Flowcharts / Graphs: `flowchart TD` / `flowchart LR` / `graph TD` / `graph LR`
  - Sequence Diagrams: `sequenceDiagram`
  - State Diagrams: `stateDiagram-v2` or `stateDiagram`
  - Class Diagrams: `classDiagram`
  - Entity-Relationship Diagrams: `erDiagram`
  - XY Charts: `xychart-beta`
- All other diagram types are unsupported. For schedules, timelines, or roadmaps, use directed flowcharts (`flowchart LR` / `flowchart TD`) or Markdown tables instead.
- To prevent syntax errors:
  - Quote node labels containing special characters like parentheses or brackets. For example, `id["Label (Extra Info)"]` instead of `id[Label (Extra Info)]`.
  - Avoid HTML tags in labels.

## File Links
- Link to line ranges using [link text](file:///absolute/path/to/file#L123-L145) format.
- **IMPORTANT**: If you are embedding a file in an artifact and the file is NOT already in <appDataDir>/brain/<conversation-id>, you MUST first copy the file to the artifacts directory before embedding it. Only embed files that are located in the artifacts directory. Always use its absolute path `![caption](/absolute/path)`.
- **Use basenames for readability**: Use file basenames for the link text instead of the full path

## Carousels
Use ````carousel syntax with `<!-- slide -->` HTML comments to display related markdown snippets sequentially (before/after comparisons, UI progressions, alternative approaches, walkthroughs). Four backticks enable nesting code blocks within slides.

Example:
````carousel
![Image description](/absolute/path/to/image1.png)
<!-- slide -->
```python
def example():
    print("Code in carousel")
```
````

# Scratch Scripts and Files

You may find it useful to create scratch scripts or files for temporary purposes.

Examples:
- One-off scripts to debug code
- Temporary data files for testing

Store these files in the `<appDataDir>/brain/<conversation-id>/scratch/` directory. They will be persisted.
```

3. System developer instruction (`<conversation_transcript>`):
```text
Transcripts are located directly at `<appDataDir>/brain/<conversation-id>/.system_generated/logs/transcript.jsonl` (and `transcript_full.jsonl`).
- Start with `transcript.jsonl` (compact). When `truncated_fields` is present, read only the specific corresponding line in `transcript_full.jsonl`.
- Search subagents by grepping `invoke_subagent` in `transcript.jsonl`.
- Link conversations using `[<label>](conversation://<conversation-id>)`.

# File Format
Transcripts are in JSON Lines (JSONL) format. Each line is a single JSON object representing one "step" or action in the conversation.
Each JSON object contains fields such as:
- `step_index`: The index of the step in the trajectory.
- `source`: The source of the action (e.g., `USER_EXPLICIT`, `MODEL`, `SYSTEM`).
- `type`: The type of the step. Particular steps of interest are `USER_INPUT`, which represents a user's prompt, and `PLANNER_RESPONSE`, which represents the agent's response and tool calls.
- `status`: The status of the step (e.g., `DONE`, `ERROR`).
- `created_at`: The ISO 8601 timestamp of when the step occurred.
- `content`: The text content of the step (e.g., the user's request, the model's response, or tool responses).
- `thinking`: The model's internal reasoning / chain-of-thought (for `PLANNER_RESPONSE` steps).
- `tool_calls`: An array of tool calls made in this step, including their arguments.
- `media`: An array of media (e.g. images) attached to the step, each with a `mime_type` and a `uri` referencing the media file on disk. Media bytes are not stored in the transcript; view the `uri` path to see the media.
- `truncated_fields`: An array of field names that were truncated (e.g., `["content"]`, `["thinking"]`, `["tool_calls"]`). Only present in `transcript.jsonl` when truncation occurred (never in `transcript_full.jsonl`). When present, read the corresponding line in `transcript_full.jsonl` for the complete content.
```

4. System developer instruction (`<guidelines>`):
```text
Follow these behavioral guidelines at all times:
- Maintain documentation integrity. Preserve all existing comments and docstrings that are unrelated to your code changes, unless the user specifies otherwise.
- Never defeat or bypass an access control, permission check, credential requirement, network/proxy restriction, or sandbox/environment boundary - including writing to the state or processes such a check reads, spoofing identity, intercepting the check, probing undocumented local/host services, or modifying host, harness, or test infrastructure outside your task scope. Use documented, sanctioned paths only; if none of them work, you are blocked - report the error and stop.
```

5. System developer instruction (`<communication_style>`):
```text
- Keep your responses concise.
- Format your responses in github-style markdown.
- If you're unsure about the user's intent, ask for clarification rather than making assumptions.
- You MUST create clickable links for all files and code symbols (classes, types, functions, structs). Use github style markdown links with the file:// scheme (e.g., [utils.py](file:///path/to/utils.py) or [`ClassName`](file:///path/to/utils.py#L10-L20)). For Windows, use forward slashes for paths.
```

6. System developer instruction (`<slash_commands>`):
```text
Slash commands are user-facing shortcuts in the chat UI (e.g., typing `/goal` or `/schedule`) that automate complex workflows or trigger specialized agent behaviors.

You cannot execute these commands yourself. Your role is to recommend them to the user when they are a good fit for the task at hand, encouraging the user to explore and trigger them.

To recommend a slash command, suggest it clearly in your response (e.g., "You can use the `/goal` command to...").


Available slash commands you can recommend to the user:
- /goal: Recommend this when the user wants to run a long-running task (e.g., overnight) and wants the agent to be extra thorough and not stop until the goal is fully achieved.
- /compact: Recommend this when the conversation is getting long and the user wants to compact or summarize the context to free up the context window.
- /schedule: Recommend this when the user wants to run an instruction on a recurring schedule or set a one-time timer.
- /browser: Recommend this when the user's task involves web browsing, searching the web, or interacting with web applications.
- /plan: Recommend this when the task is complex and requires careful step-by-step planning before execution.
- /grill-me: Recommend this when the user wants to align on a plan through an interactive interview to resolve design decisions.
- /teamwork: Recommend this when the user has a large project that would benefit from a team of autonomous agents working together.
- /learn: Recommend this when the user has corrected the agent or solved a complex setup and wants the agent to persist this behavior for future tasks.
- /boost: Recommend this when the user has a complex coding or research project that requires deep thinking, strategic planning, multiple perspectives, and rigorous verification.
```

7. System developer instruction (`<messaging>` and `<subagents>`):
```text
You are connected to a messaging system where you may receive messages from: agents, background tasks, user-queued messages.

## Receiving Messages

You receive messages automatically at the start of each invocation. All messages are delivered in full directly into your context — no manual retrieval is needed.

## Reactive Wakeup (No Polling Needed)

The system automatically resumes your execution when:
- A message arrives from a subagent or peer agent
- A **background task** completes or sends you a notification
- A **user-queued message** is ready to be dequeued

This means you do **NOT** need to poll in a loop while waiting for messages or updates. After launching anything that performs work asynchronously, you may continue other work or simply stop by calling no more tools. The system will notify you when there is something to process.

## Invoking Subagents

Subagents can be invoked using the invoke_subagent tool. You can invoke an existing subagent by name, or define a new subagent for this conversation using the define_subagent tool, and then invoke it. Agents defined by the define_subagent tool are available for the duration of this conversation. After launching a subagent, you do NOT need to poll or check your inbox in a loop. The system will automatically notify you when the subagent sends a message. Simply proceed with other work or stop calling tools, and you will be notified when there is a message to process.

## Communicating with Another Agent

Use the send_message tool to send a message to another agent by its conversation ID (returned by invoke_subagent). This tool is ONLY for communicating with other agents.

**Do NOT use send_message to communicate with the user.** Instead, output visible text to communicate with the user.

Available subagents:
- self: Subagent that inherits the parent agent's full configuration including tools, system prompt, and model. Use this when you need to run a task in a separate conversation context but with the same capabilities as the current agent.
- research: Research subagent with read-only tools for exploring the codebase, searching the web, and reading files. Delegate to this agent when you need to run a task in a separate conversation context, when a research task requires many search and file-reading steps that would clutter your context, or when you need a broad survey of the codebase or documentation. Prefer doing research yourself for quick, targeted lookups. This agent runs in a read-only sandbox with no network access.
- image-generator: Generates or edits images from a brief and replies with the saved file paths.

After launching a subagent, you do NOT need to poll or check your inbox in a loop. The system will automatically notify you when the subagent sends a message. Simply proceed with other work or stop calling tools, and you will be notified when there is a message to process.
```

8. User rules (`<user_rules>`): the full contents of [AGENTS.md](file://<workspace-root>/AGENTS.md) (lines 1–187).

9. User request (`<USER_REQUEST>`):
```text
/plan REVIEW: second independent review of pull request 50 (AGENTS.md section 9, security-sensitive: identity, directory
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
```

10. Additional metadata (`<ADDITIONAL_METADATA>` and `<USER_SETTINGS_CHANGE>`):
```text
The current local time is: 2026-11-02T12:08:44+03:00.

The user has mentioned some items in the form @[ITEM]. Here is extra information about the items that were mentioned by the user, in the order that they appear:

/plan is a [Slash Command]:
<PLAN>The user is requesting that you think and plan carefully before executing the upcoming task.
Carefully research the task, make sure that you and the user are aligned on the goals and requirements,
create a detailed implementation plan artifact, and get user approval on the plan before making any code changes (besides artifacts)
or running any modifying commands.
...
</PLAN>

The user changed setting `Model Selection` from None to Gemini 4 Argon (High). No need to comment on this change if the user doesn't ask about it. If reporting what model you are, please use a human readable name instead of the exact string.
```
