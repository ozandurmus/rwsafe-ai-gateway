<!-- Argon consultation 2026-10-30T18:09:39Z, model gemini-4-argon-high, effort high; unaltered output except 27 local paths masked (AGENTS.md 4.2) -->

Role: `REVIEWER`

### (1) CONSENT Table

| Area | Verdict |
|---|---|
| Two-person / two-role approval in application flow ([`PolicyRegistryService.approve`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/policy/PolicyRegistryService.java#L217-L235), [`PolicyRegistryStore.approve`](file://<workspace-root>/java/persistence/src/main/java/io/rwsafe/persistence/PolicyRegistryStore.java#L103-L150)) | **CONSENT** — Enforces `security_admin` and `privacy_officer` from two distinct pseudonyms under a per-rule transaction advisory lock and row `FOR UPDATE` lock. |
| Fail-closed class actions & exception refusal ([`RegistryVocabulary`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/policy/RegistryVocabulary.java#L28-L69), [`PolicyRegistryService.classDraft`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/policy/PolicyRegistryService.java#L152-L164), [`PolicyRegistryService.refuseException`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/policy/PolicyRegistryService.java#L238-L248)) | **CONSENT** — Every Tier-1 DLP class is fail-closed, refuses `ALLOW` and `WARN` in both `enforce` and `monitor` modes across API, DB check constraints, seed parser, and compiler, and refuses exceptions (`FAIL_CLOSED_NO_EXCEPTION`). |
| Ed25519 signing, key handling & internal connector isolation ([`SnapshotSigner`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/policy/SnapshotSigner.java#L26-L135), [`SnapshotFeedController`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/policy/SnapshotFeedController.java#L21-L72), [`InternalConnector`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/config/InternalConnector.java#L25-L93)) | **CONSENT** — Signs exact UTF-8 response bytes, fails closed with HTTP 503 when the key is missing or invalid, never logs key material, supports `ETag` / `If-None-Match` (`304`), and confines `/internal/v1/policy/snapshot` to the dedicated snapshot connector port. |
| Admin API RBAC & CSRF gate ([`SecurityConfig`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/SecurityConfig.java#L60-L103), [`AuthController`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/identity/AuthController.java#L94-L152)) | **CONSENT** — `viewer` and `replay_viewer` are blocked from all `POST` mutations (`403`); `replay_viewer` is blocked even if combined with another role; session IDs and CSRF tokens rotate on login; pseudonymisation fails closed (`503`) when the privacy key is missing. |
| Append-only triggers & C7 audit triggers ([`V2__policy_registry.sql`](file://<workspace-root>/java/persistence/src/main/resources/db/migration/V2__policy_registry.sql#L125-L186)) | **CONSENT** — `DELETE` and `TRUNCATE` are blocked on all three registry tables; `UPDATE` is blocked on `policy_approval` and `policy_snapshot`; `AFTER` triggers ledger every insert and lifecycle update. |
| React rendering & CSP ([`PoliciesPage.tsx`](file://<workspace-root>/frontend/src/pages/PoliciesPage.tsx#L1-L548), [`PlatformsPage.tsx`](file://<workspace-root>/frontend/src/pages/PlatformsPage.tsx#L1-L115)) | **CONSENT** — No raw HTML injection sinks (`dangerouslySetInnerHTML`, `innerHTML`) exist; `SecurityConfig` sets `script-src 'self'; object-src 'none'; base-uri 'none'`. |

---

### (2) DISSENT Table

| Finding ID | File and Line or Symbol | What Is Wrong | Severity | Concrete Correction |
|---|---|---|---|---|
| **D-01** | [`V2__policy_registry.sql`](file://<workspace-root>/java/persistence/src/main/resources/db/migration/V2__policy_registry.sql#L85-L123) (`rwsafe_policy_rule_version_guard`), [`SnapshotCompiler.java`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/policy/SnapshotCompiler.java#L59-L89) (`compile`) | Direct DB write bypasses two approvals: (1) `rwsafe_policy_rule_version_guard` allows `INSERT` with `source = 'seed'` and `status = 'active'` for any `version > 1`, any `mode`/`rollout_stage`, and any `author_fingerprint` with zero `policy_approval` rows; (2) `UPDATE` from `status = 'active'` to `status = 'superseded'` requires zero approvals and does not check that a replacement version is active (allowing direct DB deactivation of platform rules, since `SnapshotCompiler` allows an empty `platforms` list); (3) `SnapshotCompiler.compile()` does not verify that compiled `registry` versions actually hold 2 distinct approvals or that `platforms` is non-empty. | **P0** | In `V2__policy_registry.sql`, constrain `source = 'seed'` to `version = 1 AND mode = 'enforce' AND rollout_stage = 'all' AND author_fingerprint = 'system:seed-fixture' AND reason_code = 'SEED_FIXTURE'` and reject `source = 'seed'` inserts once any `'registry'` row exists; require `active -> superseded` updates to have an active replacement for `(rule_id, mode)` (or `'all'` stage). In `SnapshotCompiler.compile()`, refuse empty `rows` and refuse any baseline version that is neither `(source = 'seed' && version == 1)` nor backed by 2 distinct role/person approvals. |
| **D-02** | [`PolicySnapshotStore.java`](file://<workspace-root>/java/persistence/src/main/java/io/rwsafe/persistence/PolicySnapshotStore.java#L74-L106) (`current`, `reusable`), [`SnapshotFeedController.java`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/policy/SnapshotFeedController.java#L41-L54) (`snapshot`) | Direct DB write signing oracle and clock-skew staleness hazard: `PolicySnapshotStore.reusable()` checks only `latest.rulesDigest().equals(compiled.rulesDigest()) && latest.issuedAt().plus(refreshAfter).isAfter(now)`. It never verifies that `latest.document()` equals `compiled.render(latest.version(), latest.issuedAt()).document()`, that `sha256(latest.document()).equals(latest.documentSha256())`, or that `!latest.issuedAt().isAfter(now)`. A direct DB `INSERT` into `policy_snapshot` with the current `rules_digest`, a future `issued_at`, and tampered `document` JSON is served and signed with the live Ed25519 private key by `SnapshotFeedController`, and a future `issued_at` suppresses scheduled re-issuance past the 24-hour data-plane expiry. | **P0** | In `PolicySnapshotStore.reusable()`, require `!latest.issuedAt().isAfter(now)`, `latest.documentSha256().equals(sha256(latest.document()))`, and `compiled.render(latest.version(), latest.issuedAt()).document().equals(latest.document())`. In `PolicySnapshotStore.current()` line 88, use `now` rather than preserving a future `last.get().issuedAt()`. |
| **D-03** | [`V2__policy_registry.sql`](file://<workspace-root>/java/persistence/src/main/resources/db/migration/V2__policy_registry.sql#L63-L68), [`PolicyRegistryStore.java`](file://<workspace-root>/java/persistence/src/main/java/io/rwsafe/persistence/PolicyRegistryStore.java#L79-L122) (`draft`, `approve`), [`PoliciesPage.tsx`](file://<workspace-root>/frontend/src/pages/PoliciesPage.tsx#L214) (`RuleDetail`) | Multiple concurrent `pending` versions per rule allow latent single-actor activation: there is no unique index on `(rule_id) WHERE status = 'pending'` and `pending` versions cannot transition to `superseded`. If an older `pending` version `v2` receives 1 approval and a newer draft `v3` is created (or activated in the other `mode`), `PoliciesPage.tsx` hides `v2` (`rule.versions.find` shows only `v3`), but `v2` remains `pending` indefinitely in PostgreSQL and can be activated later by a single person holding the remaining role. | **P1** | Add `CREATE UNIQUE INDEX policy_rule_version_one_pending ON policy_rule_version (rule_id) WHERE status = 'pending'` (and/or supersede any prior `pending` version of `rule_id` inside `PolicyRegistryStore.draft()` before inserting the new draft, permitting `pending -> superseded` in `rwsafe_policy_rule_version_guard`). |
| **D-04** | [`PolicyRegistryService.java`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/policy/PolicyRegistryService.java#L179-L235) (`platformDraft`, `approve`), [`PolicyRegistryStore.java`](file://<workspace-root>/java/persistence/src/main/java/io/rwsafe/persistence/PolicyRegistryStore.java#L103-L150) (`approve`) | Time-of-check to time-of-use between draft and activation: `platformDraft()` validates `PlatformRow.defect(rows)` and `keys.estateTerms()` only against platform rules that are `active` at draft time. Two concurrently `pending` platform rules with overlapping `hostSuffixes` both pass `platformDraft()`; when both are approved, `approve()` activates the second without running `SnapshotCompiler.compile()` or `PlatformRow.defect()`, permanently breaking `SnapshotCompiler.compile()` (`503 SNAPSHOT_REGISTRY_INCOMPLETE`) and starving the data plane until its 24h snapshot expires. | **P1** | When the second approval activates a version (`roles == 2`), run `compiler.compile(PolicyRegistryStore.activeIn(tx))` and the estate-term check inside the transaction before committing; if compilation fails, abort the transaction and throw `RegistryRefusal(HttpStatus.CONFLICT, ...)`. |
| **D-05** | [`PolicyViews.java`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/policy/PolicyViews.java#L44-L103) (`VersionView.masked`, `SnapshotView`, `RegistryView.masked`), [`PolicyRegistryService.java`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/policy/PolicyRegistryService.java#L132-L208) (`draft`, `platformDraft`) | Masked-role (`replay_viewer`) leak of estate terms: (1) `RegistryView.masked(TextMasker)` masks `rules` (`ruleId` and `subject`) but returns `snapshot` (`SnapshotView`) unmasked, leaking `snapshot.ruleVersions()` (`platform.<id>@vN`) and `snapshot.keyId()`; (2) `VersionView.masked(TextMasker)` does not mask `reasonCode`; (3) `PolicyRegistryService` checks `hostSuffixes`, `apiHosts`, and `loginHosts` against `keys.estateTerms()`, but does not check `platformId` or `reasonCode` against `keys.estateTerms()`. | **P1** | Check `platformId` and `reasonCode` (case-insensitively) against `keys.estateTerms()` in `PolicyRegistryService.draft()`; mask `m.mask(reasonCode)` in `VersionView.masked(m)`; add `SnapshotView.masked(TextMasker m)` (masking `ruleVersions` and `keyId`) and invoke it in `RegistryView.masked(m)`. |
| **D-06** | [`V2__policy_registry.sql`](file://<workspace-root>/java/persistence/src/main/resources/db/migration/V2__policy_registry.sql#L57-L58), [`PolicyRegistryService.java`](file://<workspace-root>/java/control/src/main/java/io/rwsafe/control/policy/PolicyRegistryService.java#L98-L119) (`currentSnapshot`, `reissueWhenDue`) | (1) `policy_rule_version_fail_closed_flow` checks `NOT (kind = 'flow' AND mode = 'enforce' AND NOT enforce_fail_closed)`, allowing `enforce_fail_closed = false` when `mode = 'monitor'` at the DB layer (inconsistent with `flowDraft()` and `policy_rule_version_fail_closed_class`); (2) `PolicyRegistryService.currentSnapshot()` and `reissueWhenDue()` issue and ledger `policy_snapshot` rows with `reason_code = 'ACTIVE_POLICY_SIGNED'` without checking `signer.available()`, so snapshots are recorded as signed and shown as active in the UI even when the signing key is missing. | **P2** | Change `policy_rule_version_fail_closed_flow` to `CHECK (NOT (kind = 'flow' AND NOT enforce_fail_closed))`; check `signer.available()` in `PolicyRegistryService.currentSnapshot()` before issuing a snapshot row. |
| **D-07** | [`frontend/src/i18n/index.tsx`](file://<workspace-root>/frontend/src/i18n/index.tsx#L168-L174) (`I18nProvider`) | `label: (key, fallback) => lookup[key] ?? fallback` looks up runtime-constructed keys on `lookup` without `Object.prototype.hasOwnProperty.call(lookup, key)`, unlike `interpolate()` at line 56; a key colliding with `Object.prototype` returns a function object instead of `fallback`. | **P2** | Use `Object.prototype.hasOwnProperty.call(lookup, key) ? lookup[key] : fallback` in `label`. |

---

### (3) QUESTIONS FOR THE PRODUCT OWNER

| Question | Recommendation |
|---|---|
| **Q-1:** Should the registry enforce a mandatory progression through `monitor` (shadow evaluation) or staged rollout (`pilot` → `pct25` → `pct50` → `all`) before a new version can be drafted/activated at `mode = 'enforce'` and `rolloutStage = 'all'` (AGENTS.md section 6), or may `security_admin` + `privacy_officer` jump directly to `enforce` + `all` while format 1 of `POLICY_SNAPSHOT_CONTRACT.md` carries only the `all` baseline? | **Recommendation:** Allow direct `enforce` + `all` with two approvals while snapshot format 1 is in force (so emergency tightening of a DLP class from `REDACT` to `BLOCK` is not delayed by staging), and enforce mandatory staged progression when group-targeted snapshot format 2 lands. |
| **Q-2:** Once a custom `platform.<id>` rule reaches `active` (`enforce`, `all`), how should operators retire or remove that platform if a vendor is decommissioned, given that `policy_rule_version` is append-only and requires `cardinality(host_suffixes) BETWEEN 1 AND 32`? | **Recommendation:** Add an explicit `enabled` boolean (or `RETIRED` status transition requiring the same two approvals) on `platform` rules so a platform can be removed from compiled snapshots with two approvals without deleting history. |

---

### (4) Verdict

**DO NOT MERGE** (resolve P0 findings D-01 and D-02, and P1 findings D-03, D-04, and D-05 before merge).

---

### (5) Verbatim Instructions Received

1. User request:
```text
/plan REVIEW: second independent review of pull request 16 (AGENTS.md section 9, security-sensitive: policy registry,
approvals, RBAC, snapshot signing), branch `feature/mvp2-control-ui`
LENS: whether the registry and its approvals, the signed snapshot feed and the masked UI hold against AGENTS.md sections
4 and 6, docs/architecture/POLICY_SNAPSHOT_CONTRACT.md, ADR-008, ADR-009 and ADR-010.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway: a Spring Boot control
plane with a React admin UI that manages the policy the data plane enforces; a public repository). You start from a fresh
context. Read AGENTS.md and ONLY the files listed below, with the Read tool, inside this repository. Do not edit, run
shell, or widen the review. Your job: find any way one person, a single role, a replayed request or a direct database
write can activate, weaken or roll back a policy without two distinct approvals; any way a fail-closed class can be
relaxed or excepted; any way the snapshot feed can serve unsigned, mis-signed, non-monotonic or non-contract bytes, leak
the signing key, or let the data plane expire (re-issue); any RBAC gap (a viewer or replay_viewer reaching a write, a raw
value or an unmasked identity); any XSS or injection through rule fields, platform rows or the language catalogues; and
any audit-ledger gap. Return exactly: (1) a CONSENT table (area, verdict), (2) a DISSENT table (finding id, file and line
or symbol, what is wrong, severity P0/P1/P2, the concrete correction), (3) QUESTIONS FOR THE PRODUCT OWNER (question, your
recommendation), (4) a one-line verdict MERGE / MERGE WITH CORRECTIONS / DO NOT MERGE, then (5) list every instruction you
received, verbatim. Be concrete and short. Never quote or invent an address, host name, account, serial or secret; the
repository holds none and neither should your output. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 6, 9)
- docs/architecture/POLICY_SNAPSHOT_CONTRACT.md
- docs/adr/ADR-010-fail-open-and-fail-closed.md
- java/persistence/src/main/resources/db/migration/V2__policy_registry.sql
- every file under java/persistence/src/main/java/ that names "policy" or "Policy"
- every file under java/control/src/main/java/io/rwsafe/control/policy/
- java/control/src/main/java/io/rwsafe/control/ security, role and web configuration files
- policy/registry-seed.yaml
- frontend/src/pages/PoliciesPage.tsx, frontend/src/pages/PlatformsPage.tsx, frontend/src/i18n/ (the loader, not the catalogues in full)
- every test under java/control/src/test/java/ and java/persistence/src/test/java/ that names "Policy", "Snapshot" or "Registry"
```

2. Workspace rule (`AGENTS.md`):
   - Full text of `AGENTS.md` (lines 1–187 of `AGENTS.md` in the repository root, loaded as `<RULE[.../AGENTS.md]>`).

3. Slash-command metadata (`/plan`):
   - Standard Antigravity `/plan` mode metadata (`<PLAN>...</PLAN>`).
