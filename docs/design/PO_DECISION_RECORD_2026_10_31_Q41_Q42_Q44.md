# PO decision record 2026-10-31: single-administrator scope withdrawal (Q-41), runbook section 7 (Q-42), pseudonym registry (Q-44)

**Status:** RATIFIED — Product Owner, 2026-10-31 (chat, three questions asked one at a time with the options, relayed by
the orchestrating session). The PO's answers, verbatim, with an English gloss:

| Id | PO answer (verbatim) | English gloss |
|---|---|---|
| Q-41 | "Tek yönetici, gerekçeyle" | "One administrator, with a reason" |
| Q-42 | "Bu bölümü onaylıyorum (Önerilen)" | "I ratify this section (recommended)" |
| Q-44 | "Takma ad kaydını kur (Önerilen)" | "Build the pseudonym registry (recommended)" |

## Context
- **Q-41.** Pull request 21 (scoped policy control) let an active group-scoped DLP class version be withdrawn, so that
  its groups fall back to the `ANY` version. The second review left the approval model open; the orchestrator decided an
  interim model and recorded it in `docs/reviews/PR21_2026_10_30_RESPONSE.md` (row Q-41) and `CURRENT_STATE.md`: a
  withdrawal request (a pending version of the same rule, mode and scope naming the target) that takes the same two
  approvals as an activation. The open question (`docs/product/OPEN_QUESTIONS.md`) offered (a) two approvals by two
  people, as implemented, or (b) one `security_admin` with a reason. The recommendation was (a), because removing a
  stricter group rule loosens policy for that group. Platform retirement (Q-40,
  `PO_DECISION_RECORD_2026_10_30_POLICY_SCOPE_AND_PLATFORM_RETIREMENT.md`) is already one administrator's action with a
  reason.
- **Q-42.** `docs/operations/DEPLOY_AND_SHARED_HOST_RUNBOOK.md` is FROZEN by
  `PO_DECISION_RECORD_2026_10_30_DESIGN_FREEZE.md` and may be amended only through a PO decision record. Pull requests
  18 and 27 added its section 7 (build and apply commands: what is committed, local checks, image build, the PO's apply
  steps) without one. The options were (a) ratify section 7 as written or (b) move it to a separate operations guide.
- **Q-44.** The masked class tokens (`TCKN-`, `TEL-`, `NUM-`, `HST-` and the others) carry 4 hex characters, as the
  FROZEN `docs/security/MASKING_AND_PRIVACY.md` says. Without the pseudonym registry its section B3 names, two values of
  one class can share a token (about even odds at 300 values per class). A shared token confuses an auditor; it leaks
  nothing. The options were (a) build the B3 registry next or (b) amend the design to 8-hex tokens now.

## Decision
1. **Q-41.** One `security_admin` withdraws an active group-scoped class version, with a required reason; no second
   approval. Not chosen: two approvals by two people (what pull request 21 implemented).
2. The reason passes the same checks as a platform retirement reason: 1 to 500 characters on one line, no identifier
   (the shared `IdentifierCheck` and the free-text masking layers), no estate-dictionary term; the masked role reads it
   withheld.
3. The withdrawal takes effect at once: the version becomes `withdrawn`, leaves the active set and the next snapshot,
   and its groups fall back to the `ANY` version.
4. The withdrawn version is never deleted and never becomes active again; its row keeps the time, the administrator's
   pseudonym and the reason. The group rule comes back only as a new version under the two approvals.
5. The withdrawal is ledgered (`audit_event`, action `policy.scope_withdraw`, the administrator as actor, the reason as
   the ledger reason) and so reaches the SIEM with the other ledger rows; the database refuses a withdrawal whose ledger
   row does not name the same administrator and reason.
6. The viewer, the privacy officer alone and the masked role are refused (HTTP 403).
7. **Q-42.** Section 7 of `docs/operations/DEPLOY_AND_SHARED_HOST_RUNBOOK.md`, as it stands on `main` on 2026-10-31, is
   ratified as part of the frozen runbook. Not chosen: moving it to a separate operations guide.
8. **Q-44.** The B3 pseudonym registry of `docs/security/MASKING_AND_PRIVACY.md` is built next, so a masked token is
   claimed once per value and kind; the token formats stay as the design says (4 hex). Not chosen: amending the design to
   8-hex tokens.

## Consequences
- `SUPERSEDES` the orchestrator's interim Q-41 decision in `docs/reviews/PR21_2026_10_30_RESPONSE.md` (row Q-41: the
  withdrawal request with two approvals) and its description in `CURRENT_STATE.md`. The rest of that response (one
  pending draft per rule, mode and scope; group-name normal form; reasons without identifiers) is unchanged.
- **Residual risk the PO accepted (Q-41):** one person can loosen policy for a group (its stricter group rule stops
  applying; the `ANY` rule, never ALLOW or WARN for a fail-closed class, applies instead). The control is the reason
  check, the ledger and the SIEM copy. As with Q-40, this single administrator's audited action is read as the "audited
  approval" of AGENTS.md section 6; activation of any version still takes two approvals. Review date: with the first
  policy-change report to the PO after go-live.
- Implementation (Q-41): Flyway `V9__single_admin_withdrawal.sql` (column `withdrawn_by`, the guard: one administrator's
  withdrawal with the ledger check, no new withdrawal request, a pending V3 request superseded and never activated);
  `PolicyRegistryStore.withdrawScope`, `PolicyRegistryService.withdrawScope`, `POST
  /api/v1/policy/rules/{ruleId}/versions/{version}/withdrawal` (now returns the withdrawn version, HTTP 200); the
  Policies screen ("Geri çek": reason, in-page confirmation, result; no approval steps for a withdrawal). Tests:
  `PolicyRegistryStoreTest`, `SingleAdminWithdrawalMigrationTest`, `SnapshotCompilerTest`,
  `PolicyRegistryIntegrationTest`, `MaskedRoleLeakProbeTest`, `frontend/src/test/policies.test.tsx`.
- `AMENDS` (Q-42) `docs/operations/DEPLOY_AND_SHARED_HOST_RUNBOOK.md`: section 7 carries a ratification line naming this
  record; later changes to section 7 need a PO decision record like the rest of the runbook.
- Q-44 is implemented by a separate lane (migration V10, the B3 `pseudonym_registry`); this record only decides it.
- `docs/product/OPEN_QUESTIONS.md`: Q-41, Q-42 and Q-44 move to the Decided table.

## Open items
None. The wording of AGENTS.md section 6, if the PO wants it to name single-administrator retirement and withdrawal
explicitly, stays a PO edit of AGENTS.md (as noted in the Q-39/Q-40 record).
