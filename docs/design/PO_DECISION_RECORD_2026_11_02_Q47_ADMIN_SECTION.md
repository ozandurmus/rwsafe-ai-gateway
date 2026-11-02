# PO decision record 2026-11-02: an Administration section like the other product's, pilot single approval, layout

**Status:** RATIFIED — Product Owner, 2026-11-02 (chat): "Sırasıyla yap hepsini. ama ilerlememizi etkilemesin." (Do
all of them, in order; but it must not affect our progress.) Before it, signed in to the pilot admin UI, the PO wrote:
"hani arayüz nexus ile benzerdi, ? Admin ekranı ldap ekranı hiçbirşey yok tanım yapabileceğim oluşturabileceğim" (wasn't
the interface similar to neXus? There is no admin screen, no LDAP screen, nothing where I can define or create) and
shared the other product's Administration menu (groups Registry, Access, Platform, Records). Three questions were then
asked with a recommended option each (the admin sections, the pilot approval rule, the layout); the PO answered with the
sentence above instead of picking options. The orchestrator reads "hepsini" as every section of the first question and
the recommended option of the other two, and said so in chat; the PO may change either reading.

## Context
The admin UI (PR 39, live on HOST-A since PR 43) has Overview, Traffic, Policies, Platforms, Notice and Health. There is
no screen for local users, roles, sessions, directory (LDAP) settings, the audit ledger or system settings; the
directory connection comes only from deploy configuration (`RWSAFE_LDAP_*`), and group-to-role binding from the
directory's group names. Activation of a policy version needs two approvals by two different people, a
`security_admin` and a `privacy_officer` (PO decision Q-39/Q-40, decision 3); the pilot has one person (the break-glass
`security_admin`), so no change can be activated there.

## Decision
1. An **Administration** section is built, in this order, each slice merged and applied to the pilot only when its
   tests pass, without stopping the running pilot (one control-plane restart per slice, announced):
   1. **Access, part 1**: local users (create, disable, reset password, assign roles), roles and what each may do, open
      sessions (list, end one).
   2. **Access, part 2**: directory (LDAP) settings entered and tested on the screen, and the binding of directory groups
      to roles chosen on the screen. The bind password is stored encrypted under a key Secret of the product's own and
      is never shown again after saving.
   3. **Records**: the audit ledger (who changed what, when, with which reason) and the scheduled-job log.
   4. **Platform**: notifications, system logs (classes and counts, never request bodies), version and build facts.
2. **Pilot approval:** a pilot-only switch lets one `security_admin` activate a policy version alone, with a reason,
   ledgered as a single-approval activation. It is off by default and in every overlay but the pilot's; go-live turns it
   off and the two-person rule applies again. Not chosen: keeping two approvals and opening a second account first.
3. **Layout:** the admin UI takes the other product's arrangement: a sectioned left menu and an Administration page with
   a grouped sub-menu. Nothing is copied from the other product's code; the arrangement is reproduced in this product's
   own components. Not chosen: new screens in the current arrangement first.

## Consequences
- AMENDS `PO_DECISION_RECORD_2026_10_30_POLICY_SCOPE_AND_PLATFORM_RETIREMENT.md` decision 3 for the pilot only, while
  the switch is on.
- Directory settings from the screen live in the product's database, not in deploy configuration; AGENTS.md section 8
  still governs deploy configuration (no `kubectl set env`), and the deploy-time `RWSAFE_LDAP_*` values, when present,
  seed the stored settings once. Every settings change is ledgered with actor and reason.
- Local users and roles are RBAC and identity work: each slice is security-sensitive (AGENTS.md section 9) and gets a
  second independent review before merge. The masked role (`replay_viewer`) sees none of these screens' real values.
- Residual risk while the pilot switch is on: one person can change what is enforced; every change carries a reason and
  a ledger entry. Review: at go-live.

## Open items
Whether local users stay after go-live (directory only, or both) is decided at go-live.
