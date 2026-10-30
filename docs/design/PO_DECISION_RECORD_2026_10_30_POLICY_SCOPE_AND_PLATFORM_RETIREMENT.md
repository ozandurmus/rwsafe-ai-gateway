# PO decision record 2026-10-30: policy scope by source, and platform retirement

**Status:** RATIFIED — Product Owner, 2026-10-30 (chat, two questions raised by the second review of pull request 16,
asked with the recommendation first). The PO's words:

- Q-39: "Kural tanımı konusu dinamik olmalı. Ben kime hangi politikanın uygulanacağını secebilmeliyim . Yayılım konusu
  bana kalmış. Kaynakta any ise tüm herkes grup ise sadece o grup." (Rule definition must be dynamic. I must be able to
  choose which policy applies to whom. Rollout is up to me. If the source is any, everyone; if it is a group, only that
  group.)
- Q-40: "Sadece yönetici kaldırabilsin" (Only an administrator may remove it.)

## Context
Pull request 16 shipped the policy registry with a mode (monitor, enforce) and a percentage rollout stage (pilot, 25 %,
50 %, all) on every rule version, but snapshot format 1 carries no targeting, so only enforce versions at stage all reach
the data plane. The second review (`docs/reviews/PR16_2026_10_30_ARGON_CONTROL_UI_SLICE2.md`) asked two questions: must a
version pass through monitor mode and the stages before enforce for everyone (Q-39), and how is a platform row retired
(Q-40). The recommendations were "direct with two approvals now, mandatory staging later" and "a two-approval retired
state". The PO chose differently on both.

## Decision
1. **Every rule version has a source scope**: `ANY` (every user) or one or more directory groups. A version with scope
   `ANY` applies to everyone; a version with a group scope applies only to members of those groups. The operator chooses
   the scope when drafting the version; there is no mandatory sequence of monitor mode or stages. Monitor mode stays
   available as a choice per version.
2. The percentage rollout stages (pilot, 25 %, 50 %, all) are retired for new versions; the group scope replaces them as
   the way to roll a policy out step by step. Existing rows keep their stage as history.
3. Activation is unchanged: two approvals by two different people (a `security_admin` and a `privacy_officer`).
4. The fail-closed law is unchanged and applies inside every scope: no scope may set a fail-closed class to ALLOW or WARN,
   and no group scope takes an exception for one.
5. **Platform retirement**: a `security_admin` alone may retire a platform row, with a reason; no second approval. The
   row is never deleted: it becomes `retired`, its history stays, and the action is ledgered. A retired platform leaves
   the next snapshot. Bringing a platform back is a new version under the normal two approvals.

Not chosen: mandatory monitor and staged progression (Q-39); a two-approval retired state (Q-40).

## How a scope is applied on the data plane
- Group membership is the proxy's claim in `X-Authenticated-Groups` (ICAP spec, identity row; whether the estate's proxy
  sends it, and in which format, is **UNVERIFIED** 2026-10-30 and is verified with the PO in the proxy guide).
- The frozen ICAP spec (identity row, OFF2-12) binds: a group claim selects a scoped policy **only on a mutually
  authenticated (Secure ICAP) connection**. On a plain ICAP connection, and when the claim is missing or unreadable, the
  **strictest** action across the `ANY` version and every active group-scoped version applies, class by class.
- When several group scopes match one user, the strictest action per class wins (BLOCK, then REDACT, then WARN, then
  ALLOW).

## Consequences
- **Plain ICAP period**: while the appliances talk plain ICAP (PO decision Q-28), a stricter group rule applies to
  everyone and a looser group rule has no effect. Group targeting takes full effect only after Secure ICAP works. The PO
  was told this in chat.
- Snapshot format 2 (`docs/architecture/POLICY_SNAPSHOT_CONTRACT.md`) carries scoped rules; the data plane accepts
  formats 1 and 2.
- Registry migration V3: scope columns on rule versions, `retired` status for platform rows, one active version per rule,
  mode and scope.
- Admin UI: a scope picker (Everyone / Groups) replaces the rollout bar; the platform screen gets a retire action for
  `security_admin` with a reason field.
- AGENTS.md section 6 is read as requiring that monitor mode and rollout by directory group **exist**, not that every
  change must pass through them; this record is that reading. Retiring a platform with one administrator's audited
  action is read as the "audited approval" of section 6. If the PO wants the wording of section 6 changed to match, that
  is a PO edit of AGENTS.md.
- Retiring a platform weakens coverage: its traffic is no longer recognised as an AI platform and falls under the
  uncategorised handling (Q-30). The ledger entry names the actor and the reason.

## Supersedes
The rollout-stage part of the pull request 16 registry design (stage percentages); answers PR 16 review questions 1 and 2.

## Open items
- Verify `X-Authenticated-Groups` on the estate's proxy (PO, with the proxy guide).
