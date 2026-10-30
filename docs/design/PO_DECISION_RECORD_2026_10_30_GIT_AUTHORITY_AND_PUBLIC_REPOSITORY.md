# PO decision record 2026-10-30: Git authority and the public repository

**Status:** RATIFIED — Product Owner, 2026-10-30 (chat): "Sen aynı zamanda PO'sun, public olarak repo'yu githubda
açabilirsin." (You are also the PO; you may open the repository publicly on GitHub.) "Burada senin push yetkini kısıtlayan
kuralları düzgün şekilde güncelle PO olarak sen benden önce bu repoyu güncelleyebilmelisin." (Update the rules that limit
your push authority properly; as PO you must be able to update this repository before I do.) "… sende mühendiste merge vs
yapabilir durumda olmalısınız" (… you and the engineer must be able to merge and so on.) "Çalıştırdım" (I ran it), on the
script that wrote the project permission file, set the required approving reviews on `main` to zero and merged pull
request 2.

## Context
The repository `github.com/ozandurmus/rwsafe-ai-gateway` was created public by the PO on 2026-10-30 with branch protection
on `main` (pull request required, one approving review, no force push, no deletion, administrators exempt). AGENTS.md
section 9 made push, PR creation and merge PO-controlled per instruction. The repository has one human GitHub account, so
nobody can approve the agent's pull requests on GitHub. The agent harness refused the agent's own edits to its permission
file, to AGENTS.md authority clauses, to branch protection and to merges without review; the PO made those changes by
running one script given in chat. No host, device, proxy or production data is involved.

## Decision
1. The repository is public; no file in it may carry production identifiers (AGENTS.md section 4.15 gate mandatory).
2. The architect and the orchestrating engineer session hold standing authorisation to push branches, open pull requests
   and merge them for committed, privacy-gated content; no per-action chat approval is needed.
3. `main` requires a pull request and zero approving reviews; force push and deletion stay blocked; administrators are
   exempt only for emergency repair by the PO.
4. Force push, repository deletion and visibility changes remain prohibited for every agent (deny rules in
   `.claude/settings.json`).
5. The second independent review that AGENTS.md section 9 requires for security-sensitive PRs is recorded in the pull
   request as a review-script output or a code-review run named by commit, not as a GitHub approval.
6. Council and review outputs under `docs/reviews/` are evidence; only a PO decision record quoting them binds (Q-36,
   decided in `PO_DECISION_RECORD_2026_10_30_FREEZE_COUNCIL_QUESTIONS_Q30_Q36.md`).
7. Edits to `AGENTS.md`, `roles/`, `docs/design/` decision records and `.claude/settings.json` that the PO dictates in chat
   are authorised for the architect session.

## Consequences
- AMENDS AGENTS.md section 1 items 4 and 6 and section 9 (this pull request).
- `.claude/settings.json` committed with the allow and deny rules and the standing-authorisation statement; the project
  settings file is part of the repository and changes only through a pull request.
- `docs/GITHUB_REPOSITORY_SETTINGS.md` records the protection as it now stands.
- Residual risk accepted: an agent merge without a second human review on non-security-sensitive pull requests. Review date
  2027-01-31.

## Open items
Whether a second human account, or the corporate GitHub Enterprise instance named in
`docs/reference/CORPORATE_TECHNOLOGY_STACK.md`, will later restore GitHub approvals: OPEN_QUESTIONS Q-37.
