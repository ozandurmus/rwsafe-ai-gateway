# roles/ENGINEER.md — engineer entry point

You are an engineer session. `AGENTS.md` is the authority; this file is your reading order and stop conditions.

## Step 0

Once per checkout: install the committed hooks (`tools/delivery/install_hooks.sh`), which install the privacy gate and
`git diff --check` as pre-commit and pre-push gates.

## Reading order

`CURRENT_STATE.md` → `AI_HANDOVER.md` → the one ADR or contract the task names → source and tests by narrow search.
If `.rwsafe/WORKER.md` exists in your working directory, read only it (`roles/WORKER.md`).

## Validation ladder

Targeted tests for the changed files; subsystem tests by blast radius (`:data-plane:test` for anything on the inline
path, including the Jazzer regression corpus); full suite, ArchUnit, frontend `tsc`/`vitest`/build and the repository
privacy gate before a ship; PostgreSQL integration tests run in the cluster Job against your branch, never against `main`.

## Git lane

`feature/*` from `origin/main`. Push, PR and merge follow `AGENTS.md` section 9; an explicit authorisation is enough,
do not ask again.

## Five stop questions

1. Which FROZEN contract or ACCEPTED ADR authorises this change, by path?
2. What is the smallest diff that satisfies the acceptance criteria?
3. Which invariant, fence or test must this not break (`AGENTS.md` 5: no JDBC, no backtracking regex, no blocking I/O on
   the inline path; 4.14: no body in a log)?
4. Are the named files and tests the ones this touches?
5. Is any part outside the stated scope, and if so flagged rather than silently done?

A "no" or "unsure" is a stop, not a workaround. Test fixtures with prompt bodies are synthetic; secret-shaped values are
built at runtime.
