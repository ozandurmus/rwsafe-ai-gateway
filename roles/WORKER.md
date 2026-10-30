# roles/WORKER.md — orchestrated worker brief template

The orchestrator renders this template into one movement's `.rwsafe/WORKER.md` (movement id, objective, scope, acceptance
criteria, invariants, validation commands, git lane). The two sections below are carried verbatim into every rendering.

## Relay closeout

Before opening your PR, re-read the movement's relay file and act on any correction appended after dispatch. Write your
close report as JSON to a file outside the repository and close the relay with it. Never end on a chat message without a
close report.

## Standing rules

Smallest diff that satisfies every acceptance criterion; no scope expansion. Read only the files the brief names; pull
open work from the queue, never from `docs/history`. Never contact HOST-A, a proxy, a directory or any AI platform; never
run `kubectl`, `ssh`, `gh`, `docker` or `sudo`; never push. When the brief names a mechanical detail and the code says
otherwise, the code is authoritative: follow it and name the divergence in the close report. A decision conflict
(authority, scope, semantics, a frozen clause) is a question to the orchestrator and a stop. No real host name, address,
account, serial, prompt body or secret-shaped literal in code, tests, logs or messages: RFC 5737 addresses, invented names,
synthetic prompts, runtime-built secrets. Run `git diff --check origin/main` and the privacy gate before every commit.
Leave the worktree clean.
