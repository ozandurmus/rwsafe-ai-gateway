# tools/review: authorised external reviews and Argon development lanes

AGENTS.md section 11: an external review is never simulated by an internal persona; it runs through these scripts, which
invoke the installed external CLIs, and its full unaltered output is written under `docs/reviews/`. AGENTS.md 4.6 and 4.7:
reviewers receive masked material only and never a prompt body. The scripts are the neXus `scripts/consult_argon.py`,
`consult_fable_*.py` and `argon_task.py` patterns with the output root, the worktree prefix and the standing rules taken
from `.rwsafe-delivery.json`, plus a content guard.

| Script | Purpose |
|---|---|
| `review_guard.py` | refuses a brief that contains a prompt-body field, a privacy-gate finding, or a canary digest; used by every script below |
| `consult_argon.py --brief FILE --output docs/reviews/NAME.md [--model ... --effort ...]` | Argon (Google Antigravity CLI `agy`, read-only `--mode plan`) |
| `consult_fable.py --brief FILE --output docs/reviews/NAME.md [--model claude-fable-5-1] [--add-dir DIR]` | Fable/Claude through `claude -p` with the Read tool only, limited to the repository and the named directories |
| `argon_task.py --worktree ~/Codo/rwsafe-<lane> --brief FILE` | one development task on Argon inside a `~/Codo/rwsafe-*` worktree on a feature branch; commits only, never pushes |
| `council_seats/*.md` | the seat briefs for the design-freeze council (one per lens), each listing the documents the seat reads |

Running a review is a PO-authorised action in this phase: the architect prepares the brief and asks before invoking.
