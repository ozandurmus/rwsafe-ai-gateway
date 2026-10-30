# Roles

`AGENTS.md` is the authority; a role file is only that role's cold start: reading order, what it may decide, stop
conditions. State your role in your first message.

| Role | File | Holds |
|---|---|---|
| Product Owner assistant / orchestrator | `PO.md` | scopes work, dispatches, reviews, merges, operates the live environment within the limits in the file |
| Product architect (design phase) | `ARCHITECT.md` | designs; writes ADRs, contracts and decision-record drafts; never product code in this phase |
| Engineer | `ENGINEER.md` | implements against a FROZEN contract or ACCEPTED ADR on a `feature/*` lane |
| Orchestrated worker | `WORKER.md` | template rendered into `.rwsafe/WORKER.md` for one bounded movement |
| Reviewer / council seat | `REVIEWER.md` | fresh-context, read-only, one concern, masked evidence only |
