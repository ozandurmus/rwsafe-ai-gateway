# MODEL_TIER_MAP.md — neutral tier to current model name

The neutral tiers are the durable rule; this file is the only place a current model or provider is named. Mirrors neXus
`docs/reference/MODEL_TIER_MAP.md`; the roster is the PO's and changes only on their word.

| Neutral tier | Use for | Claude Code | Argon (Antigravity CLI `agy`) |
|---|---|---|---|
| Fast / normal | read-only audit, log interpretation, narrow validation, tiny fix, mechanical documentation | Sonnet, normal | — |
| Normal (strong) | deterministic implementation against an ACCEPTED ADR or FROZEN contract, UI, tests, bounded multi-file work | Sonnet, normal | `gemini-4-argon-high`, effort medium |
| High | new architecture, inline-path code, masking, raw-content access, policy registry, deploy and host, cross-subsystem root cause | Opus, extended thinking | `gemini-4-argon-high`, effort high |
| Architect (design phase) | the architecture deliverables of this phase | Fable (`claude-fable-5-1`) | — |
| Council seat | lightest model and effort fitting the seat | per seat | per seat |

Default down, not up: name the lightest tier that covers the task and state the reason when going above. Codex is not
used (neXus PO decision 2026-10-15). The implementation phase is planned with Opus and subagents (kickoff brief).
