@AGENTS.md

Claude-specific delta only; `roles/ENGINEER.md` carries the reading order.

- Chat with the Product Owner in Turkish; every repository artifact in English (`AGENTS.md` section 3).
- Model tiers for this tool: `docs/reference/MODEL_TIER_MAP.md`.
- HOST-A: read-only, masked, no `sudo` (`AGENTS.md` section 8). Inventory through `tools/hosta/inventory_readonly.sh`;
  root-only listings through `tools/hosta/po_sudo_readonly.sh` run by the PO in a terminal.
- External reviews only through `tools/review/consult_*.py` (`AGENTS.md` section 11); never a simulated persona.
- Argon development lanes only through `tools/review/argon_task.py` in a `~/Codo/rwsafe-*` worktree.
- Never read `kickoff/` raw traffic or prompt samples if any are ever added; sanitize first (`AGENTS.md` section 4.1).
