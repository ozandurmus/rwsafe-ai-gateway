# security/

- `baseline.yaml`: accepted scanner findings with reason, owner and review date (AGENTS.md section 10). Empty at design
  freeze; the first ship creates the baseline from that day's findings, each triaged.
- The vulnerability SLA, root-cause log and base-image cadence are in `docs/design/SECURE_SDLC_SSDF_MAPPING.md`.
