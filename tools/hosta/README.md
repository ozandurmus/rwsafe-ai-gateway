# tools/hosta: read-only HOST-A inspection

HOST-A is shared with neXus and is inspected, never changed, from this repository (kickoff brief section 4 "Access").
Every script here follows brief section 4A: the host is read from `~/.config/nexus/hosta` and never printed; every output
byte passes through `mask.sh` (addresses, e-mails) and the remote-side node-name mask before an agent reads it; only
shapes and counts cross the boundary.

| Script | Who runs it | What it does |
|---|---|---|
| `mask.sh` | everything | The identifier mask. |
| `inventory_readonly.sh <out>` | the agent | Non-root inventory through `ssh ... bash -s < remote_inventory.sh`: capacity, ports, services, workloads, resource sums, ingress, TLS shape, quotas, storage, kubelet config and stats, registry catalogue. |
| `remote_inventory.sh` | (payload) | The commands that run on the host. `kubectl get`/`--raw`, `ss`, `df`, `lsblk`, `sysctl`, `/proc`. No `exec`, no `logs`, no SQL, no write. |
| `po_sudo_readonly.sh <out>` | the Product Owner, in a terminal | Root-only listings (nft ruleset, sshd effective config, k3s config, secrets-encryption status, root-owned disk usage, all listening processes). `sudo -v` prompts once; the agent never holds sudo (PO rule 2026-10-30). |

Outputs are written outside the repository (the agent's scratchpad). A masked inventory is summarised into
`docs/operations/PORTS_AND_RESOURCES.md` and `docs/operations/CAPACITY_AND_SLO_MODEL.md`; the raw masked file is not committed.
