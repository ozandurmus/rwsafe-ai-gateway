# PO decision record 2026-11-03: the ICAP pods admit the proxy addresses themselves

**Status:** RATIFIED — Product Owner, 2026-11-03 (chat, question tool): "Proxy adresleriyle (Önerilen)" (with the proxy
addresses, recommended).

## Context
After the host firewall table `inet rwsafe_pilot` was applied (PILOT_RUNBOOK step 11; 3 addresses, 2 rules), the
ProxySG's ICAP health check timed out. Measured on HOST-A (masked, counts only): the proxy's SYN reaches the node and
passes the host table (its source is in the set); kube-proxy's LoadBalancer rule for the node address DNATs it straight
to an ICAP pod (its counter rose), bypassing the ServiceLB pod, so the source is still the proxy's own when k3s's
network-policy controller evaluates the ICAP pods' ingress; the pilot's policies admit 1344 only from in-cluster pods
and from the ServiceLB pods (the PLAT-F2 assumption that ServiceLB masquerades the source, not true on this host), so the
SYN is dropped. The other product's table drops nothing here (0 log lines for 1344).

## Decision
1. The ICAP pods' NetworkPolicy admits TCP 1344 from the ProxySG addresses themselves (ipBlock /32 each), typed by the PO
   on the host into an uncommitted 0600 file and filled at render time; never committed, printed or passed as an argument.
2. The host firewall table stays as well: two independent allowlists; after a host reboot (the table is not persistent)
   the NetworkPolicy still admits only the proxies.
   Not chosen: admitting every external source in the NetworkPolicy and relying on the host table alone (faster, but
   open to the whole network after a reboot until the table is re-applied).

## Consequences
- AMENDS the k3s overlay's PLAT-F2 note: on HOST-A the client address reaches the ICAP pods; the production design's
  ICAP ingress must be revisited before go-live (CURRENT_STATE Open).
- New pilot host file and helper (`icap-clients.env`, `tools/pilot/icap_clients.sh`), a runbook step, manifest-check
  bounds; security-sensitive, second review before merge.

## Open items
The production (k3s overlay) ICAP ingress design, at go-live.
