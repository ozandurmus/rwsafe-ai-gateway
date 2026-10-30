# Hardening exceptions for PO approval

**Status:** DRAFT for PO decision. Each exception: what, why, source, destination, duration, and what happens without
it. Where no exception is needed, the row says so. Based on the 2026-10-30 inventory and the neXus hardening record
(`HOST_A_HARDENING_DRAFT.md`, H1–H4, M1–M4); the root-only pass (nftables ruleset shape, sshd settings) was read on 2026-10-30 and
its findings are folded in below.

| ID | Exception | Reason | Source | Destination | Duration | If refused |
|---|---|---|---|---|---|---|
| H-1 | Inbound TCP **1344** (ICAP) and **11344** (Secure ICAP) on the node's host firewall | ProxySG must reach rwsafe's ICAP Service (ServiceLB on the node address) | **only the ProxySG appliances' addresses** (the proxy team supplies them; they live in the uncommitted `rwsafe-estate` ConfigMap and in the nftables set, never in the repository) | HOST-A node address | permanent while the product is in service; reviewed yearly | no inline inspection: the product cannot do jobs 1–3 |
| H-2 | Pilot only: plain ICAP on 1344 without TLS | Secure ICAP needs the ProxySG client certificate and SGOS support (UNVERIFIED for the installed version); the pilot may start plain while the certificates are issued | ProxySG addresses | node 1344 | **pilot period, maximum 60 days**, then 1344 closed and 11344 only | pilot delayed until mTLS is in place |
| H-3 | Inbound UDP **1161** (SNMP agent), or a host firewall redirect 161→1161 | the corporate NMS polls rwsafe health by SNMP (brief 5F) | the NMS addresses | node | permanent | SNMP polling unavailable; health is still exposed over HTTPS and syslog |
| H-4 | Outbound TCP **6514** (syslog over TLS) or UDP/TCP 514 from rwsafe pods to the SIEM | SIEM export (brief 5B, 10.4) | rwsafe worker pods | the SIEM collector | permanent | no SIEM export; the audit stays local |
| H-5 | Outbound TCP 389/636 (LDAP/LDAPS) from the control plane to the directory | LDAP/AD login and group-to-role binding | rwsafe control pod | the directory servers (through the same path neXus already uses) | permanent | local break-glass accounts only |
| H-6 | Outbound HTTPS from the **gateway** pods to the AI platforms' API endpoints **through the corporate proxy** | the LLM API gateway forwards governed requests upstream | rwsafe gateway pods | the corporate proxy (which applies its own egress policy) | permanent | no LLM API gateway (job 4) |
| H-7 | Outbound SMTP 25/587 from the worker to the corporate relay | notifications (brief 5F) | rwsafe worker pod | the relay | permanent | no mail notifications |
| H-8 | Inbound HTTPS 443 for the new host names | already open for everyone (neXus hardening H2 opens 80/443 to everyone) | any | node 443 | — | **no new exception needed**: host-based routing reuses the open port |
| H-9 | Pilot only, chained forward proxy TCP **3128** from ProxySG | only if phase 0 shows ProxySG cannot hand WebSocket traffic to ICAP (ADR-004/005) | ProxySG addresses | node 3128 | decided after phase 0 | WebSocket traffic stays log-only or agent-covered |
| H-10 | Agent channel | the off-net agent reports to `agent.<corp-domain>` over 443 with mTLS | the Internet via the corporate reverse proxy | node 443 | decided with ADR-006 | **no new port**; a reverse-proxy publication is a corporate network change, not a HOST-A exception |

## Observations that are not rwsafe exceptions (reported to the PO)

- TCP **25** listens on all interfaces on HOST-A (an MTA); the host firewall drops it from outside today
  (confirmed from the ruleset). rwsafe does not need it inbound; the PO may want it bound to loopback.
- neXus's limits over-commit the node (`CAPACITY_AND_SLO_MODEL.md` §1); not an exception, a neXus observation.
- The in-cluster registry has hundreds of stale tags (`SHIP_PIPELINE_PLAN.md` §4).
- No ResourceQuota or PodDisruptionBudget exists for neXus; rwsafe's own objects do not change that.

## Kubernetes-level hardening rwsafe brings for itself (no exception needed)

PSA `restricted` on all three rwsafe namespaces; default-deny NetworkPolicy; no hostPath; no hostPort in pod specs
(ServiceLB holds the node port); `automountServiceAccountToken: false`; read-only root filesystems; all capabilities
dropped including `NET_RAW`; Secrets encrypted at rest (k3s setting already on, verified); image signature and
provenance verification at deploy; heap dumps disabled (`-XX:-HeapDumpOnOutOfMemoryError`) and JFR recordings off in
production (PRIV-10).

## What the root-only pass showed (2026-10-30, shapes only)

- nftables table `inet nexus_host`: input policy **drop**; loopback, established, CNI/flannel interfaces and the pod/service
  ranges accepted; ICMP accepted; **22 only from the `ssh_allowed` set (2 blocks) and the `sftp_push_allowed` set (5
  entries)**; **80 and 443 accepted from anywhere**; everything else dropped with rate-limited logging; prerouting drops
  new connections to the NodePort range on the outside interface. The kube/CNI nat tables are managed by k3s and carry
  the hostPort DNAT for 80/443. So: the ICAP ports and SNMP are closed today and need exactly the rows H-1 (and H-3, H-9
  if chosen); nothing else changes.
- sshd (effective, global): port 22 on all addresses, `PermitRootLogin no`, pubkey yes, password **no**, keyboard-interactive
  **no**, X11/TCP/agent forwarding **no**, `MaxAuthTries 3`, idle timeout 300 s × 2, banner, `AllowUsers` with 3 entries
  (per-user `Match` blocks are not shown by the global view). No rwsafe exception is needed on sshd.
- k3s: `secrets-encryption: true` (status: enabled, AES-CBC key active, re-encryption finished), `protect-kernel-defaults:
  true`; the k3s service environment carries the corporate proxy variables (values withheld); the registry mirror is
  configured in `registries.yaml` by endpoint. rwsafe pods therefore get proxy settings only when their manifests set
  them explicitly (the gateway does, the ICAP engine does not).
- Disk (root-only): containerd 72 GiB, neXus platform backups 78 GiB, security reports 0.3 GiB, logs 1.1 GiB; PVC
  directories were not enumerable through the glob and are inferred from the kubelet summary (the artefact store
  dominates). The 75 % watermark is already crossed.
- Host sockets by process: sshd 22, the MTA on 25 (all interfaces, dropped by the firewall from outside), k3s API 6443,
  kubelet 10250, k3s internals on loopback, resolver, chrony, flannel 8472/udp. Nothing on 1344, 11344, 3128, 161, 514.

## The proposed firewall addition (a neXus-owned file, delivered by a neXus PR)

In `deploy/hosta/nexus-host-firewall.nft` (template; real addresses only in `/etc/nexus/firewall.nft` on the host):

```
    set icap_clients {
        type ipv4_addr
        flags interval
        # ProxySG appliances that send ICAP to rwsafe (HARDENING_EXCEPTIONS H-1); filled only on the host.
        elements = { @PROXYSG_BLOCK@ }
    }
    set nms_pollers {
        type ipv4_addr
        flags interval
        elements = { @NMS_BLOCK@ }
    }
    ...
        tcp dport { 1344, 11344 } ip saddr @icap_clients accept
        udp dport 1161 ip saddr @nms_pollers accept        # only if H-3 is approved
```

Applied with the same 5-minute automatic-rollback discipline the neXus hardening record used.
