# HOST-A measurement, 2026-10-31

**Status:** LIVE evidence record. Source: the masked, read-only inventory of HOST-A taken on 2026-10-31
(`tools/hosta/inventory_readonly.sh`, non-root, output through `tools/hosta/mask.sh`). Shapes and counts only: no
address, host name, account or object name of neXus appears. It updates the measured rows of
`PORTS_AND_RESOURCES.md` §1 (FROZEN, measured 2026-10-30) as evidence; the frozen document itself is amended only
through a PO decision record, so where the two disagree this record is the newer measurement.

## 1. What was measured

| Fact | 2026-10-31 | Earlier figure (2026-10-30) | Consequence |
|---|---|---|---|
| Kubernetes | k3s v1.36.4, single node, containerd | same | none |
| Root filesystem (the one filesystem every PVC, image and backup shares) | **69 % used, 305 GiB free** of 1005 GiB | 80 % used, 189 GiB free | the 25 % headroom rule of AGENTS.md section 8 holds again; the storage budget below is raised |
| Node ports 1344 and 11344 | not in use | not in use | the pilot's ICAP ServiceLB port 1344 does not collide |
| In-cluster registry | a Service `registry` in `kube-system`, port 80 to 5000 | same | rwsafe images are pushed there by the build Jobs (`deploy/rwsafe/build`) |
| How the other product builds images | kaniko Jobs in its own build namespace pushing to that registry; a build-cache repository exists | not recorded | the pilot's build follows the same pattern in `<product>-build`, with its own repositories `<product>-dataplane`, `<product>-control` and no cache repository |
| Ingress | Traefik is the LoadBalancer for 80/443 through ServiceLB | same | the pilot adds no Ingress; the admin UI is reached by `kubectl port-forward` |
| rwsafe namespaces | none (`rwsafe*` absent) | none | the pilot starts from nothing |
| PriorityClasses | the system classes and the other product's low class (-100) | same | rwsafe's classes (1000, 500, -200) are unchanged (Q-10) |
| ResourceQuota | none anywhere | none | rwsafe brings its own (k3s overlay) |

## 2. The storage budget

`tools/deploy/manifest_check.py` refuses a render whose PVCs together request more than `HOST_FREE_STORAGE_BUDGET`
(PR 27 review D-06). From this measurement: 305 GiB free minus the kubelet's hard eviction reserve (nodefs.available
5 % of 1005 GiB = 50.25 GiB) = 254.75 GiB, rounded down to **254 GiB** (was 138 GiB). local-path reserves nothing, so it
is a budget, not a guarantee.

The capture cap does **not** follow: `RWSAFE_CAPTURE_MAX_STORE_BYTES` stays at 32 GiB and the PVC
`rwsafe-capture-store` at 40Gi (DEPLOY_AND_SHARED_HOST_RUNBOOK §7.5: raising it is the PO's decision), and redacted
capture stays off in the pilot. The figures "80 % used" and "138Gi" in `DEPLOY_AND_SHARED_HOST_RUNBOOK.md` §7.5 and in the comments of
`deploy/rwsafe/base/20-configmaps.yaml` describes the 2026-10-30 measurement.

## 3. Still to measure before the pilot's first apply

- The ServiceLB pods' labels on HOST-A (`svccontroller.k3s.cattle.io/svcname`, `.../svcnamespace`), which the
  NetworkPolicy `rwsafe-icap-from-servicelb` selects (k3s overlay, UNVERIFIED since 2026-10-30): read them from the
  first `svclb-*` pod of the pilot's Service (PILOT_RUNBOOK.md step 13 shows the count of ready ServiceLB pods).
- Whether the node's hostPort traffic passes the host firewall's prerouting hook before the DNAT (PILOT_RUNBOOK.md
  steps 11 and 13, UNVERIFIED 2026-10-31): proved by the test from a machine that is not a proxy.
