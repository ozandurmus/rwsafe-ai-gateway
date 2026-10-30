# ADR-001: Hosting on HOST-A and namespace isolation

Status: PROPOSED
Date: 2026-10-30
Answers: brief section 2 (Hosting), section 4 rules 1 and 6, section 10.4 Portability; council ARCH-2, Argon P0-2, P1-2,
offensive seat "same server" risks, privacy seat "same server" risks

## Context

The PO decided that rwsafe runs on the same single k3s node as neXus with its own infrastructure on it and must never
conflict with neXus. The 2026-10-30 inventory (`docs/operations/PORTS_AND_RESOURCES.md`) shows: no ResourceQuota,
LimitRange or PDB anywhere; neXus pods at `system-cluster-critical` with disk-pressure tolerations; PSA `restricted` only
on the scanner namespace; one LVM root filesystem at 80 % that every PVC shares without quota; k3s Secrets encrypted at
rest. neXus's own portability contract (`PORT-1`, `PORT-3`) forbids quota, limit-range and Ingress objects in the base
manifest directory because OpenShift projects pre-provision them differently; the brief's rule 1 requires them. The
corporate target platform is OpenShift (`docs/reference/CORPORATE_TECHNOLOGY_STACK.md`).

## Decision

1. **Three namespaces**: `rwsafe` (runtime), `rwsafe-build` (kaniko builds, integration Jobs), `rwsafe-security`
   (scanners). Label `app.kubernetes.io/part-of: rwsafe` (never `nexus-ui2`). No rwsafe object names a `ui2*` namespace,
   Service, Secret or PVC; a manifest test asserts it (as neXus C11 NS-1).
2. **Kustomize layout** `deploy/rwsafe/base` (portable workloads: Deployments, StatefulSet, Services, ConfigMap and Secret
   contracts, NetworkPolicies, PDBs, ServiceAccounts) and overlays `deploy/rwsafe/overlays/k3s` (Namespace labels,
   ResourceQuota, LimitRange, PriorityClasses, Ingress objects, ServiceLB Services for ICAP) and
   `deploy/rwsafe/overlays/openshift` (Routes, no quota objects). This satisfies brief rule 1 and PORT-3 at once.
3. **Isolation beyond quota** (ARCH-2): PriorityClasses `rwsafe-dataplane` 1000, `rwsafe-control` 500, `rwsafe-batch`
   −200, all `preemptionPolicy: Never`; **no tolerations**; ResourceQuota requests 4 CPU / 8 GiB, limits 8 CPU / 16 GiB,
   `requests.storage` 150 GiB, `services.loadbalancers` 3 (ICAP, SNMP, optional proxy; PLAT-F6), with smaller quotas on
   `rwsafe-build` and `rwsafe-security`; LimitRange with defaults so no container is unlimited; PSA `restricted` enforced on `rwsafe` and
   `rwsafe-security`; `baseline` on `rwsafe-build` because kaniko needs it (the one documented relaxation, PLAT-F6);
   `automountServiceAccountToken: false` on **every** rwsafe pod, the control plane included: the disk watermark is read
   with `statvfs` on the mounted capture-store path (`java.nio.file.FileStore`), which on local-path reports the root
   filesystem and on OpenShift the PVC, so no kubelet API and no cluster-scoped RBAC is needed (PLAT-F7). Every `emptyDir`
   carries a `sizeLimit` (512 Mi on runtime pods, 256 Mi for the verdict spool, 4 Gi on build pods), enforced by the
   manifest test.
4. **Storage**: local-path PVCs with application-enforced byte caps and the disk watermark breaker
   (`CAPACITY_AND_SLO_MODEL.md` §2); no `hostPath`; raw bodies content-addressed and deduplicated before encryption.
5. **Network**: namespace default-deny; explicit allows only (PORTS_AND_RESOURCES §4.2). Egress to the AI platforms is
   allowed only from the gateway pods and only through the corporate proxy; the ICAP pods have no egress beyond DNS and
   the control plane.
6. **Workload security**: `runAsNonRoot`, no fixed UID/GID (arbitrary-UID images, group-0 ownership), read-only root
   filesystem with emptyDir scratch, all capabilities dropped, seccomp RuntimeDefault, digest-pinned images, Secrets as
   file mounts under `/run/secrets/`; no hostPort, no hostNetwork, no NodePort in the base (the k3s overlay's ServiceLB
   Service is the one node-level exposure, for ICAP).
7. **Shared with neXus**: only the node, the ingress controller, the local registry, the directory source and the SIEM.
   Never a database, PVC, Secret, ConfigMap or ServiceAccount.

## Alternatives considered

- A second VM: ruled out by the PO (there is no other server).
- A separate k3s cluster on the same VM (k3s in a VM or a second k3s instance): doubles control-plane overhead on a node
  with 16 vCPU and complicates the single ingress; rejected.
- Putting rwsafe in the `ui2` namespace with a prefix: violates brief rule 1 and the HOST_X spirit; rejected.
- ResourceQuota in the base manifests: violates PORT-3; the overlay solves it.

## Consequences

- AC-1 and AC-4 are testable from manifests alone (quota sum, PriorityClass order, PSA labels, PORT-1 checklist).
- neXus is unaffected until ADR-003's ingress change, which is a separate neXus PR.
- The OpenShift overlay needs a Route per host and the corporate quota; the base is identical.

## Evidence and UNVERIFIED facts

- Measured inventory 2026-10-30 (shapes and counts only). k3s v1.36.4; PSA labels are the standard admission mechanism.
- UNVERIFIED: whether the corporate OpenShift projects allow a product-defined PriorityClass (cluster-scoped) or require
  the platform team to create it; recorded as an OpenShift-stage precondition.

## Open questions

OPEN_QUESTIONS Q-10 (PriorityClass relative to `ui2-low`), Q-11 (neXus limits over-commit the node).
