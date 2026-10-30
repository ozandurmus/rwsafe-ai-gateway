# deploy/rwsafe: kustomize base and overlays (design drafts)

ADR-001 §2. `base/` holds the portable workload manifests (identical on k3s and OpenShift: PORT-1/PORT-3); `overlays/k3s/`
adds what only HOST-A needs (Namespace labels, PriorityClasses, ResourceQuota, LimitRange, Ingress objects, the ServiceLB
Service for ICAP); `overlays/openshift/` adds Routes and nothing else. At design freeze only the isolation objects of the
k3s overlay are written, as the artefact AC-1 and AC-4 are checked against; workloads follow in the implementation phase.

Rules: no `hostPath`, no `hostPort` in pod specs, no fixed UID/GID, read-only root, all capabilities dropped, digest-pinned
images, Secret contracts without values, real names only in uncommitted ConfigMaps (`rwsafe-estate`). The manifest test
suite asserts every rule and that no object names a `ui2*` namespace or Service.
