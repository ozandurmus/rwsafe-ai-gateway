# Ports and resources: the HOST-A inventory and the rwsafe plan

**Status:** FROZEN by `docs/design/PO_DECISION_RECORD_2026_10_30_DESIGN_FREEZE.md` (2026-10-30); amended only through a PO decision record or an ADR
that quotes one.

**History:** DRAFT for design freeze. Source: read-only, masked inventory of HOST-A taken on 2026-10-30 with
`tools/hosta/inventory_readonly.sh` (non-root) and `tools/hosta/po_sudo_readonly.sh` (root-only listings run by the PO).
Values below are shapes and counts; no address, host name or account appears. Where the root-only pass has not yet been
read, the row says (root-only pass read 2026-10-30).

## 1. What HOST-A is (measured)

| Fact | Measured value |
|---|---|
| Platform | Ubuntu 26.04.1 LTS, kernel 7.0, VMware guest, single node |
| CPU | 16 vCPU (2 sockets × 8 cores, no SMT) |
| Memory | 62 GiB total, 8 GiB swap; working set 8 GiB, 52.8 GiB available at measurement |
| Disk | one 1 TB LVM root filesystem (ext4): 1005 GiB, **764 GiB used (80 %)**, 189 GiB available; `/boot` separate 2 GiB. Every PVC, the registry, the k3s datastore, images, backups and logs share this one filesystem |
| Image filesystem | same filesystem; images and layers 47.5 GiB |
| Kubernetes | k3s v1.36.4, containerd 2.3.4, Traefik ingress (k3s bundled), ServiceLB (klipper), local-path provisioner, metrics-server, CoreDNS, in-cluster registry (registry:3, digest-pinned) |
| kubelet eviction | hard: nodefs.available 5 %, imagefs.available 5 %; image GC high 85 % / low 80 %; maxPods 110; podPidsLimit unlimited; protectKernelDefaults true |
| Secrets at rest | `secrets-encryption: true` in the k3s config (verified non-root readable config file) |
| Time | UTC system clock, NTP synchronised; application schedules use Europe/Istanbul |
| Node conditions | MemoryPressure, DiskPressure, PIDPressure all False at measurement |

The kickoff brief said 60 % (section 4) and 80 % (council ARCH-2); the measurement is **80 %** with 189 GiB free. The
kubelet starts evicting at 5 % free (about 50 GiB), so the real working headroom before DiskPressure is about 140 GiB,
shared with neXus's backups, the registry and builds.

## 2. Ports actually in use

### 2.1 Host sockets (`ss`; process names from the PO's root-only pass)

| Proto | Port | Bind | Owner (inferred) | Note for rwsafe |
|---|---|---|---|---|
| tcp | 22 | any | sshd | management; firewall-restricted to two source blocks (neXus hardening H2) |
| tcp | 25 | any | the MTA (`master`) | **listens on all interfaces**; dropped from outside by the host firewall (verified from the ruleset); not needed by rwsafe; flagged as an observation |
| tcp/udp | 53 | specific (resolver) | systemd-resolved | — |
| tcp | 6443 | any | k3s API server (`k3s-server`) | firewall drops from outside (verified: input policy drop, only 22/80/443 accepted) |
| tcp | 6444, 10010, 10248, 10249, 10256, 10257, 10258, 10259 | loopback | k3s internals | — |
| tcp | 10250 | any | kubelet (`k3s-server`) | firewall drops from outside (verified) |
| udp | 8472 | any | flannel VXLAN | — |
| udp | 323 | loopback | chrony | — |
| tcp | 80, 443 | DNAT, not a socket | ServiceLB `svclb-traefik` hostPort → Traefik 8000/8443 | **the only public service ports**; rwsafe shares them by host name |

Free on the host: **1344** (ICAP), 11344 (Secure ICAP convention), 161/162 (SNMP), 514/6514 (syslog), 3128/8080 host-level
(the k3s Traefik dashboard port 8080 is inside the pod only), 1443/8443 host-level (Traefik uses 8443 inside its pod).

### 2.2 Cluster services (neXus and system)

| Namespace | Service | Type | Ports |
|---|---|---|---|
| kube-system | traefik | LoadBalancer (ServiceLB) | 80→web(8000) nodePort 30603, 443→websecure(8443) nodePort 30385; NodePorts are dropped at the outside interface by the host firewall (H2) |
| kube-system | registry | ClusterIP | 80→5000 |
| kube-system | kube-dns, metrics-server | ClusterIP | 53, 9153, 443 |
| ui2 | ui2-service | ClusterIP | 8080 |
| ui2 | ui2-service-internal | ClusterIP | 8080, 8086 (machine session) |
| ui2 | ui2-configuration | ClusterIP | 8084 |
| ui2 | ui2-compliance | ClusterIP | 8085 |
| ui2 | ui2-db | ClusterIP | 5432 |

Port 8087 named in the brief is not a Service today; it is a container port reserved by neXus and stays out of rwsafe's
plan. ClusterIP ports do not collide across namespaces, but rwsafe avoids reusing neXus's numbers anyway so a mistaken
cross-namespace request fails loudly.

### 2.3 Ingress today

One Ingress in `ui2`, class traefik, no `tls:` block (TLS comes from Traefik's default certificate store), two rules: a
**host-less catch-all** `/` → ui2-service and a host rule `/` → ui2-service. Traefik's default certificate is a local-CA
certificate (not self-signed), valid to 2028-12, with one 3-label DNS SAN and one IP SAN. Traefik runs with
`--entryPoints.websecure.http.tls=true`, HTTP→HTTPS permanent redirect, TLS 1.2+ AEAD-only options, and both the
Kubernetes Ingress and the Traefik CRD providers; no Middleware, IngressRoute or default backend object exists.
Consequence for ADR-003: an unknown Host or a bare IP reaches ui2-service today; rwsafe's design needs the catch-all
replaced by an explicit 404 default backend, and a per-host TLS Secret per product.

## 3. The rwsafe port plan

| Component | Protocol | Exposure | Port | Why this port |
|---|---|---|---|---|
| Admin UI and API (`rwsafe.<corp-domain>`) | HTTPS | Traefik 443 by host name | container 8080 → Service 8080 | same convention as neXus; no new host port |
| LLM API gateway (`ai-api.<corp-domain>`) | HTTPS (HTTP/1.1 and HTTP/2, SSE) | Traefik 443 by host name (council ARCH-3, Q2 recommendation: yes) | container 8090 → Service 8090 | no new host port, no firewall exception; SDK `*_BASE_URL` values take a URL, so a path or host is enough |
| ICAP (ProxySG → rwsafe) | ICAP/1.0 over TCP, plain or TLS (Secure ICAP) | **Service of type LoadBalancer through ServiceLB on the node address** (same mechanism Traefik uses, so a second pod can run during rollout: no `hostPort` in the rwsafe pod spec, council ARCH-5). ServiceLB masquerades the source address (PLAT-F2), so the ProxySG allowlist is enforced by the **host firewall** and peer identity by **mTLS**, not by the engine's view of the TCP source | **1344** plain ICAP (pilot only, H-2), **11344** Secure ICAP (TLS, mTLS) | 1344 is the IANA-registered ICAP port and ProxySG's default; 11344 is the common Secure-ICAP convention (UNVERIFIED as a ProxySG default: ProxySG lets the port be set per ICAP service, so the number is a choice, not a constraint) |
| Chained forward proxy for WebSocket (optional, ADR-004/005) | HTTP CONNECT / TLS | ServiceLB on the node address | **3128** | squid convention, free on the host; only if phase 0 shows ProxySG cannot hand WebSocket to ICAP |
| Agent channel (off-net agents, ADR-006) | HTTPS + mTLS | Traefik 443 by host name (`agent.<corp-domain>`) or the gateway host | container 8095 | no new port |
| SNMP agent (health, polled by the corporate NMS) | UDP | ServiceLB on the node address | **1161** (UDP) | 161 is free, but binding 161 needs a privileged pod or NET_BIND_SERVICE; 1161 keeps the pod unprivileged; the NMS polls a non-standard port, or the host firewall redirects 161→1161 as a hardening exception (PO choice, HARDENING_EXCEPTIONS H-3) |
| Syslog out (to the SIEM) | TCP/TLS 6514 or UDP 514 | egress only | remote port per SIEM | no inbound port |
| PostgreSQL | TCP | ClusterIP only, NetworkPolicy to rwsafe control plane and worker | 5432 (own StatefulSet `rwsafe-db`) | cluster-internal; no conflict with `ui2-db` (different namespace and Service) |
| Internal control-plane services | HTTP | ClusterIP only | 8091 (policy snapshot feed), 8092 (capture sink) | distinct from neXus's 8084/8085/8086 |
| Metrics | HTTP | ClusterIP only, scraped in-namespace | 9400 (admin), 9401 (ICAP), 9402 (gateway) | distinct from Traefik's 9100 |

Everything inbound from outside the host therefore uses **three** node-level ports beyond 443: 1344 and 11344 (ICAP, only
from the ProxySG addresses) and, when the PO chooses it, 1161/udp from the NMS. Each is a listed hardening exception.

## 4. Resource plan and the isolation objects

### 4.1 Measured neXus footprint (running pods, 2026-10-30)

| Namespace | Requests | Limits | Live working set |
|---|---|---|---|
| ui2 | 1.8 CPU, 5.0 GiB | 18 CPU, 60 GiB | 3.7 GiB, 0.06 CPU |
| ui2-build (one build running) | 0.5 CPU, 1.0 GiB | 3 CPU, 4 GiB | 1.5 GiB, 1.6 CPU |
| ui2-security | 2.1 CPU, 4.25 GiB | 4 CPU, 8 GiB | 0.3 GiB, 0.3 CPU |
| kube-system | 0.2 CPU, 0.14 GiB | mostly unlimited | 0.5 GiB |
| **Total** | **4.6 CPU, 10.4 GiB** | **25 CPU, 73.9 GiB** | **8 GiB** |

neXus's limits already exceed the node (25 of 16 CPU, 74 of 62 GiB): it relies on limits never being reached at once.
There is **no ResourceQuota, no LimitRange, no PodDisruptionBudget** anywhere; one `ui2-low` PriorityClass (−100,
`preemptionPolicy: Never`) exists besides the system classes; every other neXus pod is `system-cluster-critical`
(2000000000) with a `disk-pressure` toleration. PSA `restricted` is enforced only on `ui2-security`. Five NetworkPolicies
exist; `ui2` has no namespace default-deny.

### 4.2 rwsafe namespace objects (k3s overlay; PORT-3 keeps them out of the base manifests)

| Object | Value | Reason |
|---|---|---|
| Namespaces | `rwsafe` and `rwsafe-security`: PSA `restricted`; `rwsafe-build`: PSA `baseline` (kaniko); label `app.kubernetes.io/part-of=rwsafe` | distinct label value so no selector written for `nexus-ui2` matches; the build relaxation is the one documented exception (PLAT-F6) |
| PriorityClass `rwsafe-dataplane` | value **1000**, `preemptionPolicy: Never`, `globalDefault: false` | above the default 0 so a build pod (default 0) is evicted before the ICAP engine, far below every neXus class (ARCH-2) |
| PriorityClass `rwsafe-control` | value **500**, Never | below the data plane: under pressure the admin UI goes before ICAP |
| PriorityClass `rwsafe-batch` | value **−200**, Never | below `ui2-low`; workers, async classifiers, e2e |
| Tolerations | none; in particular no `node.kubernetes.io/disk-pressure` toleration | rwsafe is evicted before neXus when the disk fills (ARCH-2) |
| ResourceQuota `rwsafe-compute` | requests.cpu **4**, requests.memory **8Gi**, limits.cpu **8**, limits.memory **16Gi**, pods 40, persistentvolumeclaims 6, requests.storage **150Gi**, services.loadbalancers **3** | fits inside the headroom computed in CAPACITY_AND_SLO_MODEL §3; `rwsafe-build` and `rwsafe-security` carry their own smaller quotas (PLAT-F6) |
| LimitRange `rwsafe-defaults` | default request 100m/128Mi, default limit 500m/512Mi, max per container 4 CPU / 8Gi | no container runs unlimited |
| NetworkPolicy `default-deny` | deny all ingress and egress in `rwsafe` | then explicit allows: Traefik → admin/gateway pods; ServiceLB → ICAP pods on 1344/11344; control plane → `rwsafe-db`; data plane → control plane 8091/8092; egress to DNS, the AI platforms' upstreams through the corporate proxy (gateway only), LDAP, SIEM, SMTP. No rule names a `ui2*` namespace |
| PodDisruptionBudget | ICAP and gateway: `minAvailable: 1` | with 2 replicas, a rollout or a drain never takes both |
| Storage caps | `rwsafe-db-data` 20Gi, `rwsafe-capture-store` 100Gi (application byte cap 80Gi, raw-body persistence stops at a 75 % node-disk watermark), `rwsafe-model-store` 10Gi read-only | local-path has no quota enforcement (measured: every PVC reports the root filesystem's usage), so the cap is enforced by the application and by the quota's `requests.storage` |

### 4.3 rwsafe workloads and their requests and limits (initial, per CAPACITY_AND_SLO_MODEL)

| Workload | Replicas | Request | Limit | PriorityClass | Strategy |
|---|---|---|---|---|---|
| `rwsafe-icap` (Netty) | 2 | 500m, 1Gi each | 1.5 CPU, **2Gi** each (512 MiB direct + 256 MiB full-body semaphore + heap; PLAT-F1) | rwsafe-dataplane | RollingUpdate maxUnavailable 0, maxSurge 1, PDB minAvailable 1 |
| `rwsafe-gateway` (Netty) | 2 | 250m, 512Mi each | 1 CPU, 1.5Gi each | rwsafe-dataplane | same |
| `rwsafe-control` (Spring Boot admin, API, policy feed, capture sink) | 1 | 500m, 1Gi | 2 CPU, 3Gi | rwsafe-control | Recreate (migrations), the data plane keeps serving from its snapshot |
| `rwsafe-worker` (async classifiers, SIEM out, retention, exports) | 1 | 250m, 1Gi | 2 CPU, 4Gi | rwsafe-batch | Recreate |
| `rwsafe-db` (PostgreSQL 16) | 1 | 250m, 1Gi | 2 CPU, 3Gi | rwsafe-control | StatefulSet |
| Sum | | **3.5 CPU, 6.8 GiB** | within the 8 CPU / 16 GiB quota: ICAP 2 × (1.5 CPU, 2Gi), gateway 2 × (0.75, 1Gi), control 1.5/3Gi, worker 1/2Gi, db 1.5/3Gi = **7.75 CPU, 14 GiB** | | |

## 5. Conflict check against neXus

| Check | Result |
|---|---|
| Node ports | rwsafe adds 1344, 11344 (ICAP), optionally 3128 and 1161/udp; none is in use on the host |
| 443 | shared through Traefik by host name; requires the neXus catch-all rule to go (ADR-003) |
| ClusterIP ports | rwsafe uses 8080 (admin), 8090, 8091, 8092, 8095, 9400–9402, 5432 (own DB); the only number shared with neXus is 8080 and 5432, each inside its own namespace and Service |
| PriorityClass | rwsafe's highest (1000) < ui2-low? No: `ui2-low` is −100 and is neXus's deliberately lowest class for packet analysis; rwsafe's data plane sits above it and far below `system-cluster-critical` (2 × 10⁹). The PO's rule "strictly lower than neXus" is met for every neXus workload except packet analysis, which neXus itself declared lowest; this is stated in OPEN_QUESTIONS Q-10 for confirmation |
| Namespaces | `rwsafe`, `rwsafe-build`, `rwsafe-security`; no object names a `ui2*` namespace (checked by a manifest test, like neXus C11 NS-1) |
| Images | repositories `rwsafe-control`, `rwsafe-dataplane`, `rwsafe-e2e` in the shared registry; digest-pinned |
| Secrets | rwsafe's own HMAC, artefact, DB, signing and ICAP TLS keys; never a neXus Secret name |
| Protected windows | rwsafe deploys avoid 00/06/12/18 and 02:00–02:59 Europe/Istanbul; rwsafe's own scheduled jobs (retention, SIEM digests, model refresh) run at 04:00 and 16:00 Europe/Istanbul |

## 6. Root-only pass

Read on 2026-10-30; its findings are in `HARDENING_EXCEPTIONS.md` ("What the root-only pass showed"). No row above remains pending.
