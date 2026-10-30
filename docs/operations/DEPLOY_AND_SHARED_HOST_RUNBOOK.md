# Deploy and shared-host runbook

**Status:** DRAFT for design freeze (becomes the operator procedure in the implementation phase). Companion to ADR-001,
ADR-003, ADR-010, ADR-011 and `docs/design/SHIP_PIPELINE_PLAN.md`. Mirrors neXus `docs/operations/UI2_LOCAL_KUBERNETES_DEPLOYMENT.md`
and `HOST_A_RUNBOOK.md` where the mechanics are the same. No address, host name, account or key path appears here; the
operator's own store holds them (`~/.config/nexus/hosta`, `~/.config/rwsafe/`).

## 1. Zero-downtime rollout on a single node (AC-2)

### 1.1 Why `hostPort` and `Recreate` are forbidden for the data plane

On one node a pod with `hostPort: 1344` blocks a second pod with the same hostPort from scheduling, so a rollout must kill
the old pod before the new one can start (a gap), and `Recreate` does the same by definition. rwsafe exposes ICAP through
a **Service of type LoadBalancer** that k3s's ServiceLB implements with its own `svclb-*` DaemonSet pod holding the
hostPort and forwarding to the Service's endpoints (measured: Traefik is exposed exactly this way today). The rwsafe ICAP
pods themselves have no hostPort, so two can run at once and the Service endpoints switch without a gap. On OpenShift the
same Service is a plain LoadBalancer or NodePort Service behind the platform's own exposure; the base manifest does not
change.

### 1.2 The ICAP rollout sequence

```
Deployment rwsafe-icap: replicas 2, RollingUpdate {maxSurge: 1, maxUnavailable: 0}, PodDisruptionBudget minAvailable 1
readinessProbe: ICAP OPTIONS on 1344 must return 200 with a loaded policy snapshot (not just an open socket)
preStop: POST /admin/drain (local) -> OPTIONS and readiness answer 503 at once; transactions arriving on pooled or
         raced connections during the first 15 s are still SERVED, each response carrying "Connection: close";
         new transactions are refused only after 15 s; exit at zero in-flight or 20 s (PLAT-F3)
terminationGracePeriodSeconds: 30
```

1. New pod starts, loads the snapshot from the control plane (or the last persisted snapshot on its emptyDir cache),
   passes readiness only when it can serve OPTIONS 200.
2. Endpoints add the new pod; ServiceLB (iptables) starts distributing new connections to it.
3. The old pod's preStop marks OPTIONS and readiness unhealthy so ProxySG's health check and the Service stop choosing
   it; transactions that still arrive in the convergence window (endpoint removal and the 5 s health-check interval)
   are served with `Connection: close`, so pooled ProxySG connections end at a transaction boundary (ICAP has no GOAWAY).
   Only after 15 s are new transactions refused.
4. Endpoints remove the old pod; it exits within the grace period.

**Proof** (AC-2 test, phase 1): an in-cluster load generator holds 50 pooled ICAP connections at 200 transactions/s
against the Service while `kubectl rollout restart deploy/rwsafe-icap` runs; acceptance is 0 failed transactions and 0
connection resets, recorded in `docs/reviews/` with the run id. The same test runs for `rwsafe-gateway` over HTTPS.

**ProxySG side**: the ICAP service points at the node address and port 1344/11344 with health checks every 5 s; connection
reuse on; fail behaviour per ADR-010. Nothing in ProxySG changes during an rwsafe rollout.

**Source addresses**: k3s ServiceLB masquerades the TCP source to its own pod address before the packet reaches the
ICAP pod (PLAT-F2). The ProxySG allowlist is therefore enforced by the host firewall (`@icap_clients`, HARDENING H-1) and
the peer is identified by its client certificate on 11344; the NetworkPolicy admits the ServiceLB pods of the rwsafe ICAP
Service. `externalTrafficPolicy: Local` keeps traffic on the node but does not preserve the source address through ServiceLB.

### 1.3 Control plane and worker

`rwsafe-control` runs Flyway at start and is `Recreate`; the data plane keeps serving from its snapshot during the gap.
`rwsafe-worker` drains its job leases on SIGTERM (`terminationGracePeriodSeconds` 300) and releases every lease in a
terminal state (brief section 8, "stale locks").

## 2. Deploy applies manifests and config together and reports drift

Every release renders the committed kustomize overlay with the candidate image digests, runs `kubectl diff
--server-side` first, prints the drift summary (objects that differ: name and field count, never values), and applies
only after the drain. **Real names never touch the working tree** (PLAT-F8): the deploy reads the host names and other
estate values from the in-cluster ConfigMap `rwsafe-estate`, builds a transient kustomize patch in memory and streams the
rendered manifests to `kubectl diff -f -` and `kubectl apply -f -` on stdin; no rendered file with a real value is written
to disk or committed. A hand-made object or `kubectl set env` disappears at the next apply, by design; the deploy prints
the diff so nobody is surprised. Secrets are never applied over existing ones: their manifests carry name and keys only;
values are created once by the operator procedure in §4 and patched.

## 3. Shared-host rules

- **Lock**: every build or rollout of either product takes `~/.locks/hosta-build.lock`; the waiting side prints whose lock
  it waits for and gives up after 45 minutes with exit 3.
- **Windows**: no rwsafe build or deploy starts in 00:00–00:20, 06:00–06:20, 12:00–12:20, 18:00–18:20 or 02:00–02:59
  Europe/Istanbul (neXus job windows and backup hour); rwsafe's own scheduled jobs run at 04:00 and 16:00.
- **Disk**: before a build, the script reads the node filesystem usage; above 85 % it refuses to build (a kaniko build
  needs several GiB of scratch) and tells the operator what is consuming space in counts; above the 75 % watermark the
  product has already stopped persisting raw bodies.
- **Registry**: rwsafe images are `rwsafe-control`, `rwsafe-dataplane`, `rwsafe-e2e`; GC per `SHIP_PIPELINE_PLAN.md` §4.
- **neXus data is out of bounds**: no rwsafe script, job or operator step reads a `ui2*` object other than the read-only
  "is a neXus build running" check and the kubelet summary API.

## 4. First installation (operator steps, one time)

1. Apply the k3s overlay's namespace objects (Namespace with PSA labels, PriorityClasses, ResourceQuota, LimitRange).
2. Create the Secrets' values with `openssl rand`, patched into the committed empty Secret objects: database roles, privacy
   HMAC key (32 bytes, rwsafe's own), capture-store envelope key, policy-signing key, ICAP TLS server certificate and the
   ProxySG client CA for mTLS (from the proxy team), the gateway's upstream corporate API keys (from the AI platform
   admins), the e2e machine token. Values never touch a tracked file, a command argument or the terminal.
3. Create the uncommitted ConfigMaps that carry real names: `rwsafe-estate` (corporate domain list, tenant identifiers,
   ProxySG source addresses for the NetworkPolicy and the ICAP allowlist, LDAP base DNs, SIEM endpoint), from the operator's
   store.
4. Apply the base + overlay; wait for `rwsafe-db` ready; the control plane runs migrations; the data plane becomes ready
   when it has a snapshot.
5. Run the in-cluster ICAP e2e Job and the masked-role e2e Job; both must pass before the ProxySG team points a pilot
   ICAP service at rwsafe.

## 5. Backup and restore of rwsafe's own configuration

Nightly `pg_dump` of `rwsafe` (policies, identities, metadata) and an export of the policy registry as signed YAML, both
encrypted into the platform backup set; the capture store's chunk files are backed up only when the PO decides their
class needs it (default: not backed up; they are retention-bounded evidence, re-derivable from nothing, and the privacy
seat prefers fewer copies). Restore drill quarterly into the preview namespace; the drill replays deletion receipts so
expired data does not return (ADR-002).

## 6. What the deploy prints at the end

`site` (HTTPS status for `rwsafe.<corp-domain>` with the Host header via `--resolve`), `icap OPTIONS` status, `schema`
(Flyway head), `images` (digests, 19 chars), `drift` (object count), `snapshot` id, the security gate summary line, the
e2e verdicts. A deploy that ends without `Done.` is a failure with its reason in the last four lines (as neXus
`hosta_deploy.sh`).
