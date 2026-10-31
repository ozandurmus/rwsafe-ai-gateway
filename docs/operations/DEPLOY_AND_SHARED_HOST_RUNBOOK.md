# Deploy and shared-host runbook

**Status:** FROZEN by `docs/design/PO_DECISION_RECORD_2026_10_30_DESIGN_FREEZE.md` (2026-10-30); amended only through a PO decision record or an ADR
that quotes one.

**History:** DRAFT for design freeze (becomes the operator procedure in the implementation phase). Companion to ADR-001,
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
2. Create the Secrets' values with `openssl rand` as the Secrets named in `runtime-contracts.json`; no Secret object is
   committed or rendered (§7.1, §7.4): database roles, privacy
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

## 7. Build and apply commands (implementation phase)

Agents build and test; **the apply is the Product Owner's step**, run in the PO's own terminal after the checks in §3 and
outside the protected windows. No agent runs `kubectl apply`, `kubectl diff` against HOST-A or a container build for a
release.

### 7.1 What is committed

| Path | What |
|---|---|
| `deploy/images/dataplane.Containerfile`, `deploy/images/control.Containerfile` | multi-stage builds: Gradle `imageDist` (the locked, checksum-verified runtime classpath) on UBI 9 OpenJDK 21, then the UBI 9 OpenJDK 21 runtime; digest-pinned bases, UID 185 with group 0, read-only-root friendly, no shell entry point |
| `deploy/rwsafe/base/` | ServiceAccounts (no token), committed ConfigMaps, `rwsafe-icap` (Deployment of the `rwsafe-dataplane` image, ClusterIP `rwsafe-icap`, PDB; preStop `/admin/drain` on the metrics port 9401, grace 30 s), `rwsafe-control` (Deployment, Service 8080/8091/8092 and metrics 9400, ready on `/readyz` when 8080, 8091, 8092 and 9400 listen; the SIEM, capture-key and notice values mounted from their contract objects; PVC `rwsafe-capture-store` 40Gi), `rwsafe-db` (PVC `rwsafe-db-data` 20Gi, StatefulSet, Service; roles `rwsafe_migrate` and `rwsafe_app` and the ADR-002 §7 tuning from `base/db/`), NetworkPolicies between rwsafe's workloads with a default deny |
| `deploy/rwsafe/overlays/k3s/` | namespaces, PriorityClasses and their assignment, quota and limits, the ICAP ServiceLB Service, the platform-peer NetworkPolicies (DNS, ServiceLB, Traefik, the metrics scraper on 9400 and 9401) and the directory and SIEM egress, each with its own RFC 5737 placeholder CIDR, the in-cluster registry image names with a placeholder digest |
| `deploy/rwsafe/contracts/runtime-contracts.json` | names and keys of the Secrets and uncommitted ConfigMaps the manifests reference; never rendered, never applied |
| `tools/deploy/manifest_check.py` | renders the k3s overlay offline and asserts the section 8 rules; CI job `manifests` |

### 7.2 Local checks (any agent, no cluster)

```bash
./java/gradlew -p java :dataplane:imageDist :control:imageDist   # the classpaths the images copy
python3 -B tools/deploy/test_manifest_check.py                   # the check's self-test on synthetic fixtures
python3 -B tools/deploy/manifest_check.py                        # renders the k3s overlay; PASS with placeholder notes
```

### 7.3 Image build (ship pipeline, kaniko in `rwsafe-build`)

The build Job uses the repository root as context and one Containerfile per image; it pushes to the in-cluster registry
and reports the digest. On a workstation, only for a smoke check: `podman build -f deploy/images/dataplane.Containerfile
-t rwsafe-dataplane:dev .` (never pushed). Before a release, re-resolve the base digests named in each Containerfile.

### 7.4 Apply (Product Owner, HOST-A terminal)

First installation follows §4: namespaces and isolation objects, then the Secrets and the ConfigMaps `rwsafe-estate`,
`rwsafe-snapshot-public-keys` and `rwsafe-siem-destination` from `runtime-contracts.json` (values from the operator's
store; `kubectl create secret generic ... --from-file`, never `--from-literal`). The optional objects of §7.5
(`rwsafe-capture-key`, `rwsafe-siem-credentials`, `rwsafe-enduser`) may follow later: without them the pods start with
capture and the notice off and no HEC destination. Every release then renders with the candidate digests in memory and
diffs before it applies:

```bash
# in a scratch copy of deploy/rwsafe (never committed): set the candidate digests
cd "${scratch}/overlays/k3s"
kustomize edit set image \
  rwsafe-dataplane=registry.kube-system.svc.cluster.local/rwsafe-dataplane@sha256:<dataplane digest> \
  rwsafe-control=registry.kube-system.svc.cluster.local/rwsafe-control@sha256:<control digest>
# the estate patch, in memory only (§2): each estate CIDR replaces its own RFC 5737 placeholder, the directory's in the
# NetworkPolicy rwsafe-control-to-directory (192.0.2.0/24) and the SIEM receivers' in rwsafe-control-to-siem
# (198.51.100.0/24); nothing holding a real value is written to disk or printed. An empty value leaves `cidr: ` and the
# check below refuses the render.
export RWSAFE_DIRECTORY_CIDR="$(kubectl -n rwsafe get configmap rwsafe-estate -o jsonpath='{.data.directory-cidr}')"
export RWSAFE_SIEM_CIDR="$(kubectl -n rwsafe get configmap rwsafe-siem-destination -o jsonpath='{.data.siem-cidr}')"
render() { kubectl kustomize . | python3 -c 'import os, sys; sys.stdout.write(sys.stdin.read()
  .replace("cidr: 192.0.2.0/24", "cidr: " + os.environ["RWSAFE_DIRECTORY_CIDR"])
  .replace("cidr: 198.51.100.0/24", "cidr: " + os.environ["RWSAFE_SIEM_CIDR"]))'; }
render | python3 -B "${repo}/tools/deploy/manifest_check.py" --rendered /dev/stdin --release
render | kubectl diff --server-side -f -
# the control plane first, and wait for it: a rolling ICAP pod posts its drain's verdict events to a running control
# plane, never to its own emptyDir spool that dies with it (PR 18 review D-02)
render | kubectl apply --server-side -l 'app.kubernetes.io/name!=rwsafe-icap' -f -
kubectl -n rwsafe rollout status deploy/rwsafe-control --timeout=5m
render | kubectl apply --server-side -f -
kubectl -n rwsafe rollout status deploy/rwsafe-icap --timeout=5m
```

The control plane is ready only when `/readyz` answers, that is after Flyway ran as `rwsafe_migrate` and with all four
listeners (8080, 8091, 8092, 9400) up; its 5 s preStop lets in-flight event batches on 8092 finish. The ICAP pods drain from
their preStop hook (`/admin/drain`, §1.2) and end inside the 30 s grace period. `--release` refuses the committed
all-zero placeholder digest and the documentation-range directory and SIEM CIDRs. The digest edit lives only in the scratch copy (or in the
deploy script's memory) and is never committed. The data plane is ready only once it holds a valid signed
snapshot from `rwsafe-control:8091`; until the control plane serves the snapshot feed, a fresh data plane stays not
ready (fail closed) and ProxySG follows ADR-010.

### 7.5 First run of group claims, redacted capture, the end-user notice, SIEM export and metrics (Product Owner)

Operator steps for the features wired after the freeze (group claims PR 20, SIEM export PR 23, end-user notices PR 22,
redacted capture PR 25); no design changes. Every switch below is a committed ConfigMap value changed by a pull request
and applied with §7.4, or an uncommitted object from `runtime-contracts.json`; never `kubectl set env` or `kubectl
patch`. Values come from the operator's store (`~/.config/rwsafe/`) and never touch a tracked file, a command argument or
the terminal. An environment value is read at start, so after an uncommitted ConfigMap changes the PO deletes the pod
(`kubectl -n rwsafe delete pod -l app.kubernetes.io/name=rwsafe-control`, or the ICAP pods one at a time) and waits for
readiness; the Deployment recreates it with nothing hand-made left behind.

**Group claims (`RWSAFE_GROUP_CLAIM_ENCODING`, committed unset).** While unset the engine reads no
`X-Authenticated-Groups` claim and every transaction takes the strictest of the Everyone rule and every enforce group
rule. Once the proxy's encoding of that header is verified (the PO, as proxy administrator, confirms the header
substitution in the ProxySG ICAP service configuration; recorded in `docs/operations/PHASE0_PROXYSG_RECORD.md` as `plain`
or `base64`, never with a group name), a pull request adds `RWSAFE_GROUP_CLAIM_ENCODING: "plain"` or `"base64"` to
`rwsafe-icap-config` and §7.4 rolls the ICAP pods. Check: approve a synthetic group-scoped rule in monitor mode, send one
REQMOD through Secure ICAP with a synthetic group, and see its rule id in the event's `monitorRuleIds` (Traffic screen).

**End-user notice (`rwsafe-enduser`).** Create the ConfigMap from an env file in the operator's store holding the five
keys of the contract (`controller-name`, `dpo-contact`, `policy-link`, and the two retention figures in whole days,
`retention-metadata` and `retention-redacted`):

```bash
kubectl -n rwsafe create configmap rwsafe-enduser --from-env-file="${HOME}/.config/rwsafe/enduser.env"
```

Then delete the control plane pod and the ICAP pods one at a time. Check: `GET /api/v1/notice` (signed in) names a version
(`tr-<n>-<8 hex>`); while any value is missing or refused the notice has no version, nothing can be acknowledged and
capture stores nothing.

**Capture key (`rwsafe-capture-key`).** One key file per key id (base64 of 32 random bytes), `active` naming it and an
empty `shredded`, created on the HOST-A terminal without printing anything:

```bash
d="$(mktemp -d)"   # mode 0700
head -c 32 /dev/urandom | base64 > "${d}/cap-1.key"
printf 'cap-1\n' > "${d}/active"
: > "${d}/shredded"
kubectl -n rwsafe create secret generic rwsafe-capture-key --from-file="${d}"
shred -u "${d}"/* && rmdir "${d}"
```

The Secret is mounted whole, so a rotation (a new `<id>.key`, `active` pointed at it) and an emergency shred (the id
added to `shredded`, its key file removed) reach the running pod without a manifest change (LOCAL_RUN.md "Redacted
capture"). The capture store is the PVC `rwsafe-capture-store` (40Gi requested; the application caps it at 32 GiB,
below ADR-009's 80 GiB, while HOST-A's disk is 80 % used). Raising the cap and the claim is the PO's decision, after a
new disk measurement; `tools/deploy/manifest_check.py` refuses a render whose PVCs together exceed its host-free budget
(`HOST_FREE_STORAGE_BUDGET`, 138Gi: PORTS_AND_RESOURCES §1 free space minus the kubelet's 5 % eviction reserve).

**Turning capture on.** Only with the notice versioned, the key Secret present and the PO's go-ahead (Q-4 b): one pull
request sets `RWSAFE_CAPTURE_MODE: "redacted"` in both `rwsafe-control-config` and `rwsafe-icap-config`; §7.4 applies
it (control plane first). Check on Health: `capture` UP with the active key id, `capture-watermark` UP or DEGRADED (at
the measured 80 % node-disk use it is DEGRADED, which stops raw content only; redacted content stops at 85 %). Turning
it off is the same change back; stored records stay until retention.

**SIEM export (`rwsafe-siem-destination`, `rwsafe-siem-credentials`).** The ConfigMap is created from a directory in
the operator's store with one file per contract key (each value written with `printf '%s'`, no trailing newline; `ca.crt`
is the receivers' PEM bundle; `siem-cidr` the receivers' addresses for the egress NetworkPolicy), the HEC token Secret
the same way:

```bash
kubectl -n rwsafe create configmap rwsafe-siem-destination --from-file="${HOME}/.config/rwsafe/siem/"
kubectl -n rwsafe create secret generic rwsafe-siem-credentials --from-file="${HOME}/.config/rwsafe/siem-credentials/"
```

The egress rule reaches only `siem-cidr` on 6514 (syslog over TLS) and 8088 (HEC); §7.4 refuses a release without it.
One test event per format before production (clears the LEEF UNVERIFIED mark in LOCAL_RUN.md):

1. CEF: `enabled` `true`, `syslog-format` `cef`; delete the control plane pod; Health's `siem` row shows `syslog` UP with a
   delivered count (the `siem_export.start` ledger row is the first). Run the ICAP e2e Job (§4 step 5; synthetic traffic only) and confirm
   on the SIEM that one verdict event and one ledger row parse into their fields, with no `[WITHHELD]` other than
   expected. Record shapes and counts only in `docs/reviews/`.
2. LEEF: `syslog-format` `leef`, recreate the ConfigMap (`kubectl -n rwsafe delete configmap rwsafe-siem-destination`,
   then the create above), delete the pod, run the ICAP e2e Job again, and confirm in QRadar the LEEF 1.0 header and that
   values holding `\` or `=` are escaped. The watermark is per destination, so the second run's new events are the test.
3. HEC (when used, and for the audit-ledger copy, Q-SIEM-2): set `hec-url` and `hec-index`, create the token Secret,
   delete the pod; Health shows `hec` UP with a delivered count (HTTP 200 acknowledgements); the events arrive in the
   index.

Keep the format the SIEM parsed correctly; a failure leaves the destination DOWN on Health with its reason, never a
silent drop.

**Metrics (9400 control plane, 9401 ICAP).** Both NetworkPolicies admit only pods labelled
`rwsafe.io/metrics-scraper=true` in a namespace with the same label: both the scraper's namespace and its pods carry
it. Labelling them is a change outside rwsafe's namespaces, asked of the PO first (AGENTS.md section 8); until then
nothing scrapes. Residual (accepted, PR 27 review Q-1): 9401 also holds the ICAP preStop drain (`/admin/drain`), so an
admitted scraper pod could drain an ICAP pod; label only the scraper itself. The control plane's `/metrics` carries the `rwsafe_siem_*`
series.
