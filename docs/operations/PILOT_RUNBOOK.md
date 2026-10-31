# Pilot runbook: one test user's AI traffic through rwsafe on HOST-A

**Status:** DRAFT operator procedure (2026-10-31) for the first pilot. It applies the ratified
`DEPLOY_AND_SHARED_HOST_RUNBOOK.md` (sections 1-4 and 7) to the pilot overlay; where it differs, the difference is named.
The Turkish copy-paste checklist of the Product Owner's remaining steps (10 if not yet done, 11 with its one-line check,
14 (the admin UI, with the probe's pseudonym), 15-17, the one-step undo, and what to tell the orchestrator after each) is `PILOT_ADIMLAR.md`; step numbers match.

**Scope.** The corporate web proxy (Broadcom ProxySG, SGOS 7.4.15.x, three appliances, PHASE0_PROXYSG_RECORD F-1)
sends the AI-category requests of **one test user** to the ICAP engine over **plain ICAP on 1344** (decision Q-28,
exception H-2: at most 30 days, REQMOD fail-closed). The pilot uses `deploy/rwsafe/overlays/pilot`: no directory
(break-glass sign-in only), no SIEM, no capture, no group claims, no Ingress (admin UI by `kubectl port-forward`), the
committed policy seed (TCKN redact, secrets block, enforce). neXus is not touched: no neXus object, namespace,
Ingress, registry repository or firewall table is read or changed.

**Placeholders.** Never write a real value into this file, a commit, a chat or a ticket: `<node-address>` (HOST-A's
address), `<proxysg-address-1>` ... `<proxysg-address-3>`, `<DOMAIN>\<test-user>`, `<AI category>` (the vendor's
category name as shown in the console), `<admin-user>` (your SSH account). Real values exist only on the host, in
the proxy console and in `~/.config/<product>/`.

**Product name.** Every name below that carries the product comes from `deploy/rwsafe/product.env` (`PRODUCT=rwsafe`
today; PO decision 2026-10-31: renameable from one place). Commands use `${PRODUCT}`; `tools/pilot/render.py` renames
the committed manifests, and `tools/deploy/manifest_check.py --product` proves that nothing rendered still carries
another name or any neXus name (`ui2*`, `nexus*`), and that no node port collides with one in use (Traefik's 80/443).

## 0. Rules for every step

**Who runs a step** (`docs/design/PO_DECISION_RECORD_2026_10_31_AGENT_APPLIES_PILOT.md`, Q-45, RATIFIED; it amends
`DEPLOY_AND_SHARED_HOST_RUNBOOK.md` §7 for the pilot):

- Steps marked **HOST CHANGE** may be run by the Product Owner **or** by the orchestrating agent (never a worker), only
  inside the product's own namespaces and the product's own cluster-scoped objects. Before each one the agent states the
  step in one line in chat and waits for the PO's confirmation of that step; it never runs two host changes on one
  confirmation, and a deletion (step 18) is asked separately, object group by object group.
- Every `kubectl` runs as the host user with the user's own kubeconfig, **never through `sudo`** (AGENTS.md section 8,
  Q-45 point 3); the tools/pilot scripts refuse a `KUBECTL` that runs sudo.
- **PO only:** step 10 (the break-glass password: the orchestrating agent never runs it and never reads its file; the
  script refuses to run without an interactive terminal), step 11 (the host firewall, root), and the proxy console steps
  15-17 (Q-20).
- Read-only steps (marked READ) may be run by either without a confirmation.

**Masking.** When the agent runs a step, every output passes through `tools/hosta/mask.sh` (append
`2>&1 | sh tools/hosta/mask.sh`); the tools/pilot scripts mask their own output. The agent never reads a raw build log:
it reads the Job's condition and the error classes only (step 5). Nobody pastes a raw build log, address, user name or
proxy policy text into chat.

**Shared-host rules (DEPLOY_AND_SHARED_HOST_RUNBOOK §3).** Before steps 2-12: take the lock `~/.locks/hosta-build.lock`
(`flock`), stay out of 00:00-00:20, 06:00-06:20, 12:00-12:20, 18:00-18:20 and 02:00-02:59 Europe/Istanbul, and check
that the root filesystem is below 85 % used (`df -h /`; 69 % on 2026-10-31, HOSTA_MEASUREMENT_2026_10_31.md).

**The host changes, in order** (each confirmed on its own):

| # | Step | What changes | Undo |
|---|---|---|---|
| H1 | 2 | namespaces `${PRODUCT}`, `${PRODUCT}-build`, `${PRODUCT}-security`; PriorityClasses `${PRODUCT}-dataplane`, `-control`, `-batch`; three ResourceQuotas and LimitRanges | step 18 |
| H2 | 3 | three ConfigMaps in `${PRODUCT}-build` (build tag, CA bundle, proxy settings without credentials) | deleted with the namespace |
| H3 | 4 | build context PVC (1Gi) and a short-lived loader pod in `${PRODUCT}-build` | deleted with the namespace |
| H3b | 4b | the pinned base images pushed into the in-cluster registry as repositories `${PRODUCT}-mirror/ubi9/*` (from the workstation export; digests verified) | step 18 note |
| H4 | 5 | the data plane image built and pushed to the in-cluster registry as repository `${PRODUCT}-dataplane` | step 18 note |
| H5 | 6 | the control image, repository `${PRODUCT}-control` | step 18 note |
| H6 | 7 | four Secrets/ConfigMaps of generated values plus the estate dictionary ConfigMap in `${PRODUCT}` | deleted with the namespace |
| (PO) | 10 | **PO only**: the break-glass password copied to a file in the PO's home; the copy in the pod's PVC removed | step 18 |
| H7 | 9 | database, control plane and their Services, PVCs and NetworkPolicies in `${PRODUCT}` | step 18 |
| H9a | 9b | the ICAP engine (2 pods), its ClusterIP Service and the synthetic probe CronJob `${PRODUCT}-icap-probe` (every 15 minutes, in-cluster only); **nothing on the node's 1344** | step 18 |
| H8 | 11 | **root, PO only**: a separate nftables table `<product>_pilot` (hyphens as underscores) that drops new TCP 1344 connections **to the node's own addresses** from every source except the ProxySG appliances (pod-to-pod and ServiceLB traffic untouched; neXus's own table is not touched) | `sudo nft delete table inet <product>_pilot` |
| H8b | 11.3 | one probe Job created from the CronJob by `tools/pilot/verify_firewall.sh` (removed by its TTL after a day); `--latest` instead changes nothing | the TTL |
| H9 | 12 | the ServiceLB Service that opens **1344 on the node** (no node-port range port: `allocateLoadBalancerNodePorts: false`, externalTrafficPolicy Cluster) | step 18 |
| P1 | 15 | **proxy**: a new ICAP service pointing at `<node-address>:1344` | delete the service |
| P2 | 16 | **proxy**: one policy rule sending only the test user's AI-category requests to it, fail-closed | step 17.6, one step |

## 1. Prepare the checkout and the variables (READ)

On HOST-A, in the checkout of the merged `main` (`~/rwsafe` in `.rwsafe-delivery.json`), at the commit to pilot. When the
host cannot reach GitHub (2026-10-31), the orchestrator copies `git archive origin/main` into `~/rwsafe` over SSH and
writes the full commit id to `~/rwsafe/.pilot-commit`; there is then no `.git`, and the steps below use the copy as is
(`build_config.sh` reads the tag from `.pilot-commit`; step 4 uses `tar` instead of `git archive`).

```bash
cd ~/rwsafe && git fetch -q && git checkout --detach origin/main && git log --oneline -1
export PRODUCT="$(sed -n 's/^PRODUCT=//p' deploy/rwsafe/product.env)"; echo "product ${PRODUCT}"
mkdir -p ~/pilot && chmod 0700 ~/pilot
kubectl version --client | head -1; python3 --version; openssl version
# nothing of the product exists yet; 1344 is free on the node
kubectl get namespace "${PRODUCT}" "${PRODUCT}-build" "${PRODUCT}-security" 2>&1 | grep -c NotFound
kubectl get priorityclass "${PRODUCT}-dataplane" "${PRODUCT}-control" "${PRODUCT}-batch" 2>&1 | grep -c NotFound
ss -ltn 'sport = :1344' | tail -n +2 | wc -l
# the local checks: the manifest rules, the render, the pilot overlay
python3 -B tools/deploy/test_manifest_check.py 2>&1 | tail -1
python3 -B tools/pilot/test_render.py 2>&1 | tail -1
python3 -B tools/deploy/manifest_check.py --overlay deploy/rwsafe/overlays/pilot --product "${PRODUCT}" | tail -1
```

Expected: `product rwsafe` (or the chosen name); `3`, `3`, `0`; OpenSSL 3.x; `OK`, `OK`; `manifest check PASS ...` (two
notes about the placeholder digests, which steps 5-6 replace). `kubectl` is the host user's own (the masked inventory
showed the user lists nodes and reads the cluster without root); never prefix it with `sudo`.

## 2. HOST CHANGE H1: namespaces and isolation objects

```bash
python3 -B tools/pilot/render.py --product "${PRODUCT}" \
  --kinds Namespace,PriorityClass,ResourceQuota,LimitRange --output ~/pilot/isolation.json
kubectl diff --server-side -f ~/pilot/isolation.json | grep -c '^+++ '
kubectl apply --server-side -f ~/pilot/isolation.json
kubectl get namespace -l "app.kubernetes.io/part-of=${PRODUCT}" --no-headers | wc -l
```

Expected: `render: ... 12 objects (3 LimitRange, 3 Namespace, 3 PriorityClass, 3 ResourceQuota)`; 12 objects shown by
the diff; 12 `serverside-applied` lines; `3` namespaces. PSA: `${PRODUCT}` and `${PRODUCT}-security` enforce
`restricted`, `${PRODUCT}-build` `baseline` (kaniko, PLAT-F6).

## 3. HOST CHANGE H2: the build's ConfigMaps

The tag is the commit id. The CA bundle is the host's own system bundle (public CA material; it contains the corporate
CA when the host trusts the TLS-intercepting proxy). The proxy settings are the ones the host's k3s service already uses
(HARDENING_EXCEPTIONS: "the k3s service environment carries the corporate proxy variables"); the PO writes them once
into `~/.config/${PRODUCT}/build-proxy.env` (mode 0600; never printed) as four lines `HTTP_PROXY=http://<proxy>:<port>`,
`HTTPS_PROXY=...`, `NO_PROXY=...` (must hold `.svc,.cluster.local,registry.kube-system.svc.cluster.local`) and
`GRADLE_OPTS=-Dhttps.proxyHost=<proxy> -Dhttps.proxyPort=<port> -Dhttp.proxyHost=<proxy> -Dhttp.proxyPort=<port>
-Dhttp.nonProxyHosts=*.svc|*.cluster.local`. **Never credentials**: no `user:password@` in a URL, no `proxyUser` or
`proxyPassword`; the script refuses them (PR 33 review D-03). On a network without a proxy the four keys are present and
empty. The proxy reaches kaniko's own pulls from its environment and the Containerfiles' build stage only as build
arguments (`ARG`, never `ENV`, none in the runtime stage), so no proxy setting is in a layer or the history of an image.

```bash
tools/pilot/build_config.sh --check
tools/pilot/build_config.sh
```

Expected: `proxy settings: valid (values not shown)`, `check passed ...`; then the same check line and `stored configmap
${PRODUCT}-build-config (image-tag <12 hex>)`, `stored configmap ${PRODUCT}-build-ca`, `stored configmap
${PRODUCT}-build-proxy (values not shown)`. A refusal names the rule and the key only (`refused: HTTP_PROXY carries
credentials (userinfo)`), never a value; every kubectl output is discarded. Re-run it for a build of another commit (it
updates the tag).

## 4. HOST CHANGE H3: the build context

```bash
python3 -B tools/pilot/render.py --target build --product "${PRODUCT}" --output ~/pilot/build.json
kubectl apply --server-side -f ~/pilot/build.json -l "app.kubernetes.io/name in (${PRODUCT}-build-context,${PRODUCT}-build-context-loader)"
kubectl -n "${PRODUCT}-build" wait --for=condition=Ready "pod/${PRODUCT}-build-context-loader" --timeout=180s
# java/, the admin UI's sources (frontend/: the control image builds them, npm ci from the committed lockfile) and
# deploy/images/; a copy without .git leaves out the local node_modules/ and dist/
{ git archive --format=tar HEAD java frontend deploy/images 2>/dev/null \
    || tar -cf - --exclude=node_modules --exclude=dist java frontend deploy/images; } \
  | kubectl -n "${PRODUCT}-build" exec -i "${PRODUCT}-build-context-loader" -- \
      sh -c 'rm -rf /workspace/src && mkdir /workspace/src && tar -xf - -C /workspace/src --no-same-owner'
# the CA bundle for Gradle inside the build stage (deploy/images/ca/, git-ignored): the same host bundle
kubectl -n "${PRODUCT}-build" exec -i "${PRODUCT}-build-context-loader" -- \
  sh -c 'cat > /workspace/src/deploy/images/ca/host-bundle.pem' < /etc/ssl/certs/ca-certificates.crt
# the pinned Gradle distribution (the host cannot follow services.gradle.org's redirect, 2026-10-31): fetched on the
# workstation, its SHA-256 compared with distributionSha256Sum in java/gradle/wrapper/gradle-wrapper.properties, copied to
# the host as ~/pilot/gradle-8.14.3-bin.zip; the wrapper checks the sum again inside the build
sum="$(sed -n 's/^distributionSha256Sum=//p' java/gradle/wrapper/gradle-wrapper.properties)"
echo "${sum}  ${HOME}/pilot/gradle-8.14.3-bin.zip" | sha256sum -c --quiet && echo "gradle distribution: sum ok"
kubectl -n "${PRODUCT}-build" exec -i "${PRODUCT}-build-context-loader" -- \
  sh -c 'cat > /workspace/src/deploy/images/gradle-dist/gradle-8.14.3-bin.zip' < ~/pilot/gradle-8.14.3-bin.zip
kubectl -n "${PRODUCT}-build" exec "${PRODUCT}-build-context-loader" -- \
  sh -c 'ls /workspace/src/java/gradlew /workspace/src/frontend/package-lock.json /workspace/src/deploy/images/dataplane.Containerfile /workspace/src/deploy/images/ca/host-bundle.pem /workspace/src/deploy/images/gradle-dist/gradle-8.14.3-bin.zip | wc -l'
kubectl -n "${PRODUCT}-build" delete pod "${PRODUCT}-build-context-loader" --wait=true
```

Expected: `render: target build, ... 4 objects (2 Job, 1 PersistentVolumeClaim, 1 Pod)`; the PVC and the pod applied;
`condition met`; `5` (the Gradle wrapper, the UI's lockfile, a Containerfile, the CA bundle, the Gradle distribution);
the pod deleted (the build quota holds one 3-CPU build and nothing else, so the loader must be
gone before step 5).

## 4b. HOST CHANGE H3b: mirror the pinned base images (orchestrator workstation, then the host)

The pilot host cannot pull from registry.access.redhat.com (the corporate network refuses the connection, 2026-10-31;
kaniko failed with `x509` / connect errors), and HOST-A's sshd allows no port forwarding. The workstation exports the
pinned images (the linux/amd64 manifests the Containerfiles pin, their configs and layers; every digest verified) to a
directory, the directory is copied to the host, and the host pushes it into the in-cluster registry under
`${PRODUCT}-mirror/` through a short-lived loopback port-forward, verifying every digest again. The build Jobs read the
mirror through `--registry-map=registry.access.redhat.com=<in-cluster registry>/${PRODUCT}-mirror` (the build check
allows no other mapping, and no split form).

```bash
# workstation
SSL_CERT_FILE=/etc/ssl/cert.pem python3 -I tools/pilot/mirror_images.py --export "${work}/mirror" --product "${PRODUCT}"
tar -C "${work}" -cf - mirror | ssh <host> 'rm -rf ~/pilot/mirror && tar -x -C ~/pilot'
# host: a loopback-only port-forward that ends by itself, the import, then the forward and the copy are removed
(timeout 600 kubectl -n kube-system port-forward --address 127.0.0.1 svc/registry 15007:80 >/dev/null 2>&1 &)
python3 -I tools/pilot/mirror_images.py --import ~/pilot/mirror --dest http://127.0.0.1:15007
pkill -u "$(id -u)" -f 'port-forward --address 127.0.0.1 svc/registry 15007:80'; rm -rf ~/pilot/mirror
```

Expected: one `pushed ${PRODUCT}-mirror/...` line per manifest and `import done`. Three images: `ubi9/openjdk-21`,
`ubi9/openjdk-21-runtime` and `ubi9/nodejs-22` (the control image's admin UI build stage, about 240 MB compressed); a
mirror made before the UI stage existed lacks the last one, so re-run this step once.

## 5. HOST CHANGE H4: build the data plane image

```bash
kubectl apply --server-side -f ~/pilot/build.json -l "app.kubernetes.io/name=${PRODUCT}-build-dataplane"
kubectl -n "${PRODUCT}-build" wait --for=condition=complete "job/${PRODUCT}-build-dataplane" --timeout=45m
kubectl -n "${PRODUCT}-build" get pod -l "job-name=${PRODUCT}-build-dataplane" \
  -o jsonpath='{.items[0].status.containerStatuses[0].state.terminated.message}' > ~/pilot/dataplane.digest
grep -cE '^sha256:[0-9a-f]{64}$' ~/pilot/dataplane.digest
```

Expected: `job.batch/...-build-dataplane serverside-applied`; `condition met` (typically 5-15 minutes: Gradle resolves
and verifies every dependency); `1`. If it fails, the error class (the agent reads only this; a raw build log can name
the proxy or other estate hosts, which mask.sh does not cover):

```bash
kubectl -n "${PRODUCT}-build" logs "job/${PRODUCT}-build-dataplane" --tail=200 2>&1 \
  | grep -oiE 'x509|certificate|proxy|timed out|connection refused|verification failed|no space left' | sort | uniq -c
```

`x509`/`certificate`: the CA bundle (steps 3, 4); `proxy`/`timed out`/`connection refused`: the proxy settings (step 3);
`verification failed`: a code problem (stop and report); `no space left`: the node's disk. The PO may read the full log
himself. To retry: `kubectl -n "${PRODUCT}-build" delete job "${PRODUCT}-build-dataplane"` (a deletion: confirmed on
its own), then this step again.

## 6. HOST CHANGE H5: build the control image

```bash
kubectl apply --server-side -f ~/pilot/build.json -l "app.kubernetes.io/name=${PRODUCT}-build-control"
kubectl -n "${PRODUCT}-build" wait --for=condition=complete "job/${PRODUCT}-build-control" --timeout=45m
kubectl -n "${PRODUCT}-build" get pod -l "job-name=${PRODUCT}-build-control" \
  -o jsonpath='{.items[0].status.containerStatuses[0].state.terminated.message}' > ~/pilot/control.digest
grep -cE '^sha256:[0-9a-f]{64}$' ~/pilot/control.digest
```

Expected as in step 5. The digests are not secret (they name image content); they are the only input the render needs.
The control build first builds the admin UI: `npm ci` fetches the committed lockfile's packages from registry.npmjs.org
through the same proxy and CA bundle (each package checked against the lockfile's integrity hash, no install script
run), then `npm run build`. In the error-class grep above, use `job/${PRODUCT}-build-control`; an npm failure also
shows as `npm error` (count it with `grep -c 'npm error'`): `x509`/`certificate` again means the CA bundle,
`EINTEGRITY` a lockfile or registry problem (stop and report).

## 7. HOST CHANGE H6: Secrets and uncommitted ConfigMaps

```bash
tools/pilot/bootstrap_secrets.sh --plan
tools/pilot/bootstrap_secrets.sh
```

Expected: the plan lists 5 objects to create and changes nothing; then `created secret ${PRODUCT}-snapshot-signing-key`,
`created configmap ${PRODUCT}-snapshot-public-keys`, `created secret ${PRODUCT}-privacy-hmac-key`, `created secret
${PRODUCT}-db-credentials`, `created configmap ${PRODUCT}-estate`, `done: 5 created, 0 existing; no value was printed`.
Run again, it creates nothing (idempotent). It never prints a value: everything is generated in a `mktemp -d`
directory, passed as files and shredded.

The estate dictionary holds one synthetic placeholder term, because an empty one is refused by design (masked views
answer 503). The pilot's checks do not use the masked role; before anyone does, replace it with the estate's real terms
(one per line, kept in `~/.config/${PRODUCT}/estate-dictionary.txt`, never in the repository), then delete the control
plane pod so it reads the file again:

```bash
kubectl -n "${PRODUCT}" create configmap "${PRODUCT}-estate" \
  --from-file=estate-dictionary.txt="${HOME}/.config/${PRODUCT}/estate-dictionary.txt" --dry-run=client -o yaml \
  | kubectl replace -f - >/dev/null && echo "estate dictionary replaced"
kubectl -n "${PRODUCT}" delete pod -l "app.kubernetes.io/name=${PRODUCT}-control"
```

Never delete and recreate `${PRODUCT}-db-credentials` while the database PVC exists: the database takes its role
passwords only at its first initialisation.

## 8. Render and check the workloads (READ)

```bash
python3 -B tools/pilot/render.py --product "${PRODUCT}" \
  --dataplane-digest "$(cat ~/pilot/dataplane.digest)" --control-digest "$(cat ~/pilot/control.digest)" \
  --output ~/pilot/app.json
python3 -B tools/deploy/manifest_check.py --rendered ~/pilot/app.json --release --product "${PRODUCT}" | tail -1
kubectl diff --server-side -f ~/pilot/app.json | grep -c '^+++ '
```

Expected: `render: target pilot, product ..., 41 objects (...)`; `manifest check PASS: 41 objects, 4 workloads, 0
failure(s); product ...` (the fourth workload is the synthetic probe's CronJob, inside the quota); the diff shows the new objects (the 12 isolation objects are unchanged). The rendered file
holds no Secret, no estate value and no address (the pilot has no directory or SIEM CIDR to patch in), so it may stay on
disk in `~/pilot/`.

## 9. HOST CHANGE H7: database and control plane

Everything except the ICAP steps' objects (the ICAP Deployment, ConfigMap, ServiceAccount, Services, PDB and
NetworkPolicies, the synthetic probe, and every LoadBalancer Service): the ServiceLB Service would open 1344 on the node,
which waits for the firewall rule of step 11. The split is made by the render (`--phase control`, then `icap` in step
9b and `servicelb` in step 12; PR 33 review D-05), not by a label selector, and `tools/pilot/test_render.py` proves that
the three phases are disjoint, together are the whole render, and that only `servicelb` holds a LoadBalancer Service.

```bash
python3 -B tools/pilot/render.py --product "${PRODUCT}" --phase control \
  --dataplane-digest "$(cat ~/pilot/dataplane.digest)" --control-digest "$(cat ~/pilot/control.digest)" \
  --output ~/pilot/app-control.json
kubectl apply --server-side -f ~/pilot/app-control.json
kubectl -n "${PRODUCT}" rollout status "statefulset/${PRODUCT}-db" --timeout=10m
kubectl -n "${PRODUCT}" rollout status "deploy/${PRODUCT}-control" --timeout=10m
kubectl -n "${PRODUCT}" get service --no-headers | awk '{print $2}' | sort | uniq -c
```

Expected: the objects applied; both rollouts `successfully rolled out` (the first control plane start runs the Flyway
migrations, seeds the policy registry and creates the break-glass account); `2 ClusterIP` (database and control
plane; no LoadBalancer yet). If the control plane does not become ready: `kubectl -n "${PRODUCT}" logs
"deploy/${PRODUCT}-control" --tail=40 | sh tools/hosta/mask.sh` (no log line carries a secret or a prompt, AGENTS.md
4.14). UNVERIFIED (2026-10-31) on the pinned database digest: the start script creates both roles (runbook §4).

## 9b. HOST CHANGE H9a: the ICAP engine and the synthetic probe (in-cluster only)

The ICAP engine, its ClusterIP Service `${PRODUCT}-icap` (1344, cluster-internal) and the synthetic probe; no
LoadBalancer Service, so nothing answers on the node's 1344 yet. May run before or after step 11.

```bash
python3 -B tools/pilot/render.py --product "${PRODUCT}" --phase icap \
  --dataplane-digest "$(cat ~/pilot/dataplane.digest)" --control-digest "$(cat ~/pilot/control.digest)" \
  --output ~/pilot/app-icap.json
kubectl apply --server-side -f ~/pilot/app-icap.json
kubectl -n "${PRODUCT}" rollout status "deploy/${PRODUCT}-icap" --timeout=10m
kubectl -n "${PRODUCT}" get service -o jsonpath='{range .items[*]}{.spec.type}{"\n"}{end}' | sort | uniq -c
kubectl -n "${PRODUCT}" get cronjob "${PRODUCT}-icap-probe" --no-headers | wc -l
```

Expected: `render: ... 11 objects (1 ConfigMap, 1 CronJob, 1 Deployment, 4 NetworkPolicy, 1 PodDisruptionBudget, 1
Service, 2 ServiceAccount)` and the objects applied; `successfully rolled out` (the two ICAP pods are ready
only once they hold the signed policy snapshot from the control plane: fail closed; the PDB keeps one of them through
any eviction); `3 ClusterIP`; `1`.

### The synthetic probe

`${PRODUCT}-icap-probe` (`deploy/rwsafe/overlays/pilot/60-icap-probe.yaml`) runs every 15 minutes (`*/15`, concurrency
Forbid, one attempt, 120 s deadline, history 1 succeeded and 3 failed Jobs) from the **data plane image** with another
main class (`io.rwsafe.dataplane.boot.IcapProbe`; no other image is pulled). It sends ICAP OPTIONS and the six synthetic
REQMOD scenarios of `tools/icap/replay.py` to `icap://${PRODUCT}-icap:1344` and **fails the Job** when an outcome differs
from the committed seed's: clean chat allow, TCKN redact, IBAN redact, cloud key block, key after the 4096-byte preview
block, clean prompt inside the preview allow. Every value is synthetic and built at runtime. Its NetworkPolicy lets the
probe's pods reach only the ICAP pods on 1344 and the cluster DNS (to resolve the Service name); the ICAP pods admit only
the probe and the ICAP e2e Job on in-cluster 1344; the namespace's default deny stays.

Result (scenario, expected, actual, ICAP status; never a prompt, value or address), from the newest probe Job:

```bash
tools/pilot/verify_firewall.sh --latest 2>&1 | grep 'through svc'
kubectl -n "${PRODUCT}" get jobs -l "app.kubernetes.io/name=${PRODUCT}-icap-probe" --no-headers | awk '{print $2}' | sort | uniq -c
```

Probe events in the admin UI (step 14): every probe request carries the fixed synthetic identity `SYNTHETIC\icap-probe`
and the documentation-range client address `192.0.2.250`, so all its events sit under **one** `USR-...` pseudonym and
one masked subnet (the pseudonym is keyed by the estate's HMAC key, so it cannot be written down in advance). Find it
once: Traffic screen, window 1 hour, platform `gemini`, verdict `BLOCK`; the probe's cloud-key event appears there
within a minute after every :00, :15, :30 and :45, and its user column shows the probe's pseudonym. Put it in the user filter to see only the probe (six events per
run: two ALLOW, two REDACT, two BLOCK); the test user's own events are the ones under the other pseudonym. The probe's
events also count in `check_pilot.sh`'s events line (576 a day). To stop the probe, delete its CronJob (a deletion,
confirmed on its own); the next apply of this step brings it back.

## 10. PO ONLY: the break-glass password

The orchestrating agent never runs this step and never reads the file it writes (the PO's answer to the PR 33 review
question). The PO runs it in his own terminal; the script refuses to run without an interactive terminal.

```bash
tools/pilot/fetch_break_glass.sh
```

Expected: `written: ~/.config/${PRODUCT}/pilot/break-glass-initial-password (mode 0600) ...` and `removed the copy in
the control plane's PVC`. The control plane generated the password itself at its first start (the code's rule:
generated, BCrypt-hashed, written once owner-only to its PVC `${PRODUCT}-control-identity`), so no script chooses it;
this one copies it through a pipe into an owner-only file (both directories 0700), never prints it, and then removes the
copy in the PVC, so exactly one copy is left. The account name is `breakglass`. Read the file in your own
terminal; never paste it anywhere. Reset, if the file is ever lost after the account exists: the pilot holds no data
worth keeping, so step 18 and a fresh install is the reset (a password-reset command does not exist yet).

## 11. HOST CHANGE H8 (root, the PO only): host firewall for 1344

ServiceLB answers on the node's 1344 for every source, and plain ICAP has no peer authentication, so the ProxySG
allowlist (H-1) must be in place before step 12. The rule lives in its **own** nftables table; neXus's table
`inet nexus_host` is neither read nor changed. Fill the three addresses on the host only; nothing else in the block is
edited. The block derives the product name itself from `~/rwsafe/deploy/rwsafe/product.env` and runs in a subshell
with `set -euo pipefail` (PR 40 review D-04): it refuses to run when `~/rwsafe` or the name is missing or the name is not
a product name (an empty name would otherwise create a table `inet _pilot`), and stops at the first failing command
without closing the PO's terminal.

```bash
(
set -euo pipefail
cd ~/rwsafe
PRODUCT="$(sed -n 's/^PRODUCT=//p' deploy/rwsafe/product.env)"
case "${PRODUCT}" in
  ""|*[!a-z0-9-]*) echo "stopped: no valid PRODUCT in ~/rwsafe/deploy/rwsafe/product.env"; exit 1 ;;
esac
T="${PRODUCT//-/_}_pilot"   # nftables names take no hyphen: rwsafe_pilot
sudo nft -f - <<EOF
table inet ${T} {}
flush table inet ${T}
table inet ${T} {
  set icap_clients {
    type ipv4_addr
    flags interval
    elements = { <proxysg-address-1>, <proxysg-address-2>, <proxysg-address-3> }
  }
  chain prerouting {
    type filter hook prerouting priority -150; policy accept;
    fib daddr type local tcp dport 1344 ct state new ip saddr != @icap_clients drop
    fib daddr type local meta nfproto ipv6 tcp dport 1344 drop
  }
}
EOF
echo "table ${T} written"
)
```

The one-line check (read only; it derives the name the same way and may be run again at any time):

```bash
(set -euo pipefail; cd ~/rwsafe; P="$(sed -n 's/^PRODUCT=//p' deploy/rwsafe/product.env)"; test -n "${P}"; sudo nft -j list table inet "${P//-/_}_pilot" | tools/pilot/verify_firewall.sh --table)
```

Expected: `table rwsafe_pilot written` from the block; then from the check (counts only, never an address):

```text
firewall table check, product rwsafe
objects        ok   0 object(s) of another kind than table, set, chain, rule
table          ok   inet rwsafe_pilot: 1 table(s) in the input, exactly 1 expected
set            ok   icap_clients: 1 set(s), 3 element(s), all single addresses (values not shown; exactly 3 single IPv4 addresses expected)
chain          ok   1 chain(s); exactly 1 expected: prerouting, type filter, hook prerouting, priority -150, policy accept
rules          ok   2 rule(s); exactly 2 expected, each equal to step 11 in every field and operator: IPv4 1, IPv6 1, other 0
result: PASS
```

Running the block again replaces the table's content (the empty `table` line and `flush` make it idempotent; no
duplicate rules). The check passes only the exact table above (PR 40 review D-02): exactly three single IPv4 addresses
(no prefix or range), the one chain, and exactly the two rules with every field, expression and operator as written
(every match `==`, `ct state new` printed by nft as `in`; the only negation is the designed `ip saddr != @icap_clients`);
an extra object, chain, rule, expression or field fails, and so does a shape it does not recognise (UNVERIFIED
2026-10-31 on HOST-A's nft release; an `unrecognised nft JSON` or `other 1` line means: stop and report, never edit the
rule to fit). The PO tells the orchestrator only the `result:` line and the element count.

**11.3 (the orchestrator) Verify that pod traffic still flows and 1344 is still closed.** Right after the PO's check,
with the ICAP engine and the probe of step 9b in place:

```bash
tools/pilot/verify_firewall.sh            # creates one probe Job from the CronJob (H8b, confirmed on its own)
tools/pilot/verify_firewall.sh --latest   # alternative that changes nothing: the newest scheduled probe Job
```

Expected:

```text
firewall verification, product rwsafe
table          not read here (root only): the PO's one-line check of step 11 (--table) proves it
icap pods      ok   2/2 ready
through svc    ok   probe Job (now), Job Complete: PASS (7/7 as expected)
node 1344      ok   no LoadBalancer Service, no ServiceLB pod, no listening socket
node 1344      ok   a connection from this host to the node address on 1344 is refused (nothing serves it yet)
result: PASS
```

`through svc` is a pod reaching the ClusterIP Service on 1344 through the prerouting hook the rule sits on: if the rule
also matched pod or Service traffic (for example with Service addresses bound to a local interface), the probe fails
here, before any proxy traffic. Then the PO deletes the table (the undo below) and reports. `--latest` judges the newest
probe Job by creation time whatever its outcome (PR 40 review D-01): a Failed or unfinished newest Job is a FAIL, never
hidden by an older PASS; use it only when that Job was created after the PO's check (the line shows its time). Optional cross-check by the PO
from the workstation (not a ProxySG appliance): `nc -vz -w 3 <node-address> 1344` must **time out** (dropped by the
rule); "connection refused" means the rule does not match on this host: stop.

Why exactly this rule (PR 33 review D-01, P0):

- **Only traffic to the node's own addresses.** `fib daddr type local` matches a packet whose destination is an address
  of this host, that is a client reaching the ServiceLB hostPort on `<node-address>:1344`. Pod-to-pod traffic also
  passes the prerouting hook on k3s (bridged CNI traffic with bridge netfilter), including the ServiceLB pod's
  masqueraded forward to an ICAP pod on 1344 and the in-cluster e2e traffic; its destination is a pod or Service address,
  never a local one, so the rule never touches it. Without the `fib` match those packets (pod source, not in
  `@icap_clients`) would be dropped and ICAP would fail for everyone, the proxy included.
- **Before the DNAT.** Priority -150 runs before the hostPort DNAT (-100), so the destination is still the node's
  address and the port still 1344.
- **New connections only** (`ct state new`): an established ProxySG connection is never cut by a reload.
- **Not the host's own traffic**: packets the host sends itself (the OPTIONS line of `check_pilot.sh`) take the output
  path, not prerouting.

The rule is not persistent: **after a host reboot run this step again before the proxy sends traffic** (until then:
`kubectl -n "${PRODUCT}" scale deploy "${PRODUCT}-icap" --replicas=0`, and the proxy denies the test user's AI requests,
fail-closed). UNVERIFIED (2026-10-31) on HOST-A's kernel and k3s release, proved by step 11.3 and step 13 in both
directions. Undo (the PO; it derives the name the same way):
`(set -euo pipefail; cd ~/rwsafe; P="$(sed -n 's/^PRODUCT=//p' deploy/rwsafe/product.env)"; test -n "${P}"; sudo nft delete table inet "${P//-/_}_pilot")`.

## 12. HOST CHANGE H9: the ServiceLB Service (opens 1344 on the node)

Only after step 11's `result: PASS` and step 11.3's `result: PASS`.

```bash
python3 -B tools/pilot/render.py --product "${PRODUCT}" --phase servicelb \
  --dataplane-digest "$(cat ~/pilot/dataplane.digest)" --control-digest "$(cat ~/pilot/control.digest)" \
  --output ~/pilot/app-servicelb.json
kubectl apply --server-side -f ~/pilot/app-servicelb.json
kubectl -n kube-system get pods -l "svccontroller.k3s.cattle.io/svcname=${PRODUCT}-icap-lb" --no-headers | grep -c Running
```

Expected: `render: ... 1 objects (1 Service)`; `service/${PRODUCT}-icap-lb serverside-applied`; `1` (the ServiceLB
pod). `kubectl apply --server-side -f ~/pilot/app.json` (step 8) is the same end state: every earlier object unchanged.

## 13. Pilot check (READ)

```bash
tools/pilot/check_pilot.sh
```

Expected (counts only; no address or name):

```text
pilot check, product rwsafe
pods           ok   db: 1/1 ready
pods           ok   control: 1/1 ready
pods           ok   icap: 2/2 ready
control        ok   /readyz 200
icap pod 1     ok   /ready 200, snapshot version 1, transactions 12, queue 0, dropped 0, spool bytes 0
icap pod 2     ok   /ready 200, snapshot version 1, transactions 12, queue 0, dropped 0, spool bytes 0
(the snapshot version may be any number above 0; the transactions are the synthetic probe's, split between the pods)
servicelb      ok   1 node address(es) assigned, 1 ServiceLB pod(s) ready
icap options   ok   status 200, Methods REQMOD, Preview 4096, Allow 204
events         24 in the last 24 hours: ALLOW 8; BLOCK 8; REDACT 8;
result: PASS
```

The counts are an example: before the first proxied request every event is the probe's, six per run (two each ALLOW,
REDACT and BLOCK), so they grow by six every 15 minutes; the Traffic screen separates them by the probe's pseudonym
(step 9b, "The synthetic probe").

Then prove the firewall of step 11 in both directions (PR 33 review D-01):

1. **Blocked for others.** From a machine that is **not** a ProxySG appliance (your workstation):
   `nc -vz -w 3 <node-address> 1344` must **time out** (dropped by the `fib daddr type local` rule; a "connection
   refused" or "succeeded" means the rule does not match on this host: stop and tell the PO).
2. **Pod traffic untouched.** Step 11.3's `through svc` line passed, the probe keeps passing every 15 minutes
   (`tools/pilot/verify_firewall.sh --latest`), the `icap pod` lines above count `/ready 200`, and after step 15 the
   proxy's health check is healthy: the ProxySG reaches the engine only through the ServiceLB pod's forward to an ICAP pod on 1344, a
   pod-to-pod packet through the same prerouting hook. If the proxy's health check fails while the ICAP pods are ready,
   delete the table (the undo of step 11) and report: the rule caught pod traffic.

The ICAP OPTIONS line above is sent from the host itself, which the prerouting rule does not filter. UNVERIFIED (2026-10-31): the database pod's local `psql` access the events line uses;
if that line says the query failed, the transactions counts of the ICAP pods and the Traffic screen (step 14) are the
evidence instead.

## 14. The admin UI (READ; a port-forward on the host)

On HOST-A (leave it running):

```bash
kubectl -n "${PRODUCT}" port-forward "svc/${PRODUCT}-control" 18080:8080 --address 127.0.0.1
```

On your workstation: `ssh -N -L 18080:127.0.0.1:18080 <admin-user>@<node-address>`, then open `http://localhost:18080`
and sign in as `breakglass` with the password from step 10. Step 4b records that HOST-A's sshd allows no port
forwarding: if this `ssh -L` answers `administratively prohibited` (or the page does not load), stop and report; the way
to reach the forward is a PO decision (for example forwarding allowed for the admin account, or a browser on a machine
that holds the cluster's kubeconfig), never a relay improvised on the host (AGENTS.md section 8: HOST-A is never a jump
server).

What answers on 8080 (and only there; 8091, 8092 and 9400 answer 404 for every UI path): the admin UI built into the
control image (`/app/ui`, the `ui` stage of `deploy/images/control.Containerfile`). `GET /` and every client route
(`/traffic`, `/policies`, `/health`, ...) answer the SPA's `index.html` (`Cache-Control: no-store`); `/assets/*` are the
content-hashed bundles (cached for a year); the UI calls the API same-origin under `/api`, so the session and CSRF
cookies travel through the forward unchanged. Every response carries the CSP (`default-src 'self'`, `script-src 'self'`,
`frame-ancestors 'none'`), `nosniff`, `Referrer-Policy: no-referrer` and `X-Frame-Options: DENY`. A `GET /` that answers
the JSON `{"reason":"NOT_FOUND",...}` means the image has no UI: the control image was built from a commit before the UI
stage (rebuild it, step 6).

Check: the Policies screen lists the seeded rules (SECRET BLOCK; TCKN, TR_IBAN, PAYMENT_CARD REDACT; mode enforce),
Health shows the database, the snapshot feed and ingestion UP.

Cookies: the session cookie is `__Host-rwsafe-session` and both it and the CSRF cookie are `Secure`
(`RWSAFE_COOKIE_SECURE=true`, the only deploy setting). Chromium browsers (Chrome, Edge) and Firefox treat
`http://localhost` as a secure context and keep `Secure` and `__Host-` cookies there; Safari does not (UNVERIFIED
2026-10-31 for the PO's browser and version; signing in once verifies it). Use `http://localhost:18080`, not
`http://127.0.0.1:18080` or the node address. If sign-in returns to the sign-in page in Chrome or Edge on
`http://localhost`, stop and report. A non-Secure setting exists for plain-http local runs only (LOCAL_RUN.md); the control
plane refuses to start when it is half-applied (`CookiePolicy`: `RWSAFE_COOKIE_SECURE=false` needs a session cookie name
without the `__Host-` prefix, and a Secure setting needs the `__Host-` name), and using it in the pilot would be a committed overlay change after a PO decision, never
`kubectl set env`.

## 15. PROXY CHANGE P1 (the PO, proxy console): the ICAP service

Menu paths and option names are **UNVERIFIED (2026-10-31)** for SGOS 7.4.15.x and Management Center 4.1.x; where a
screen differs, use the equivalent and note the difference. In Configuration > Content Analysis > ICAP > ICAP Services,
create a new service:

| Setting | Value |
|---|---|
| Name | `<product>-pilot-reqmod` (for example `rwsafe-pilot-reqmod`) |
| Service URL | `icap://<node-address>:1344/reqmod-ai` |
| Method | request modification (REQMOD) only |
| Secure ICAP | off (plain ICAP, H-2; the 30-day clock starts with the first proxied request: record the date) |
| Preview | enabled, **4096** bytes: what the engine's OPTIONS advertises (`Preview: 4096`, step 13); "Sense settings" reads it from the engine |
| Send | client address (X-Client-IP) and authenticated user (X-Authenticated-User, shape `DOMAIN\user`, F-3); not groups (group claims are off in the pilot) |
| Maximum number of connections | 20 is ample for one user (the engine advertises 1000) |
| Maximum object size | above 4 MiB (the engine's REQMOD body limit), with the error action **deny** above it (F-11) |
| Health check | on, every 5 s (runbook §1.2) |

Verify: the service's health check shows **healthy** (it sends OPTIONS to `/reqmod-ai`; the ICAP pods' OPTIONS answer
200 only while ready). Until step 16 no user's traffic is sent to it.

## 16. PROXY CHANGE P2 (the PO, proxy console): the test user's rule, fail-closed

Precondition: SSL interception covers the AI category for the test user (PHASE0 F-4 says it is partial today; without
interception the proxy cannot hand the request body to ICAP). In the Visual Policy Manager add **one** Web Access layer
named `<product> pilot`, holding one rule (UNVERIFIED 2026-10-31 for 7.4: the "Set ICAP Request Service" action in a Web
Access layer):

| Column | Value |
|---|---|
| Source | the user object `<DOMAIN>\<test-user>` only |
| Destination | the category `<AI category>` |
| Action | Set ICAP Request Service: `<product>-pilot-reqmod`, and **"Deny the client request"** when the service is unavailable or errors (fail-closed, H-2 / ADR-010) |
| Track | none |

The same rule in CPL, for comparison only (UNVERIFIED syntax):

```text
<Proxy>
  user="<DOMAIN>\<test-user>" category="<AI category>" request.icap_service(<product>-pilot-reqmod, fail_closed)
```

Install the policy (from Management Center to the appliances the test user goes through). Nobody else matches the
rule, so nobody else's traffic changes.

## 17. Verify on the proxy and the success criteria

1. **Proxy trace.** With a policy trace limited to the test user (or Policy > Policy Trace), one request of the test
   user to an AI site shows the ICAP request service `<product>-pilot-reqmod` applied; the ICAP statistics of the
   service count requests; a request of another user to the same site shows no ICAP service.
2. **TCKN masked on the way out.** Generate a synthetic Turkish ID with a valid checksum (never a real one, never
   committed): `python3 -B -c 'import random, sys; sys.path.insert(0, "tools/trial"); import trial_proxy as t; print(t.synthetic_tckn(random.SystemRandom()))'`.
   The test user sends a prompt that contains it to an AI site of the seed (for example `chatgpt.com` or `claude.ai`)
   and asks the assistant to repeat the number. **Pass:** the AI site received `[REDACTED:TCKN]` in its place (its answer
   and its own chat history show the token, not the number).
3. **Secret blocked with the Turkish page.** Generate a synthetic cloud key (never a real one):
   `python3 -B -c 'import random, sys; sys.path.insert(0, "tools/trial"); import trial_proxy as t; print(t.synthetic_cloud_key(random.SystemRandom()))'`.
   The test user sends a prompt that contains it. **Pass:** the browser shows the product's Turkish block page and the
   AI site never receives the request.
4. **Events in the admin UI.** In the Traffic screen (step 14): one `REDACT` and one `BLOCK` event, platform `openai` or
   `claude`, the user shown as a pseudonym `USR-...` (never the name). That pseudonym must be the test user's, **not**
   the probe's of step 9b (PR 40 review D-04): the probe also writes `claude` REDACT and `openai` BLOCK events every 15
   minutes, so filter the user column by the other pseudonym, or check the two events' time against the trial.
   `tools/pilot/check_pilot.sh` counts every event, the probe's included, in its `events` line.
5. **neXus untouched.** Every applied object is in `${PRODUCT}`, `${PRODUCT}-build` or `${PRODUCT}-security`, or is a
   PriorityClass named `${PRODUCT}-*` (`kubectl get priorityclass -l "app.kubernetes.io/part-of=${PRODUCT}" --no-headers
   | wc -l` says `3`); the only host change is the table `<product>_pilot`; neXus's UI works as before (open it as you
   normally do). The render check guarantees no rendered object names `ui2*` or `nexus*`.
6. **Rollback of the proxy side, in one step:** disable (or delete) the rule of step 16 and install the policy. The
   test user's AI traffic goes direct again. Do this first whenever anything looks wrong; while the rule is active and
   the engine is down, the test user's AI requests are denied (fail-closed by design).

Requests to AI-category hosts that are not in the seed's platform list are classified as platform `unknown`; how the
engine answers them follows ADR-010 and the frozen fail-closed flow. Record what the Traffic screen shows for them as a
pilot observation (counts, never URLs).

## 18. Rollback of the whole pilot

In this order; nothing of neXus is touched. Each numbered deletion is confirmed on its own (Q-45 point 2), and each
works whatever steps ran before (`--ignore-not-found`, no error on a missing file):

```bash
# 1. the proxy rule (step 17.6) and the ICAP service (step 15) are removed in the proxy console first (the PO)
# 2. everything in the product's namespaces (Deployments, StatefulSet, PVCs and their local-path directories, Secrets,
#    ConfigMaps, the ServiceLB Service, which closes 1344 on the node)
kubectl delete namespace "${PRODUCT}" "${PRODUCT}-build" "${PRODUCT}-security" --ignore-not-found=true --wait=true
# 3. the cluster-scoped PriorityClasses
kubectl delete priorityclass "${PRODUCT}-dataplane" "${PRODUCT}-control" "${PRODUCT}-batch" --ignore-not-found=true
# 4. root, the PO: the firewall table of step 11
sudo nft delete table inet "${PRODUCT//-/_}_pilot" 2>/dev/null || echo "no firewall table (already gone)"
# 5. local files: the rendered manifests and the digests; the PO also the break-glass password file
find ~/pilot -type f -exec shred -u {} + 2>/dev/null; rmdir ~/pilot 2>/dev/null
find "${HOME}/.config/${PRODUCT}/pilot" -type f -exec shred -u {} + 2>/dev/null; true
```

Expected: the namespaces gone (`kubectl get namespace -l "app.kubernetes.io/part-of=${PRODUCT}"` prints nothing), the
three PriorityClasses deleted, the table deleted, `ss -ltn 'sport = :1344'` shows nothing. What stays: the two image
repositories `${PRODUCT}-dataplane`, `${PRODUCT}-control` and `${PRODUCT}-mirror/ubi9/*` in the shared in-cluster registry (no registry content of
neXus is touched; they go with the registry GC of SHIP_PIPELINE_PLAN §4, or stay for the next attempt).

## 19. What the pilot does not cover

Secure ICAP (H-2 closes within 30 days: the TLS Secret and 11344 return with the k3s overlay), the directory sign-in,
SIEM export, redacted capture, group claims, RESPMOD, the in-cluster ICAP e2e and masked-role e2e Jobs of runbook §4
step 5 (not yet built; the synthetic probe of step 9b covers six REQMOD scenarios and OPTIONS, not the e2e suite), and
more than one user. Each is a later, separate change.
