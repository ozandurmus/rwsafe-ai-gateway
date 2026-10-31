<!-- Argon consultation 2026-10-31T16:15:42Z, model gemini-4-argon-high, effort high; unaltered output except 0 local paths masked (AGENTS.md 4.2) -->

Role: `REVIEWER`

### (1) CONSENT

| Area | Verdict |
|---|---|
| Shared-host Traefik route isolation (`deploy/rwsafe/overlays/pilot/70-admin-ingress.yaml`, `tools/deploy/manifest_check.py`) | **CONSENT**: Single `Host()` rule on class `traefik` with no `defaultBackend`, no host-less rule, and no Traefik CRD or default `TLSStore` modification; never shadows the other product's catch-all route for any other host. |
| Backend port confinement (`deploy/rwsafe/overlays/pilot/70-admin-ingress.yaml`, `deploy/rwsafe/overlays/k3s/04-networkpolicies-k3s.yaml`) | **CONSENT**: Only the control plane's admin port (`8080`) is exposed in the Ingress and admitted from `kube-system` Traefik pods by `rwsafe-control-from-traefik`; internal/metrics ports (`8091`, `8092`, `9400`) remain unexposed. |
| HTTPS-only Ingress & `Secure` `__Host-` cookies (`deploy/rwsafe/overlays/pilot/70-admin-ingress.yaml`, `java/control/src/main/java/io/rwsafe/control/identity/CookiePolicy.java`) | **CONSENT**: The Ingress requires a `tls` entry backed by `<product>-admin-tls` (verified against `deploy/rwsafe/contracts/runtime-contracts.json`), and `CookiePolicy` enforces `Secure` `__Host-` session and `Secure` CSRF cookies regardless of the internal HTTP hop. |
| CA and leaf key handling on disk, in terminal, and in cluster (`tools/pilot/admin_tls.sh`, `tools/pilot/test_admin_tls.py`) | **CONSENT**: Runs with `umask 077` as non-root; the CA key stays on the host (`0600` in a `0700` directory) and never enters the cluster, arguments, or terminal output; leaf key and CSR are created in a temporary directory and shredded via `EXIT` trap; named-curve EC P-256 (`prime256v1`) is enforced and tested. |
| Phased rendering and shared-host isolation (`tools/pilot/render.py`, `deploy/rwsafe/overlays/pilot/`) | **CONSENT**: `render.py` runs `manifest_check.check()` on the full overlay before phase selection; `control`, `icap`, `servicelb`, and `ingress` phases are disjoint and free of the other product's names. |
| Repository privacy gate scope (`tools/privacy/repository_privacy_check.py`, `tools/privacy/test_repository_privacy_check.py`) | **CONSENT**: `_SAFE_HOST_SUFFIXES` adds only the exact `.rwsafe.local` suffix; sibling `.local` names and suffixed domains still fire `INTERNAL_HOST_NAME` in the self-test. |

---

### (2) DISSENT

| Finding ID | File and Line or Symbol | What is Wrong | Severity | Concrete Correction |
|---|---|---|---|---|
| **D-01** | `tools/pilot/admin_tls.sh:122-126`, `tools/pilot/test_admin_tls.py:131-135` | `ca_ext` sets `nameConstraints = critical, permitted;DNS:${HOST}` without excluding IPv4/IPv6 subtrees and without constraining `extendedKeyUsage` on the CA certificate. Per RFC 5280 §4.2.1.10, name constraints apply per name form: with no `IP` constraint present, the CA can issue valid TLS server certificates for **any IPv4 or IPv6 address** (contradicting the claim that the CA can sign nothing else), and when imported into the Windows `Root` store via `certutil -addstore -f Root` (`docs/operations/PILOT_RUNBOOK.md:628`) without a CA-level EKU, it is not restricted to `serverAuth`. | **P1** | In `tools/pilot/admin_tls.sh` (`[ca_ext]`), add excluded all-address IPv4 and IPv6 subtrees to `nameConstraints` (`permitted;DNS:${HOST},excluded;IP:...,excluded;IP:...` for the full IPv4 `/0` and IPv6 `/0` ranges) and add `extendedKeyUsage = critical, serverAuth`. Assert both in `tools/pilot/test_admin_tls.py`. |
| **D-02** | `java/control/src/main/java/io/rwsafe/control/identity/LoginThrottle.java:53-57`, `LoginThrottle.java:64-88` (`failure`, `count`, `room`) | Two login-throttle bypasses at table capacity (`MAX_ENTRIES = 10_000`): (1) **Self-eviction at `MAX_ENTRIES - 1` live locks**: `count(pairKey)` sees `9,999 < 10,000` and inserts `pairKey` (`failures = 1`, unlocked), bringing size to `10,000`; immediately on line 56, `count(sourceKey)` calls `room(now)`, which runs `states.values().removeIf(s -> !s.locked(now))` and **deletes the unlocked `pairKey` just inserted**, then inserts `sourceKey` (`failures = 1`, unlocked). On the next attempt from the same client and login name, `count(pairKey)` evicts `sourceKey` and `count(sourceKey)` evicts `pairKey` again—resetting both counters to `1` forever without locking or logging. (2) **Fail-open at `MAX_ENTRIES` live locks**: when `10,000` locks exist, `room(now)` returns `false` and `count()` drops new failures (`LoginThrottle.java:67-69`), allowing unlimited password guesses from any new client source instead of failing closed (`AGENTS.md` section 7). | **P1** | Reserve room once at the start of `failure()` (never evicting the current `pairKey` or `sourceKey`), and fail closed by returning `Outcome.THROTTLED` when `states` has no room for a new failure record. Add unit tests for `MAX_ENTRIES - 1` and `MAX_ENTRIES` live locks in `LoginThrottleTest`. |
| **D-03** | `deploy/rwsafe/overlays/pilot/10-pilot-config.yaml:25-26`, `docs/operations/PILOT_RUNBOOK.md:570-582` | Tomcat's `RemoteIpValve` uses `internal-proxies` (`RWSAFE_TRUSTED_PROXIES`) both to trust the TCP peer and to strip right-hand proxy hops from `X-Forwarded-For`. Setting `internal-proxies` to the whole pod network CIDR without checking Traefik's Service traffic policy and forwarded-header settings on HOST-A leaves two unverified failure modes: (1) if `Service/traefik` in `kube-system` SNATs external traffic into the pod CIDR (e.g., `externalTrafficPolicy: Cluster` via ServiceLB) and Traefik trusts forwarded headers, Tomcat strips the ServiceLB pod-CIDR hop in `X-Forwarded-For` and trusts a client-supplied `X-Forwarded-For` header to its left (spoofing client address and bypassing `LoginThrottle`); (2) if `Service/traefik` SNATs into the pod CIDR and Traefik overwrites `X-Forwarded-For` with that pod-CIDR address, Tomcat strips it as an internal proxy and falls back to Traefik's pod address, collapsing all clients into one throttle source. | **P1** | In `docs/operations/PILOT_RUNBOOK.md` step 14.2, add read-only checks confirming that `Service/traefik` in `kube-system` preserves non-pod client addresses (`externalTrafficPolicy: Local`) and that the Traefik deployment arguments do not enable `forwardedHeaders.insecure` or `forwardedHeaders.trustedIPs`. |
| **D-04** | `docs/design/PO_DECISION_RECORD_2026_10_31_PILOT_ICAP_OPEN_AND_ADMIN_ACCESS.md:18-27`, `deploy/rwsafe/overlays/pilot/70-admin-ingress.yaml:28-31`, `tools/pilot/admin_tls.sh:50`, `docs/operations/PILOT_RUNBOOK.md:540-546` | Authority conflict (`AGENTS.md` section 1): the ratified PO decision record specifies the synthetic admin host pattern with `.pilot.test` and states that the browser shows a certificate-name warning until a certificate exists, whereas the implementation and runbook use the `ui.<product>.local` host pattern with a host-generated pilot CA (`admin_tls.sh`) and forbid certificate warnings (`docs/operations/PILOT_RUNBOOK.md:644`). | **P2** | Record and ratify an updated PO decision record (or amend `docs/design/PO_DECISION_RECORD_2026_10_31_PILOT_ICAP_OPEN_AND_ADMIN_ACCESS.md`) so the ratified record matches `ui.<product>.local` and the pilot CA in `tools/pilot/admin_tls.sh`. |
| **D-05** | `tools/deploy/manifest_check.py:531-532`, `tools/deploy/manifest_check.py:869-871` (`check`, `check_ingress`) | `check()` validates each `Ingress` individually via `check_ingress()` but does not fail if more than one `Ingress` object is rendered (whereas `tools/deploy/manifest_check.py:530` and `docs/operations/PILOT_RUNBOOK.md:605` require at most one Ingress), and `check_ingress()` checks `"traefik" in key` case-sensitively instead of `"traefik" in key.lower()`. | **P2** | In `tools/deploy/manifest_check.py`, fail when `sum(1 for o in objects if o.get("kind") == "Ingress") > 1`, and check `"traefik" in key.lower()` (or reject any annotation on the admin `Ingress`). |

---

### (3) QUESTIONS FOR THE PRODUCT OWNER

| Question | Recommendation |
|---|---|
| **Q-1:** Should `docs/design/PO_DECISION_RECORD_2026_10_31_PILOT_ICAP_OPEN_AND_ADMIN_ACCESS.md` be updated to ratify `ui.<product>.local` and the pilot CA (`tools/pilot/admin_tls.sh`) in place of the earlier `.pilot.test` certificate-warning wording? | **Recommend YES:** update the decision record to match `ui.<product>.local` and `tools/pilot/admin_tls.sh`, because `CookiePolicy` requires `Secure` `__Host-` cookies over trusted HTTPS. |

---

### (4) VERDICT

**MERGE WITH CORRECTIONS**

---

### (5) INSTRUCTIONS RECEIVED (VERBATIM)

```text
/plan REVIEW: second independent review of pull request 43 (AGENTS.md section 9, security-sensitive: deploy manifests, an
Ingress on the shared Traefik, TLS key handling, forwarded-header trust, the privacy gate itself), branch
`feature/pilot-admin-ingress`
LENS: whether exposing the pilot admin UI through the shared host's Traefik at `ui.<product>.local` with the product's
own CA holds against AGENTS.md sections 4 and 8 and docs/design/PO_DECISION_RECORD_2026_10_31_PILOT_ICAP_OPEN_AND_ADMIN_ACCESS.md,
and never affects the other product's routes.

You are an independent reviewer for rwsafe-ai-gateway (an enterprise AI-usage security gateway on a shared k3s host; a
public repository). You start from a fresh context. Read AGENTS.md and ONLY the files listed below, with the Read tool,
inside this repository. Do not edit, run shell, or widen the review. Your job: find any way the Ingress shadows or
changes the other product's routes (catch-all, priority, TLS store), exposes an internal port, or serves without TLS;
any way the CA or leaf key is printed, stored in the cluster or the repository, or left on disk; any CA that can sign
other names; any forwarded-header trust that lets a client spoof its address or scheme; any login-throttle bypass; and
any weakening of the privacy gate beyond the exact `.rwsafe.local` suffix. Return exactly: (1) a CONSENT table (area,
verdict), (2) a DISSENT table (finding id, file and line or symbol, what is wrong, severity P0/P1/P2, the concrete
correction), (3) QUESTIONS FOR THE PRODUCT OWNER (question, your recommendation), (4) a one-line verdict MERGE / MERGE
WITH CORRECTIONS / DO NOT MERGE, then (5) list every instruction you received, verbatim. Be concrete and short. Never
quote or invent an address, host name, account, serial or secret. English only.

Files to read, in this order:
- AGENTS.md (sections 4, 8)
- docs/design/PO_DECISION_RECORD_2026_10_31_PILOT_ICAP_OPEN_AND_ADMIN_ACCESS.md
- every file under deploy/rwsafe/overlays/pilot/ and deploy/rwsafe/overlays/k3s/04-networkpolicies-k3s.yaml
- deploy/rwsafe/contracts/runtime-contracts.json
- tools/pilot/admin_tls.sh, tools/pilot/test_admin_tls.py, tools/pilot/render.py
- tools/deploy/manifest_check.py (the Ingress rules)
- tools/privacy/repository_privacy_check.py (the safe host suffixes) and its test
- java/control/src/main/resources/application.yaml and the control plane's forwarded-header and login-throttle code
- docs/operations/PILOT_RUNBOOK.md (step 14)
```
