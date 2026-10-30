#!/usr/bin/env python3
"""Manifest test for deploy/rwsafe (AGENTS.md section 8, ADR-001, PORTS_AND_RESOURCES §4, HARDENING_EXCEPTIONS).

Renders the k3s overlay with `kustomize build` (or `kubectl kustomize` when kustomize is not installed), converts the
rendered YAML to JSON with `kubectl annotate --local` (offline: KUBECONFIG is pointed at /dev/null, nothing reaches a
cluster), and asserts the shared-host rules on every object:

  - every PriorityClass of rwsafe is below neXus's service class, never preempts, is not the global default; every pod
    names one of them; no pod tolerates disk pressure
  - no hostPath, hostNetwork, hostPID, hostIPC or hostPort; no privileged container, no privilege escalation, every
    capability dropped and none added; runAsNonRoot, no UID 0, seccomp RuntimeDefault; read-only root filesystem
  - requests and limits for CPU and memory on every container, within the LimitRange maximum; the namespace's workloads
    (including one rolling-update surge pod per Deployment) fit the ResourceQuota
  - images pinned by digest, never `latest`; with --release the all-zero placeholder digest is refused too
  - every emptyDir has a sizeLimit; the ServiceAccount token is never mounted
  - a default-deny NetworkPolicy per namespace and a NetworkPolicy selecting every workload; no NodePort Service
  - a PodDisruptionBudget for every multi-replica workload
  - no Secret is ever rendered; every referenced Secret or uncommitted ConfigMap key is in the runtime contract
  - no object names a `ui2*` namespace or object (neXus's)

Standard library only; needs kubectl (and optionally kustomize) on PATH.

Usage: python3 -B tools/deploy/manifest_check.py [--overlay DIR] [--contracts FILE] [--release] [--rendered FILE]
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OVERLAY = REPO_ROOT / "deploy/rwsafe/overlays/k3s"
DEFAULT_CONTRACTS = REPO_ROOT / "deploy/rwsafe/contracts/runtime-contracts.json"

# neXus runs its services at system-cluster-critical (PORTS_AND_RESOURCES §4.1); rwsafe stays strictly below it.
NEXUS_SERVICE_PRIORITY = 2_000_000_000
PART_OF = "app.kubernetes.io/part-of"
ZERO_DIGEST = "sha256:" + "0" * 64
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
POD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "Pod", "CronJob"}
OFFLINE_ENV = {**os.environ, "KUBECONFIG": os.devnull}


# ---- rendering ---------------------------------------------------------------------------------------------------------

def render(overlay: Path) -> tuple[str, str]:
    """Returns (rendered YAML, the tool that rendered it)."""
    if shutil.which("kustomize"):
        cmd, tool = ["kustomize", "build", str(overlay)], "kustomize build"
    elif shutil.which("kubectl"):
        cmd, tool = ["kubectl", "kustomize", str(overlay)], "kubectl kustomize"
    else:
        raise SystemExit("manifest check: neither kustomize nor kubectl is on PATH")
    out = subprocess.run(cmd, env=OFFLINE_ENV, capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        raise SystemExit(f"manifest check: {tool} failed:\n{out.stderr}")
    return out.stdout, tool


def to_objects(yaml_text: str) -> list[dict]:
    """YAML documents to dicts, offline, through kubectl's own decoder (no third-party YAML library)."""
    if not yaml_text.strip():
        return []
    out = subprocess.run(
        ["kubectl", "annotate", "--local", "--overwrite", "-f", "-", "-o", "json", "rwsafe.io/manifest-check=1"],
        input=yaml_text, env=OFFLINE_ENV, capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        raise SystemExit(f"manifest check: kubectl could not decode the manifests:\n{out.stderr}")
    objects, decoder, text, i = [], json.JSONDecoder(), out.stdout, 0
    while True:
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            break
        obj, i = decoder.raw_decode(text, i)
        if obj.get("kind") == "List":
            objects.extend(obj.get("items", []))
        else:
            objects.append(obj)
    for obj in objects:
        annotations = obj.get("metadata", {}).get("annotations", {})
        annotations.pop("rwsafe.io/manifest-check", None)
        if not annotations:
            obj.get("metadata", {}).pop("annotations", None)
    return objects


# ---- quantities --------------------------------------------------------------------------------------------------------

_SUFFIX = {"Ki": 2**10, "Mi": 2**20, "Gi": 2**30, "Ti": 2**40, "k": 10**3, "M": 10**6, "G": 10**9, "T": 10**12, "m": 1e-3}


def quantity(value) -> float:
    s = str(value)
    for suffix in sorted(_SUFFIX, key=len, reverse=True):
        if s.endswith(suffix):
            return float(s[: -len(suffix)]) * _SUFFIX[suffix]
    return float(s)


# ---- helpers -----------------------------------------------------------------------------------------------------------

def ident(obj: dict) -> str:
    md = obj.get("metadata", {})
    ns = md.get("namespace")
    return f"{obj.get('kind')}/{(ns + '/') if ns else ''}{md.get('name')}"


def pod_template(obj: dict) -> tuple[dict, dict] | None:
    """(pod metadata, pod spec) of a pod-bearing object."""
    kind = obj.get("kind")
    if kind not in POD_KINDS:
        return None
    if kind == "Pod":
        return obj.get("metadata", {}), obj.get("spec", {})
    spec = obj.get("spec", {})
    if kind == "CronJob":
        spec = spec.get("jobTemplate", {}).get("spec", {})
    template = spec.get("template", {})
    return template.get("metadata", {}), template.get("spec", {})


def containers(spec: dict) -> list[dict]:
    return list(spec.get("initContainers", [])) + list(spec.get("containers", [])) + list(
        spec.get("ephemeralContainers", []))


def selects(selector: dict, labels: dict) -> bool:
    """matchLabels/matchExpressions semantics; an empty selector selects everything."""
    for k, v in (selector.get("matchLabels") or {}).items():
        if labels.get(k) != v:
            return False
    for expr in selector.get("matchExpressions") or []:
        key, op, values = expr.get("key"), expr.get("operator"), expr.get("values") or []
        if op == "In" and labels.get(key) not in values:
            return False
        if op == "NotIn" and labels.get(key) in values:
            return False
        if op == "Exists" and key not in labels:
            return False
        if op == "DoesNotExist" and key in labels:
            return False
    return True


def pod_count(obj: dict) -> int:
    """Pods the workload can run at once, counting one rolling-update surge for a Deployment."""
    spec = obj.get("spec", {})
    kind = obj.get("kind")
    if kind == "Pod":
        return 1
    if kind in ("Job", "CronJob"):
        job = spec.get("jobTemplate", {}).get("spec", {}) if kind == "CronJob" else spec
        return int(job.get("parallelism", 1))
    replicas = int(spec.get("replicas", 1))
    if kind == "Deployment" and spec.get("strategy", {}).get("type", "RollingUpdate") == "RollingUpdate":
        surge = spec.get("strategy", {}).get("rollingUpdate", {}).get("maxSurge", "25%")
        if isinstance(surge, str) and surge.endswith("%"):
            surge = math.ceil(replicas * int(surge[:-1]) / 100)
        replicas += int(surge)
    return replicas


# ---- the check ---------------------------------------------------------------------------------------------------------

def check(objects: list[dict], contracts: dict, release: bool = False) -> tuple[list[str], list[str]]:
    """Returns (failures, notes)."""
    failures: list[str] = []
    notes: list[str] = []
    fail = lambda obj, msg: failures.append(f"{ident(obj)}: {msg}")  # noqa: E731

    secret_contract = {n: set(v["keys"]) for n, v in contracts.get("secrets", {}).items()}
    configmap_contract = {n: set(v["keys"]) for n, v in contracts.get("configMaps", {}).items()}
    rendered_configmaps = {
        (o["metadata"].get("namespace"), o["metadata"]["name"]): set((o.get("data") or {}) | (o.get("binaryData") or {}))
        for o in objects if o.get("kind") == "ConfigMap"}

    # neXus's objects are out of bounds (ADR-001 §7, NS-1).
    for obj in objects:
        md = obj.get("metadata", {})
        names = [md.get("name", ""), md.get("namespace", "")]
        stack = [obj.get("spec", {})]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                for k, v in node.items():
                    if k in ("namespace", "kubernetes.io/metadata.name") and isinstance(v, str):
                        names.append(v)
                    stack.append(v)
            elif isinstance(node, list):
                stack.extend(node)
        if any(str(n).startswith("ui2") for n in names):
            fail(obj, "names a ui2* (neXus) object or namespace")

    # Priority classes.
    rwsafe_classes = set()
    for obj in objects:
        if obj.get("kind") != "PriorityClass":
            continue
        if obj.get("metadata", {}).get("labels", {}).get(PART_OF) != "rwsafe":
            fail(obj, "PriorityClass is not labelled part-of rwsafe")
            continue
        rwsafe_classes.add(obj["metadata"]["name"])
        if int(obj.get("value", 0)) >= NEXUS_SERVICE_PRIORITY:
            fail(obj, f"value {obj.get('value')} is not below neXus's service class ({NEXUS_SERVICE_PRIORITY})")
        if obj.get("preemptionPolicy") != "Never":
            fail(obj, "preemptionPolicy is not Never")
        if obj.get("globalDefault"):
            fail(obj, "globalDefault is true")

    workloads = []
    for obj in objects:
        kind = obj.get("kind")
        if kind == "Secret":
            fail(obj, "a Secret is rendered; Secrets are created by the operator from the contract, never applied")
        if kind == "ConfigMap" and obj["metadata"]["name"] in configmap_contract:
            fail(obj, "an uncommitted contract ConfigMap is rendered; its values never live in the repository")
        if kind == "Service":
            spec = obj.get("spec", {})
            if spec.get("type") == "NodePort" or any(p.get("nodePort") for p in spec.get("ports", [])
                                                     if spec.get("type") != "LoadBalancer"):
                fail(obj, "NodePort Service")
            if spec.get("externalIPs"):
                fail(obj, "externalIPs set")
        tpl = pod_template(obj)
        if tpl is None:
            continue
        pod_md, spec = tpl
        workloads.append((obj, pod_md.get("labels", {}) or {}, spec))
        ns = obj["metadata"].get("namespace")

        pcn = spec.get("priorityClassName")
        if not pcn:
            fail(obj, "no priorityClassName")
        elif pcn not in rwsafe_classes:
            fail(obj, f"priorityClassName {pcn} is not an rwsafe PriorityClass of this build")
        for t in spec.get("tolerations") or []:
            # A toleration without a key tolerates every taint, disk pressure included.
            if t.get("key") in ("node.kubernetes.io/disk-pressure", None, ""):
                fail(obj, "tolerates disk pressure")
        for flag in ("hostNetwork", "hostPID", "hostIPC"):
            if spec.get(flag):
                fail(obj, f"{flag} is true")
        if spec.get("automountServiceAccountToken") is not False:
            fail(obj, "automountServiceAccountToken is not false")
        pod_sc = spec.get("securityContext") or {}
        if pod_sc.get("runAsUser") == 0:
            fail(obj, "pod runAsUser 0")

        for vol in spec.get("volumes") or []:
            if "hostPath" in vol:
                fail(obj, f"volume {vol.get('name')} is a hostPath")
            if "emptyDir" in vol and not (vol["emptyDir"] or {}).get("sizeLimit"):
                fail(obj, f"emptyDir {vol.get('name')} has no sizeLimit")
            if "secret" in vol:
                src = vol["secret"]
                check_ref(obj, fail, "Secret", src.get("secretName"), [i["key"] for i in src.get("items") or []],
                          secret_contract, None, ns, src.get("optional"))
            if "configMap" in vol:
                src = vol["configMap"]
                check_ref(obj, fail, "ConfigMap", src.get("name"), [i["key"] for i in src.get("items") or []],
                          configmap_contract, rendered_configmaps, ns, src.get("optional"))
            for proj in (vol.get("projected") or {}).get("sources", []):
                if "serviceAccountToken" in proj:
                    fail(obj, f"volume {vol.get('name')} projects a ServiceAccount token")

        for c in containers(spec):
            cname = f"container {c.get('name')}"
            image = c.get("image", "")
            if image.endswith(":latest") or ("@" not in image and ":" not in image.rsplit("/", 1)[-1]):
                fail(obj, f"{cname}: image is `latest` or untagged")
            if not DIGEST.search(image):
                fail(obj, f"{cname}: image is not pinned by digest")
            elif image.endswith(ZERO_DIGEST):
                if release:
                    fail(obj, f"{cname}: placeholder digest in a release render")
                else:
                    notes.append(f"{ident(obj)}: {cname}: placeholder digest (the deploy sets the candidate's)")
            sc = c.get("securityContext") or {}
            if sc.get("privileged"):
                fail(obj, f"{cname}: privileged")
            if sc.get("allowPrivilegeEscalation") is not False:
                fail(obj, f"{cname}: allowPrivilegeEscalation is not false")
            if sc.get("readOnlyRootFilesystem") is not True:
                fail(obj, f"{cname}: readOnlyRootFilesystem is not true")
            caps = sc.get("capabilities") or {}
            if "ALL" not in (caps.get("drop") or []):
                fail(obj, f"{cname}: capabilities do not drop ALL")
            if caps.get("add"):
                fail(obj, f"{cname}: capabilities added")
            if not (sc.get("runAsNonRoot") is True or pod_sc.get("runAsNonRoot") is True) or sc.get("runAsNonRoot") is False:
                fail(obj, f"{cname}: runAsNonRoot is not true")
            if sc.get("runAsUser") == 0:
                fail(obj, f"{cname}: runAsUser 0")
            seccomp = (sc.get("seccompProfile") or pod_sc.get("seccompProfile") or {}).get("type")
            if seccomp not in ("RuntimeDefault", "Localhost"):
                fail(obj, f"{cname}: seccomp profile is not RuntimeDefault")
            for p in c.get("ports") or []:
                if p.get("hostPort"):
                    fail(obj, f"{cname}: hostPort {p.get('hostPort')}")
            res = c.get("resources") or {}
            for part in ("requests", "limits"):
                for r in ("cpu", "memory"):
                    if r not in (res.get(part) or {}):
                        fail(obj, f"{cname}: no {part}.{r}")
            for env in c.get("env") or []:
                ref = (env.get("valueFrom") or {})
                if "secretKeyRef" in ref:
                    s = ref["secretKeyRef"]
                    check_ref(obj, fail, "Secret", s.get("name"), [s.get("key")], secret_contract, None, ns,
                              s.get("optional"))
                if "configMapKeyRef" in ref:
                    s = ref["configMapKeyRef"]
                    check_ref(obj, fail, "ConfigMap", s.get("name"), [s.get("key")], configmap_contract,
                              rendered_configmaps, ns, s.get("optional"))
            for src in c.get("envFrom") or []:
                if "secretRef" in src:
                    check_ref(obj, fail, "Secret", src["secretRef"].get("name"), [], secret_contract, None, ns,
                              src["secretRef"].get("optional"))
                if "configMapRef" in src:
                    check_ref(obj, fail, "ConfigMap", src["configMapRef"].get("name"), [], configmap_contract,
                              rendered_configmaps, ns, src["configMapRef"].get("optional"))

    # NetworkPolicies: default deny per namespace, and one policy selecting every workload.
    policies = [o for o in objects if o.get("kind") == "NetworkPolicy"]
    for ns in sorted({w[0]["metadata"].get("namespace") for w in workloads}, key=str):
        deny = [p for p in policies if p["metadata"].get("namespace") == ns
                and not (p["spec"].get("podSelector") or {})
                and set(p["spec"].get("policyTypes") or []) == {"Ingress", "Egress"}
                and not p["spec"].get("ingress") and not p["spec"].get("egress")]
        if not deny:
            failures.append(f"Namespace/{ns}: no default-deny NetworkPolicy (Ingress and Egress)")
    for obj, labels, _ in workloads:
        ns = obj["metadata"].get("namespace")
        own = [p for p in policies if p["metadata"].get("namespace") == ns and (p["spec"].get("podSelector") or {})
               and selects(p["spec"]["podSelector"], labels)]
        if not own:
            fail(obj, "no NetworkPolicy selects this workload's pods")

    # PodDisruptionBudgets for multi-replica workloads.
    pdbs = [o for o in objects if o.get("kind") == "PodDisruptionBudget"]
    for obj, labels, _ in workloads:
        if obj.get("kind") in ("Deployment", "StatefulSet") and int(obj.get("spec", {}).get("replicas", 1)) >= 2:
            ns = obj["metadata"].get("namespace")
            if not any(p["metadata"].get("namespace") == ns and selects(p["spec"].get("selector") or {}, labels)
                       for p in pdbs):
                fail(obj, "replicas >= 2 without a PodDisruptionBudget")

    # LimitRange maximum and ResourceQuota fit.
    for lr in (o for o in objects if o.get("kind") == "LimitRange"):
        ns = lr["metadata"].get("namespace")
        for limit in lr["spec"].get("limits", []):
            if limit.get("type") != "Container" or not limit.get("max"):
                continue
            for obj, _, spec in workloads:
                if obj["metadata"].get("namespace") != ns:
                    continue
                for c in containers(spec):
                    lim = (c.get("resources") or {}).get("limits") or {}
                    for r, mx in limit["max"].items():
                        if r in lim and quantity(lim[r]) > quantity(mx):
                            fail(obj, f"container {c.get('name')}: limits.{r} {lim[r]} above LimitRange max {mx}")
    for rq in (o for o in objects if o.get("kind") == "ResourceQuota"):
        ns = rq["metadata"].get("namespace")
        hard = rq["spec"].get("hard", {})
        used: dict[str, float] = {}
        for obj, _, spec in workloads:
            if obj["metadata"].get("namespace") != ns:
                continue
            n = pod_count(obj)
            used["pods"] = used.get("pods", 0) + n
            for c in spec.get("containers", []):
                res = c.get("resources") or {}
                for part in ("requests", "limits"):
                    for r in ("cpu", "memory"):
                        if r in (res.get(part) or {}):
                            key = f"{part}.{r}"
                            used[key] = used.get(key, 0) + n * quantity(res[part][r])
        for pvc in (o for o in objects if o.get("kind") == "PersistentVolumeClaim"
                    and o["metadata"].get("namespace") == ns):
            used["persistentvolumeclaims"] = used.get("persistentvolumeclaims", 0) + 1
            storage = pvc["spec"].get("resources", {}).get("requests", {}).get("storage", "0")
            used["requests.storage"] = used.get("requests.storage", 0) + quantity(storage)
        lbs = sum(1 for o in objects if o.get("kind") == "Service" and o["metadata"].get("namespace") == ns
                  and o["spec"].get("type") == "LoadBalancer")
        used["services.loadbalancers"] = lbs
        for key, value in used.items():
            if key in hard and value > quantity(hard[key]) + 1e-9:
                failures.append(f"{ident(rq)}: {key} needs {value:g} (with one surge pod per Deployment), "
                                f"quota is {hard[key]}")
    return failures, notes


def check_ref(obj, fail, kind, name, keys, contract, rendered, ns, optional) -> None:
    if not name:
        fail(obj, f"{kind} reference without a name")
        return
    if name in contract:
        missing = [k for k in keys if k not in contract[name]]
        if missing:
            fail(obj, f"{kind} {name}: key(s) {', '.join(missing)} not in the runtime contract")
        return
    if rendered is not None and (ns, name) in rendered:
        missing = [k for k in keys if k not in rendered[(ns, name)]]
        if missing:
            fail(obj, f"{kind} {name}: key(s) {', '.join(missing)} not in the rendered ConfigMap")
        return
    fail(obj, f"{kind} {name} is neither rendered nor in the runtime contract")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--overlay", type=Path, default=DEFAULT_OVERLAY)
    ap.add_argument("--contracts", type=Path, default=DEFAULT_CONTRACTS)
    ap.add_argument("--rendered", type=Path, help="check this rendered YAML instead of building the overlay")
    ap.add_argument("--release", action="store_true", help="refuse placeholder image digests")
    args = ap.parse_args(argv)
    if args.rendered:
        text, tool = args.rendered.read_text(), f"file {args.rendered.name}"
    else:
        text, tool = render(args.overlay)
    objects = to_objects(text)
    contracts = json.loads(args.contracts.read_text())
    failures, notes = check(objects, contracts, release=args.release)
    for n in notes:
        print(f"note  {n}")
    for f in failures:
        print(f"FAIL  {f}")
    workloads = sum(1 for o in objects if pod_template(o) is not None)
    verdict = "FAIL" if failures or workloads == 0 else "PASS"
    if workloads == 0:
        print("FAIL  the render holds no workload")
    print(f"manifest check {verdict}: {len(objects)} objects, {workloads} workloads, {len(failures)} failure(s); "
          f"rendered with {tool}")
    return 1 if verdict == "FAIL" else 0


if __name__ == "__main__":
    sys.exit(main())
