#!/usr/bin/env python3
"""Manifest test for deploy/rwsafe (AGENTS.md section 8, ADR-001, PORTS_AND_RESOURCES §4, HARDENING_EXCEPTIONS).

Renders the k3s overlay with `kustomize build` (or `kubectl kustomize` when kustomize is not installed), converts the
rendered YAML to JSON with `kubectl annotate --local` (offline: KUBECONFIG is pointed at /dev/null, nothing reaches a
cluster), and asserts the shared-host rules on every object:

  - every PriorityClass of rwsafe is at most 1000 (PO decision Q-10) and so below neXus's service class, never preempts,
    is not the global default; every pod names one of them; no pod carries any toleration (ADR-001 §3)
  - no hostPath, hostNetwork, hostPID, hostIPC or hostPort; no privileged container, no privilege escalation, every
    capability dropped and none added; runAsNonRoot, no fixed runAsUser or runAsGroup (arbitrary-UID images, ADR-001
    §6), seccomp RuntimeDefault only; read-only root filesystem
  - requests and limits for CPU and memory on every container, within the LimitRange maximum; the namespace's workloads
    (init containers and volumeClaimTemplates included, and one rolling-update surge pod per Deployment) and its PVCs
    fit the ResourceQuota; every PVC and claim template is within the LimitRange's PVC maximum and every claimed PVC
    is rendered; all requested storage together is within HOST_FREE_STORAGE_BUDGET; every rendered namespace has a
    ResourceQuota and a LimitRange
  - every Namespace enforces PSA `restricted` (only `rwsafe-build` may enforce `baseline`) and audits and warns at
    `restricted`
  - images pinned by digest, never `latest`; with --release the all-zero placeholder digest is refused too
  - every emptyDir has a sizeLimit of at most 512Mi (4Gi in `rwsafe-build`) and is never memory-backed; the
    ServiceAccount token is never mounted, and every ServiceAccount sets automountServiceAccountToken false
  - a default-deny NetworkPolicy per namespace and a NetworkPolicy selecting every workload; every egress rule names its
    destination, no ipBlock is 0.0.0.0/0, and with --release no ipBlock is an RFC 5737 documentation placeholder; no
    placeholder is shared by two NetworkPolicies (the estate patch replaces each by one value); an ipBlock without a
    valid cidr, an ingress rule without `from`, an empty peer and an empty namespace or pod selector in a peer fail
    (EMPTY_SELECTOR_EXCEPTIONS lists deliberate ones); no NodePort Service
  - a PodDisruptionBudget for every multi-replica workload, keeping at least one pod and allowing at least one eviction
  - no Secret is ever rendered; every referenced Secret or uncommitted ConfigMap key (env, volume, projected volume)
    is in the runtime contract
  - nothing anywhere in any object (keys, values, tokens of names, URLs and selectors) names a `ui2*` or `nexus*`
    object, namespace, label, PriorityClass or registry repository (neXus's)
  - the product name (deploy/rwsafe/product.env, or --product) drives every cluster-visible name (PO, 2026-10-31): the
    committed manifests are written with `rwsafe` and renamed by `rename_objects`; under another name nothing rendered
    still names rwsafe, every in-cluster registry image is a `<product>-*` repository, and the part-of label and the
    build namespace follow the name
  - no LoadBalancer port or hostPort is a port already in use on HOST-A (HOST_PORTS_IN_USE: Traefik owns 80/443), and no
    container or Service port is one of neXus's cluster ports (NEXUS_CLUSTER_PORTS)

Standard library only; needs kubectl (and optionally kustomize) on PATH.

Usage: python3 -B tools/deploy/manifest_check.py [--overlay DIR] [--contracts FILE] [--release] [--rendered FILE]
                                                 [--product NAME]
"""
from __future__ import annotations

import argparse
import ipaddress
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
PRODUCT_FILE = REPO_ROOT / "deploy/rwsafe/product.env"
# The name the committed manifests and the runtime contract are written with; a render under another product name renames
# every cluster-visible occurrence (rename_objects). Application-internal identifiers keep it (environment variable names,
# mount paths, Secret and ConfigMap keys, database and role names, the snapshot key id).
SOURCE_PRODUCT = "rwsafe"
IN_CLUSTER_REGISTRY = "registry.kube-system.svc.cluster.local"
_PRODUCT_RE = re.compile(r"^[a-z][a-z0-9-]{0,18}[a-z0-9]$")
_RESERVED_PRODUCTS = {"default", "system", "kube", "registry", "traefik", "local-path", "monitoring"}
# HOSTA_MEASUREMENT_2026_10_31.md and PORTS_AND_RESOURCES §2.1: host ports in use on HOST-A (sshd 22, the MTA 25, the
# resolver 53, Traefik's ServiceLB 80/443, chrony 323, the k3s API 6443/6444, flannel 8472, k3s internals and the kubelet
# 10010 and 10248-10259). A LoadBalancer port or a hostPort on one of them would collide on the node.
HOST_PORTS_IN_USE = {22, 25, 53, 80, 323, 443, 6443, 6444, 8472, 10010} | set(range(10248, 10260))
# PORTS_AND_RESOURCES §2.2 and §5: neXus's cluster ports. 8080 and 5432 are shared by number inside separate namespaces
# and Services (accepted in §5); these are never reused, so a mistaken cross-namespace request fails loudly.
NEXUS_CLUSTER_PORTS = {8084, 8085, 8086, 8087}

# neXus runs its services at system-cluster-critical (PORTS_AND_RESOURCES §4.1); rwsafe stays strictly below it. PO
# decision Q-10 (PO_DECISION_RECORD_2026_10_30_MVP_BLOCKING_QUESTIONS item 8) places the data plane at 1000, above
# neXus's packet-analysis class (-100) and below every other neXus class; no rwsafe class may exceed it.
NEXUS_SERVICE_PRIORITY = 2_000_000_000
RWSAFE_PRIORITY_CEILING = 1000
# ADR-001 §3: emptyDir caps; the build namespace (`<product>-build`) is the one PSA `baseline` exception (PLAT-F6).
EMPTYDIR_CAP = 512 * 2**20
BUILD_EMPTYDIR_CAP = 4 * 2**30
PSA = "pod-security.kubernetes.io/"
# RFC 5737 documentation ranges: the committed placeholder for estate addresses (the deploy patches the real ones in).
DOCUMENTATION_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
# neXus's objects (ADR-001 §7, NS-1): a token of a key or value that starts with `ui2` or `nexus` (its namespaces `ui2*`,
# its label value `nexus-ui2`, its PriorityClass `ui2-low`, its registry repositories `nexus-ui2-*`).
_NAME_TOKENS = re.compile(r"[/.:=@?&#,;\s\-\"'()\[\]{}]+")
PART_OF = "app.kubernetes.io/part-of"
ZERO_DIGEST = "sha256:" + "0" * 64
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
POD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "Pod", "CronJob"}
OFFLINE_ENV = {**os.environ, "KUBECONFIG": os.devnull}
# NetworkPolicies whose peers deliberately carry an empty namespaceSelector or podSelector (every pod of the policy's
# own namespace, or every namespace), as ident -> reason. Empty: no committed policy needs one (PR 27 review D-03); an
# entry is added only with its reason and a review in the pull request that adds it.
EMPTY_SELECTOR_EXCEPTIONS: dict[str, str] = {}
# PR 27 review D-06: the storage all rwsafe namespaces may request together on HOST-A. Measured 2026-10-31
# (docs/operations/HOSTA_MEASUREMENT_2026_10_31.md, superseding the 2026-10-30 figure of PORTS_AND_RESOURCES §1): 305 GiB
# free on the one 1005 GiB root filesystem, minus the kubelet's hard eviction reserve nodefs.available 5 % of 1005 GiB
# (50.25 GiB) = 254.75 GiB, rounded down. local-path reserves nothing, so this is a budget, not a guarantee; re-measure
# before raising it (a PO decision, DEPLOY_AND_SHARED_HOST_RUNBOOK §7.5). The capture cap does not follow it.
HOST_FREE_STORAGE_BUDGET = 254 * 2**30


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


def names_nexus(text: str) -> bool:
    """True when a key or value names a neXus (`ui2*`, `nexus*`) object: the whole string or any token of it."""
    t = text.lower()
    return "nexus-ui2" in t or any(tok.startswith(("ui2", "nexus")) for tok in _NAME_TOKENS.split(t) if tok)


def nexus_references(node, path: str = "") -> list[str]:
    """Paths (never values) of every key or string value in the object tree that names a neXus object."""
    found: list[str] = []
    if isinstance(node, dict):
        for k, v in node.items():
            here = f"{path}.{k}" if path else str(k)
            if names_nexus(str(k)):
                found.append(here)
            found.extend(nexus_references(v, here))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            found.extend(nexus_references(v, f"{path}[{i}]"))
    elif isinstance(node, str) and names_nexus(node):
        found.append(path)
    return found


def pod_resources(spec: dict) -> dict[str, float]:
    """Effective pod requests and limits for the quota: the sum of the containers (and restartable init sidecars), or the
    largest ordinary init container when that is larger (the scheduler's rule)."""
    out: dict[str, float] = {}
    for part in ("requests", "limits"):
        for r in ("cpu", "memory"):
            key = f"{part}.{r}"
            def value(c):
                return quantity(((c.get("resources") or {}).get(part) or {}).get(r, 0))
            inits = spec.get("initContainers") or []
            sidecars = [c for c in inits if c.get("restartPolicy") == "Always"]
            ordinary = [c for c in inits if c.get("restartPolicy") != "Always"]
            total = sum(value(c) for c in list(spec.get("containers") or []) + sidecars)
            out[key] = max([total] + [value(c) for c in ordinary])
    return out


def empty_selector(selector) -> bool:
    """True for a label selector that selects everything ({} or no labels and no expressions)."""
    return not ((selector or {}).get("matchLabels") or (selector or {}).get("matchExpressions"))


def documentation_range(net) -> bool:
    """True for an RFC 5737 documentation network: the committed placeholder of an estate address."""
    return any(net.version == d.version and net.subnet_of(d) for d in DOCUMENTATION_NETS)


def pdb_count(value, replicas: int, round_up: bool) -> int:
    """A PDB's minAvailable or maxUnavailable as a pod count."""
    if isinstance(value, str) and value.endswith("%"):
        exact = replicas * int(value[:-1]) / 100
        return math.ceil(exact) if round_up else math.floor(exact)
    return int(value)


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


# ---- the product name (PO, 2026-10-31: renameable from one place) ------------------------------------------------------

def default_product() -> str:
    """The `PRODUCT=` line of deploy/rwsafe/product.env, the one place the deployed name is set."""
    for line in PRODUCT_FILE.read_text().splitlines():
        line = line.strip()
        if line.startswith("PRODUCT="):
            return line.split("=", 1)[1].strip().strip("\"'")
    raise SystemExit(f"manifest check: no PRODUCT= line in {PRODUCT_FILE.name}")


def validate_product(name: str) -> str | None:
    """The reason a product name is refused, or None: lower case DNS label, 2-20 characters (so `<product>-security`
    and every derived object name stay valid), never a neXus name or a Kubernetes or platform name."""
    if not isinstance(name, str) or not _PRODUCT_RE.match(name) or "--" in name:
        return "must be 2-20 characters of a-z, 0-9 and single hyphens, starting with a letter"
    if names_nexus(name):
        return "names neXus (ui2*, nexus*)"
    if name in _RESERVED_PRODUCTS or name.startswith(("kube", "system", "k3s", "openshift")):
        return "is a Kubernetes or platform name"
    return None


def swap_name(value: str, product: str) -> str:
    """`rwsafe` -> product, `rwsafe-x` -> `<product>-x`; anything else unchanged."""
    if value == SOURCE_PRODUCT:
        return product
    if value.startswith(SOURCE_PRODUCT + "-"):
        return product + value[len(SOURCE_PRODUCT):]
    return value


def _swap_label_key(key: str, product: str) -> str:
    prefix = SOURCE_PRODUCT + ".io/"
    return product + ".io/" + key[len(prefix):] if key.startswith(prefix) else key


_DNS_NAME = re.compile(r"(?<![A-Za-z0-9_-])" + SOURCE_PRODUCT + r"((?:-[a-z0-9]+)*)\." + SOURCE_PRODUCT + r"\.svc\b")
_REGISTRY_REPO = re.compile(r"(?<=" + re.escape(IN_CLUSTER_REGISTRY + "/") + r")" + SOURCE_PRODUCT + "-")
# Dicts whose `name` is a reference to another object, and keys whose string value is one.
_NAME_HOLDERS = {"metadata", "configMapRef", "secretRef", "configMapKeyRef", "secretKeyRef", "configMap", "secret"}
_REF_KEYS = {"namespace", "serviceAccountName", "priorityClassName", "claimName", "secretName", "serviceName"}


def _is_label_map(parent: str, node: dict) -> bool:
    if parent in ("labels", "matchLabels"):
        return True
    # A Service's spec.selector is a plain label map; a workload's or PDB's has matchLabels/matchExpressions.
    return parent == "selector" and bool(node) and all(isinstance(v, str) for v in node.values()) and not (
        {"matchLabels", "matchExpressions"} & set(node))


def _rename(node, product: str, parent: str = ""):
    if isinstance(node, dict):
        if _is_label_map(parent, node):
            return {_swap_label_key(k, product): swap_name(v, product) if isinstance(v, str) else v
                    for k, v in node.items()}
        out = {}
        for k, v in node.items():
            if isinstance(v, str) and ((k == "name" and parent in _NAME_HOLDERS) or k in _REF_KEYS):
                out[k] = swap_name(v, product)
            elif k == "key" and parent == "matchExpressions[]" and isinstance(v, str):
                out[k] = _swap_label_key(v, product)
            elif k == "values" and parent == "matchExpressions[]" and isinstance(v, list):
                out[k] = [swap_name(x, product) if isinstance(x, str) else x for x in v]
            else:
                out[k] = _rename(v, product, k)
        return out
    if isinstance(node, list):
        return [_rename(v, product, parent + "[]") for v in node]
    if isinstance(node, str):
        return _REGISTRY_REPO.sub(product + "-", _DNS_NAME.sub(
            lambda m: f"{product}{m.group(1)}.{product}.svc", node))
    return node


def rename_objects(objects: list[dict], product: str) -> list[dict]:
    """The rendered objects under the product name: object names, namespaces, references (ServiceAccount, PriorityClass,
    Secret, ConfigMap, PVC, Service), label keys `rwsafe.io/*` and values, selectors, in-cluster Service DNS names and
    in-cluster registry repositories. Free text, environment variable names, mount paths, keys and ConfigMap file
    contents other than Service DNS names are left as they are."""
    if product == SOURCE_PRODUCT:
        return objects
    return [_rename(o, product) for o in objects]


def rename_contracts(contracts: dict, product: str) -> dict:
    """The runtime contract's object names and namespaces under the product name; keys are unchanged."""
    if product == SOURCE_PRODUCT:
        return contracts
    out = dict(contracts)
    if "namespace" in out:
        out["namespace"] = swap_name(out["namespace"], product)
    for section in ("secrets", "configMaps"):
        out[section] = {swap_name(n, product): v for n, v in (contracts.get(section) or {}).items()}
    if isinstance(contracts.get("build"), dict):
        build = dict(contracts["build"])
        build["namespace"] = swap_name(build.get("namespace", ""), product)
        build["configMaps"] = {swap_name(n, product): v for n, v in (build.get("configMaps") or {}).items()}
        out["build"] = build
    return out


def _source_name_left(value: str) -> bool:
    return (value == SOURCE_PRODUCT or value.startswith(SOURCE_PRODUCT + "-")
            or f".{SOURCE_PRODUCT}.svc" in value or f"//{SOURCE_PRODUCT}-" in value
            or f"{IN_CLUSTER_REGISTRY}/{SOURCE_PRODUCT}-" in value)


def source_name_references(node, path: str = "", parent: str = "") -> list[str]:
    """Paths (never values) where a render under another product name still names the source product: label keys
    `rwsafe.io/*`, and string values that are `rwsafe`, start with `rwsafe-`, or hold an rwsafe Service DNS name or
    registry repository. Not counted: map keys other than label keys, `key` and `path` fields (Secret and ConfigMap
    keys), ConfigMap data (file contents), and environment values equal to `rwsafe` (the database name)."""
    found: list[str] = []
    if isinstance(node, dict):
        for k, v in node.items():
            here = f"{path}.{k}" if path else str(k)
            if parent in ("labels", "matchLabels") and str(k).startswith(SOURCE_PRODUCT + ".io/"):
                found.append(here)
            if k == "key" and parent == "matchExpressions[]" and str(v).startswith(SOURCE_PRODUCT + ".io/"):
                found.append(here)
            if k in ("key", "path") and parent != "matchExpressions[]":
                continue
            if k in ("data", "binaryData") and path == "":
                for dk, dv in (v or {}).items():
                    if isinstance(dv, str) and (f".{SOURCE_PRODUCT}.svc" in dv
                                                or f"{IN_CLUSTER_REGISTRY}/{SOURCE_PRODUCT}-" in dv):
                        found.append(f"{here}.{dk}")
                continue
            if k == "value" and parent == "env[]" and v == SOURCE_PRODUCT:
                continue
            found.extend(source_name_references(v, here, k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            found.extend(source_name_references(v, f"{path}[{i}]", parent + "[]"))
    elif isinstance(node, str) and _source_name_left(node):
        found.append(path)
    return found


# ---- the check ---------------------------------------------------------------------------------------------------------

def check(objects: list[dict], contracts: dict, release: bool = False,
          product: str = SOURCE_PRODUCT) -> tuple[list[str], list[str]]:
    """Returns (failures, notes). `objects` and `contracts` are already under the product name (rename_objects,
    rename_contracts)."""
    failures: list[str] = []
    notes: list[str] = []
    fail = lambda obj, msg: failures.append(f"{ident(obj)}: {msg}")  # noqa: E731
    build_namespaces = {f"{product}-build"}

    secret_contract = {n: set(v["keys"]) for n, v in contracts.get("secrets", {}).items()}
    configmap_contract = {n: set(v["keys"]) for n, v in contracts.get("configMaps", {}).items()}
    rendered_configmaps = {
        (o["metadata"].get("namespace"), o["metadata"]["name"]): set((o.get("data") or {}) | (o.get("binaryData") or {}))
        for o in objects if o.get("kind") == "ConfigMap"}
    rendered_claims = {(o["metadata"].get("namespace"), o["metadata"]["name"])
                       for o in objects if o.get("kind") == "PersistentVolumeClaim"}

    # neXus's objects are out of bounds (ADR-001 §7, NS-1): the whole object, keys and values (PR 18 review D-04).
    for obj in objects:
        where = nexus_references(obj)
        if where:
            fail(obj, f"names a ui2* (neXus) object, namespace, label or repository (a ui2* or nexus* token) at "
                      f"{', '.join(where[:5])}")
    # PO 2026-10-31: under another product name nothing rendered still names the source product.
    if product != SOURCE_PRODUCT:
        for obj in objects:
            where = source_name_references(obj)
            if where:
                fail(obj, f"still names {SOURCE_PRODUCT} under product {product} at {', '.join(where[:5])}")

    # Priority classes.
    rwsafe_classes = set()
    for obj in objects:
        if obj.get("kind") != "PriorityClass":
            continue
        if obj.get("metadata", {}).get("labels", {}).get(PART_OF) != product:
            fail(obj, f"PriorityClass is not labelled part-of {product}")
            continue
        rwsafe_classes.add(obj["metadata"]["name"])
        if int(obj.get("value", 0)) >= NEXUS_SERVICE_PRIORITY:
            fail(obj, f"value {obj.get('value')} is not below neXus's service class ({NEXUS_SERVICE_PRIORITY})")
        if int(obj.get("value", 0)) > RWSAFE_PRIORITY_CEILING:
            fail(obj, f"value {obj.get('value')} is above the rwsafe ceiling {RWSAFE_PRIORITY_CEILING} (PO decision Q-10)")
        if obj.get("preemptionPolicy") != "Never":
            fail(obj, "preemptionPolicy is not Never")
        if obj.get("globalDefault"):
            fail(obj, "globalDefault is true")

    workloads = []
    for obj in objects:
        kind = obj.get("kind")
        if kind == "Secret":
            fail(obj, "a Secret is rendered; Secrets are created by the operator from the contract, never applied")
        if kind == "ServiceAccount" and obj.get("automountServiceAccountToken") is not False:
            fail(obj, "ServiceAccount automountServiceAccountToken is not false")
        if kind == "Namespace":
            labels = obj["metadata"].get("labels") or {}
            enforce = labels.get(PSA + "enforce")
            allowed = {"restricted", "baseline"} if obj["metadata"]["name"] in build_namespaces else {"restricted"}
            if labels.get(PART_OF) != product:
                fail(obj, f"Namespace is not labelled part-of {product}")
            if enforce not in allowed:
                fail(obj, f"PSA enforce is {enforce or 'unset'}, not {' or '.join(sorted(allowed, reverse=True))}")
            for mode in ("audit", "warn"):
                if labels.get(PSA + mode) != "restricted":
                    fail(obj, f"PSA {mode} is not restricted")
        if kind == "ConfigMap" and obj["metadata"]["name"] in configmap_contract:
            fail(obj, "an uncommitted contract ConfigMap is rendered; its values never live in the repository")
        if kind == "Service":
            spec = obj.get("spec", {})
            if spec.get("type") == "NodePort" or any(p.get("nodePort") for p in spec.get("ports", [])
                                                     if spec.get("type") != "LoadBalancer"):
                fail(obj, "NodePort Service")
            if spec.get("externalIPs"):
                fail(obj, "externalIPs set")
            for p in spec.get("ports", []):
                if spec.get("type") == "LoadBalancer" and p.get("port") in HOST_PORTS_IN_USE:
                    fail(obj, f"LoadBalancer port {p.get('port')} is already in use on the host")
                if p.get("port") in NEXUS_CLUSTER_PORTS or p.get("targetPort") in NEXUS_CLUSTER_PORTS:
                    fail(obj, f"port {p.get('port')} is one of neXus's cluster ports")
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
            # ADR-001 §3: no tolerations at all. A toleration without a key tolerates every taint, disk pressure included.
            if t.get("key") in ("node.kubernetes.io/disk-pressure", None, ""):
                fail(obj, "tolerates disk pressure")
            else:
                fail(obj, f"tolerates taint {t.get('key')} (no tolerations, ADR-001 §3)")
        for flag in ("hostNetwork", "hostPID", "hostIPC"):
            if spec.get(flag):
                fail(obj, f"{flag} is true")
        if spec.get("automountServiceAccountToken") is not False:
            fail(obj, "automountServiceAccountToken is not false")
        pod_sc = spec.get("securityContext") or {}
        for field in ("runAsUser", "runAsGroup"):
            if field in pod_sc:
                fail(obj, f"pod {field} {pod_sc[field]} is fixed (arbitrary-UID images, ADR-001 §6)")
        if (pod_sc.get("seccompProfile") or {}).get("type") not in (None, "RuntimeDefault"):
            fail(obj, "pod seccomp profile is not RuntimeDefault")

        for vol in spec.get("volumes") or []:
            if "hostPath" in vol:
                fail(obj, f"volume {vol.get('name')} is a hostPath")
            if "emptyDir" in vol:
                ed = vol["emptyDir"] or {}
                cap = BUILD_EMPTYDIR_CAP if ns in build_namespaces else EMPTYDIR_CAP
                if not ed.get("sizeLimit"):
                    fail(obj, f"emptyDir {vol.get('name')} has no sizeLimit")
                elif quantity(ed["sizeLimit"]) > cap:
                    fail(obj, f"emptyDir {vol.get('name')} sizeLimit {ed['sizeLimit']} is above the cap "
                              f"{'4Gi' if cap == BUILD_EMPTYDIR_CAP else '512Mi'}")
                if ed.get("medium") == "Memory":
                    fail(obj, f"emptyDir {vol.get('name')} is memory-backed")
            if "secret" in vol:
                src = vol["secret"]
                check_ref(obj, fail, "Secret", src.get("secretName"), [i["key"] for i in src.get("items") or []],
                          secret_contract, None, ns, src.get("optional"))
            if "configMap" in vol:
                src = vol["configMap"]
                check_ref(obj, fail, "ConfigMap", src.get("name"), [i["key"] for i in src.get("items") or []],
                          configmap_contract, rendered_configmaps, ns, src.get("optional"))
            if "persistentVolumeClaim" in vol:
                claim = (vol["persistentVolumeClaim"] or {}).get("claimName")
                if (ns, claim) not in rendered_claims:
                    fail(obj, f"volume {vol.get('name')} claims PVC {claim}, which the render does not hold")
            for proj in (vol.get("projected") or {}).get("sources", []):
                # PR 27 review D-05: a projected Secret or ConfigMap is a reference like any other.
                if "secret" in proj:
                    src = proj["secret"] or {}
                    check_ref(obj, fail, "Secret", src.get("name"), [i["key"] for i in src.get("items") or []],
                              secret_contract, None, ns, src.get("optional"))
                if "configMap" in proj:
                    src = proj["configMap"] or {}
                    check_ref(obj, fail, "ConfigMap", src.get("name"), [i["key"] for i in src.get("items") or []],
                              configmap_contract, rendered_configmaps, ns, src.get("optional"))
                if "serviceAccountToken" in proj:
                    fail(obj, f"volume {vol.get('name')} projects a ServiceAccount token")

        for c in containers(spec):
            cname = f"container {c.get('name')}"
            image = c.get("image", "")
            if image.endswith(":latest") or ("@" not in image and ":" not in image.rsplit("/", 1)[-1]):
                fail(obj, f"{cname}: image is `latest` or untagged")
            if image.startswith(IN_CLUSTER_REGISTRY + "/"):
                repository = image[len(IN_CLUSTER_REGISTRY) + 1:].split("@", 1)[0].split(":", 1)[0]
                if not repository.startswith(product + "-"):
                    fail(obj, f"{cname}: in-cluster registry repository {repository} is not a {product}-* repository")
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
            for field in ("runAsUser", "runAsGroup"):
                if field in sc:
                    fail(obj, f"{cname}: {field} {sc[field]} is fixed (arbitrary-UID images, ADR-001 §6)")
            seccomp = (sc.get("seccompProfile") or pod_sc.get("seccompProfile") or {}).get("type")
            if seccomp != "RuntimeDefault":
                fail(obj, f"{cname}: seccomp profile is not RuntimeDefault")
            for p in c.get("ports") or []:
                if p.get("hostPort"):
                    fail(obj, f"{cname}: hostPort {p.get('hostPort')}")
                if p.get("containerPort") in NEXUS_CLUSTER_PORTS:
                    fail(obj, f"{cname}: containerPort {p.get('containerPort')} is one of neXus's cluster ports")
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
    # The deploy's estate patch replaces each placeholder by text (DEPLOY_AND_SHARED_HOST_RUNBOOK §7.4), so one
    # placeholder in two policies would give two destinations (the directory, the SIEM) one estate value.
    placeholder_users: dict[str, set[str]] = {}
    for p in policies:
        # A rule without peers admits every source (ingress) or reaches every address (egress) (PR 27 review D-03).
        for direction, peers_key, what in (("ingress", "from", "a source (`from`) admits every peer"),
                                           ("egress", "to", "a destination (`to`) reaches every address")):
            for rule in p["spec"].get(direction) or []:
                if not rule.get(peers_key):
                    fail(p, f"{direction} rule without {what}")
        for direction, peers_key in (("ingress", "from"), ("egress", "to")):
            for rule in p["spec"].get(direction) or []:
                for peer in rule.get(peers_key) or []:
                    if not peer:
                        fail(p, f"{direction} peer is empty and matches everything")
                        continue
                    for selector in ("namespaceSelector", "podSelector"):
                        if selector in peer and empty_selector(peer[selector]) \
                                and ident(p) not in EMPTY_SELECTOR_EXCEPTIONS:
                            fail(p, f"{direction} peer has an empty {selector}, which matches every "
                                    f"{'namespace' if selector == 'namespaceSelector' else 'pod'}")
                    if "ipBlock" not in peer:
                        continue
                    # PR 27 review D-01: an empty estate value renders `cidr:` (null); never skipped.
                    cidr = (peer.get("ipBlock") or {}).get("cidr")
                    if not cidr:
                        fail(p, f"{direction} ipBlock has no cidr (an empty estate value)")
                        continue
                    try:
                        net = ipaddress.ip_network(cidr, strict=False)
                    except ValueError:
                        fail(p, f"{direction} ipBlock cidr is not a network")
                        continue
                    if net.prefixlen == 0:
                        fail(p, f"{direction} ipBlock {cidr} is every address")
                    elif documentation_range(net):
                        placeholder_users.setdefault(cidr, set()).add(ident(p))
                        if release:
                            fail(p, f"{direction} ipBlock is a documentation-range placeholder in a release render")
                        else:
                            notes.append(f"{ident(p)}: {direction} ipBlock is a documentation-range placeholder "
                                         f"(the deploy's estate patch sets the real addresses)")
    for cidr, users in sorted(placeholder_users.items()):
        if len(users) > 1:
            failures.append(f"documentation-range placeholder {cidr} is shared by {', '.join(sorted(users))}; each "
                            f"estate value needs its own placeholder")
    for obj, labels, _ in workloads:
        ns = obj["metadata"].get("namespace")
        own = [p for p in policies if p["metadata"].get("namespace") == ns and (p["spec"].get("podSelector") or {})
               and selects(p["spec"]["podSelector"], labels)]
        if not own:
            fail(obj, "no NetworkPolicy selects this workload's pods")

    # PodDisruptionBudgets for multi-replica workloads, each keeping a pod and allowing an eviction (PR 18 review D-05).
    pdbs = [o for o in objects if o.get("kind") == "PodDisruptionBudget"]
    for pdb in pdbs:
        ns = pdb["metadata"].get("namespace")
        selected = [(o, l) for o, l, _ in workloads if o["metadata"].get("namespace") == ns
                    and (pdb["spec"].get("selector") or {}) and selects(pdb["spec"]["selector"], l)]
        if not selected:
            fail(pdb, "PodDisruptionBudget selects no workload")
        for obj, _ in selected:
            replicas = int(obj.get("spec", {}).get("replicas", 1))
            spec = pdb["spec"]
            if "minAvailable" in spec:
                m = pdb_count(spec["minAvailable"], replicas, True)
                if not 1 <= m < replicas:
                    fail(pdb, f"minAvailable {spec['minAvailable']} is not between 1 and {ident(obj)}'s replicas - 1")
            elif "maxUnavailable" in spec:
                u = pdb_count(spec["maxUnavailable"], replicas, False)
                if not 1 <= u < replicas:
                    fail(pdb, f"maxUnavailable {spec['maxUnavailable']} is not between 1 and {ident(obj)}'s replicas - 1")
            else:
                fail(pdb, "PodDisruptionBudget sets neither minAvailable nor maxUnavailable")
    for obj, labels, _ in workloads:
        if obj.get("kind") in ("Deployment", "StatefulSet") and int(obj.get("spec", {}).get("replicas", 1)) >= 2:
            ns = obj["metadata"].get("namespace")
            if not any(p["metadata"].get("namespace") == ns and selects(p["spec"].get("selector") or {}, labels)
                       for p in pdbs):
                fail(obj, "replicas >= 2 without a PodDisruptionBudget")

    # Every rendered namespace has a ResourceQuota and a LimitRange (ADR-001 §3).
    rendered_namespaces = {o["metadata"]["name"] for o in objects if o.get("kind") == "Namespace"} | {
        o["metadata"].get("namespace") for o in objects if o.get("metadata", {}).get("namespace")}
    for ns in sorted(rendered_namespaces):
        for kind in ("ResourceQuota", "LimitRange"):
            if not any(o.get("kind") == kind and o["metadata"].get("namespace") == ns for o in objects):
                failures.append(f"Namespace/{ns}: no {kind}")

    # LimitRange maximum and ResourceQuota fit.
    for lr in (o for o in objects if o.get("kind") == "LimitRange"):
        ns = lr["metadata"].get("namespace")
        for limit in lr["spec"].get("limits", []):
            if limit.get("type") == "PersistentVolumeClaim" and (limit.get("max") or {}).get("storage"):
                mx = limit["max"]["storage"]
                for pvc in (o for o in objects if o.get("kind") == "PersistentVolumeClaim"
                            and o["metadata"].get("namespace") == ns):
                    storage = pvc["spec"].get("resources", {}).get("requests", {}).get("storage", "0")
                    if quantity(storage) > quantity(mx):
                        fail(pvc, f"requests.storage {storage} above LimitRange PVC max {mx}")
                # PR 27 review D-05: a StatefulSet's claim templates become PVCs under the same maximum.
                for obj, _, _ in workloads:
                    if obj["metadata"].get("namespace") != ns or obj.get("kind") != "StatefulSet":
                        continue
                    for vct in obj["spec"].get("volumeClaimTemplates") or []:
                        storage = (vct.get("spec") or {}).get("resources", {}).get("requests", {}).get("storage", "0")
                        if quantity(storage) > quantity(mx):
                            fail(obj, f"volumeClaimTemplate {vct.get('metadata', {}).get('name')}: requests.storage "
                                      f"{storage} above LimitRange PVC max {mx}")
                continue
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
            for key, value in pod_resources(spec).items():
                used[key] = used.get(key, 0) + n * value
            if obj.get("kind") == "StatefulSet":
                replicas = int(obj["spec"].get("replicas", 1))
                for vct in obj["spec"].get("volumeClaimTemplates") or []:
                    storage = (vct.get("spec") or {}).get("resources", {}).get("requests", {}).get("storage", "0")
                    used["persistentvolumeclaims"] = used.get("persistentvolumeclaims", 0) + replicas
                    used["requests.storage"] = used.get("requests.storage", 0) + replicas * quantity(storage)
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

    # PR 27 review D-06: every PVC and claim template of every rendered namespace together within the host's free disk.
    requested = sum(quantity(o["spec"].get("resources", {}).get("requests", {}).get("storage", "0"))
                    for o in objects if o.get("kind") == "PersistentVolumeClaim")
    for obj, _, _ in workloads:
        if obj.get("kind") == "StatefulSet":
            requested += int(obj["spec"].get("replicas", 1)) * sum(
                quantity((v.get("spec") or {}).get("resources", {}).get("requests", {}).get("storage", "0"))
                for v in obj["spec"].get("volumeClaimTemplates") or [])
    if requested > HOST_FREE_STORAGE_BUDGET:
        failures.append(f"requested storage of all namespaces is {requested / 2**30:g}Gi, above the host-free budget "
                        f"{HOST_FREE_STORAGE_BUDGET / 2**30:g}Gi (HOSTA_MEASUREMENT_2026_10_31)")
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
    ap.add_argument("--product", help="the deployed product name (default: deploy/rwsafe/product.env); an overlay "
                                      "render is renamed to it, a --rendered file must already carry it")
    args = ap.parse_args(argv)
    product = args.product or default_product()
    refused = validate_product(product)
    if refused:
        print(f"FAIL  product name {product!r} {refused}")
        return 2
    if args.rendered:
        text, tool = args.rendered.read_text(), f"file {args.rendered.name}"
        objects = to_objects(text)
    else:
        text, tool = render(args.overlay)
        objects = rename_objects(to_objects(text), product)
    contracts = rename_contracts(json.loads(args.contracts.read_text()), product)
    failures, notes = check(objects, contracts, release=args.release, product=product)
    for n in notes:
        print(f"note  {n}")
    for f in failures:
        print(f"FAIL  {f}")
    workloads = sum(1 for o in objects if pod_template(o) is not None)
    verdict = "FAIL" if failures or workloads == 0 else "PASS"
    if workloads == 0:
        print("FAIL  the render holds no workload")
    print(f"manifest check {verdict}: {len(objects)} objects, {workloads} workloads, {len(failures)} failure(s); "
          f"product {product}; rendered with {tool}")
    return 1 if verdict == "FAIL" else 0


if __name__ == "__main__":
    sys.exit(main())
