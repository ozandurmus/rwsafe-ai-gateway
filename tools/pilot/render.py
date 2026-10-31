#!/usr/bin/env python3
"""Render a deploy target under the product name, with the built image digests (docs/operations/PILOT_RUNBOOK.md).

The committed manifests are written with `rwsafe`; the product's deployed name is set in one place,
deploy/rwsafe/product.env (PO, 2026-10-31), and this wrapper renames every cluster-visible name to it
(tools/deploy/manifest_check.rename_objects): namespaces, PriorityClasses, ServiceAccounts, Services, PVCs, Secret and
ConfigMap names, the part-of label, selectors, in-cluster Service DNS names and registry repositories.

Targets:
  pilot  deploy/rwsafe/overlays/pilot (default)
  k3s    deploy/rwsafe/overlays/k3s
  build  deploy/rwsafe/image-build (the kaniko Jobs and their context loader)

For `pilot` and `k3s` the whole render passes the manifest check first (with --release semantics when both digests are
given) and nothing is printed otherwise; `build` passes its own build check. The output is one JSON `List` that
`kubectl apply --server-side -f` reads; `--kinds` keeps only the named kinds (the isolation step applies Namespaces,
PriorityClasses, ResourceQuotas and LimitRanges before anything else). Nothing here contacts a cluster: kubectl runs
offline (KUBECONFIG=/dev/null). No value of an estate, Secret or address is ever part of a render.

Standard library only; needs kubectl (or kustomize) on PATH.

Usage: python3 -B tools/pilot/render.py [--target pilot|k3s|build] [--product NAME]
           [--dataplane-digest sha256:<64 hex>] [--control-digest sha256:<64 hex>] [--kinds Kind,Kind]
           [--phase all|control|icap] [--output FILE]
       exit 0 rendered, 1 refused (the reason is printed on stderr), 2 usage
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "deploy"))
import manifest_check as mc  # noqa: E402

TARGETS = {
    "pilot": mc.REPO_ROOT / "deploy/rwsafe/overlays/pilot",
    "k3s": mc.REPO_ROOT / "deploy/rwsafe/overlays/k3s",
    "build": mc.REPO_ROOT / "deploy/rwsafe/image-build",
}
DIGEST_VALUE = re.compile(r"^sha256:[0-9a-f]{64}$")
# The images the deploy pins, by their source (committed) repository name.
IMAGES = {"dataplane": f"{mc.IN_CLUSTER_REGISTRY}/{mc.SOURCE_PRODUCT}-dataplane",
          "control": f"{mc.IN_CLUSTER_REGISTRY}/{mc.SOURCE_PRODUCT}-control"}


class Refused(Exception):
    pass


def icap_object(obj: dict, product: str) -> bool:
    """True for an object of the ICAP step (PILOT_RUNBOOK.md step 12): the ICAP engine's Deployment, Services, PDB,
    ConfigMap, ServiceAccount and NetworkPolicies, and every LoadBalancer Service (the one that opens 1344 on the node).
    PR 33 review D-05: the control step (9) applies everything else, before the firewall rule of step 11 exists."""
    md = obj.get("metadata") or {}
    labels = md.get("labels") or {}
    return (labels.get("app.kubernetes.io/component") == "icap"
            or str(labels.get("app.kubernetes.io/name", "")).startswith(f"{product}-icap")
            or str(md.get("name", "")).startswith(f"{product}-icap")
            or (obj.get("kind") == "Service" and (obj.get("spec") or {}).get("type") == "LoadBalancer"))


def select_phase(objects: list[dict], product: str, phase: str) -> list[dict]:
    """`control`: every object but the ICAP step's; `icap`: only those; `all`: everything."""
    if phase == "control":
        out = [o for o in objects if not icap_object(o, product)]
        if any(o.get("kind") == "Service" and (o.get("spec") or {}).get("type") == "LoadBalancer" for o in out):
            raise Refused("the control phase would hold a LoadBalancer Service")
        return out
    if phase == "icap":
        return [o for o in objects if icap_object(o, product)]
    return objects


def set_digests(objects: list[dict], digests: dict[str, str]) -> int:
    """Replaces the placeholder digest of each named image; returns how many containers changed."""
    changed = 0
    for obj in objects:
        tpl = mc.pod_template(obj)
        if tpl is None:
            continue
        for c in mc.containers(tpl[1]):
            image = c.get("image", "")
            for name, digest in digests.items():
                if image == f"{IMAGES[name]}@{mc.ZERO_DIGEST}":
                    c["image"] = f"{IMAGES[name]}@{digest}"
                    changed += 1
    return changed


PROXY_ARGS = ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "GRADLE_OPTS")


def _build_contract(contracts: dict) -> dict[str, set[str]]:
    return {n: set(v.get("keys") or []) for n, v in ((contracts.get("build") or {}).get("configMaps") or {}).items()}


def _check_kaniko_args(where: str, args: list[str], product: str, proxy_keys: set[str]) -> list[str]:
    """PR 33 review D-02, D-03: one explicit `--destination=<registry>/<product>-*`, no short or split form, no
    blanket TLS skip, and proxy settings only as `--build-arg=KEY=$(KEY)` (expanded from the uncommitted ConfigMap at
    run time, never a literal in the manifest)."""
    failures: list[str] = []
    destinations = [a.split("=", 1)[1] for a in args if a.startswith("--destination=")]
    if len(destinations) != 1:
        failures.append(f"{where}: needs exactly one --destination=<repository> argument, has {len(destinations)}")
    for target in destinations:
        if not target.startswith(f"{mc.IN_CLUSTER_REGISTRY}/{product}-"):
            failures.append(f"{where}: destination is not a {product}-* repository of the in-cluster registry")
    for a in args:
        if a in ("-d", "--destination") or a.startswith("-d="):
            failures.append(f"{where}: destination given in a short or split form ({a.split('=', 1)[0]})")
        if a in ("--insecure", "--skip-tls-verify") or a.startswith(("--insecure=", "--skip-tls-verify=")):
            failures.append(f"{where}: {a.split('=', 1)[0]} relaxes TLS for every registry")
        if a.startswith("--insecure-registry=") and a.split("=", 1)[1] != mc.IN_CLUSTER_REGISTRY:
            failures.append(f"{where}: --insecure-registry names another registry than the in-cluster one")
        if a.startswith("--cache-repo=") and not a.split("=", 1)[1].startswith(f"{mc.IN_CLUSTER_REGISTRY}/{product}-"):
            failures.append(f"{where}: --cache-repo is not a {product}-* repository")
        if a == "--build-arg":
            failures.append(f"{where}: --build-arg given in a split form")
        if a.startswith("--build-arg="):
            key, _, value = a.split("=", 1)[1].partition("=")
            if key not in proxy_keys or value != f"$({key})":
                failures.append(f"{where}: --build-arg {key} is not KEY=$(KEY) of a proxy key of the build contract")
    return failures


def check_build(objects: list[dict], product: str, contracts: dict) -> list[str]:
    """The build target's rules (PR 33 review D-02): the objects in `<product>-build` and labelled part-of the product;
    no Secret and no contract ConfigMap rendered; every ConfigMap reference in the build contract (or rendered) with its
    keys; no Secret reference; the pod and container rules the runtime check applies, with the one documented `baseline`
    relaxation for kaniko (root, writable root filesystem, default capabilities); images pinned by a real digest; the
    kaniko arguments of _check_kaniko_args; no neXus name and no leftover source name."""
    failures: list[str] = []
    namespace = f"{product}-build"
    contract = _build_contract(contracts)
    proxy_keys = set(contract.get(f"{product}-build-proxy", set()))
    rendered_cms = {o["metadata"]["name"]: set((o.get("data") or {}) | (o.get("binaryData") or {}))
                    for o in objects if o.get("kind") == "ConfigMap"}
    claims = {o["metadata"]["name"] for o in objects if o.get("kind") == "PersistentVolumeClaim"}

    def ref(where: str, name: str | None, keys: list[str], optional) -> None:
        if not name:
            failures.append(f"{where}: ConfigMap reference without a name")
        elif name in contract:
            missing = [k for k in keys if k not in contract[name]]
            if missing:
                failures.append(f"{where}: ConfigMap {name}: key(s) {', '.join(missing)} not in the build contract")
        elif name in rendered_cms:
            missing = [k for k in keys if k not in rendered_cms[name]]
            if missing:
                failures.append(f"{where}: ConfigMap {name}: key(s) {', '.join(missing)} not rendered")
        else:
            failures.append(f"{where}: ConfigMap {name} is neither rendered nor in the build contract")

    for obj in objects:
        where = mc.ident(obj)
        kind = obj.get("kind")
        if kind == "Secret":
            failures.append(f"{where}: a Secret is rendered")
        if kind == "ConfigMap" and obj["metadata"]["name"] in contract:
            failures.append(f"{where}: an uncommitted build contract ConfigMap is rendered")
        if obj.get("metadata", {}).get("namespace") != namespace:
            failures.append(f"{where}: not in namespace {namespace}")
        if obj.get("metadata", {}).get("labels", {}).get(mc.PART_OF) != product:
            failures.append(f"{where}: not labelled part-of {product}")
        if mc.nexus_references(obj):
            failures.append(f"{where}: names a ui2* or nexus* (neXus) object")
        if product != mc.SOURCE_PRODUCT and mc.source_name_references(obj):
            failures.append(f"{where}: still names {mc.SOURCE_PRODUCT} under product {product}")
        tpl = mc.pod_template(obj)
        if tpl is None:
            continue
        spec = tpl[1]
        if spec.get("automountServiceAccountToken") is not False:
            failures.append(f"{where}: automountServiceAccountToken is not false")
        if spec.get("priorityClassName") != f"{product}-batch":
            failures.append(f"{where}: priorityClassName is not {product}-batch")
        for flag in ("hostNetwork", "hostPID", "hostIPC"):
            if spec.get(flag):
                failures.append(f"{where}: {flag} is true")
        if spec.get("tolerations"):
            failures.append(f"{where}: carries tolerations (no tolerations, ADR-001 §3)")
        pod_sc = spec.get("securityContext") or {}
        for field in ("runAsUser", "runAsGroup"):
            if field in pod_sc:
                failures.append(f"{where}: pod {field} is fixed")
        for vol in spec.get("volumes") or []:
            if "hostPath" in vol:
                failures.append(f"{where}: volume {vol.get('name')} is a hostPath")
            if "secret" in vol or any("secret" in s or "serviceAccountToken" in s
                                      for s in (vol.get("projected") or {}).get("sources", [])):
                failures.append(f"{where}: volume {vol.get('name')} mounts a Secret or a token")
            if "emptyDir" in vol:
                ed = vol["emptyDir"] or {}
                if not ed.get("sizeLimit") or mc.quantity(ed["sizeLimit"]) > mc.BUILD_EMPTYDIR_CAP:
                    failures.append(f"{where}: emptyDir {vol.get('name')} has no sizeLimit of at most 4Gi")
                if ed.get("medium") == "Memory":
                    failures.append(f"{where}: emptyDir {vol.get('name')} is memory-backed")
            if "configMap" in vol:
                src = vol["configMap"] or {}
                ref(where, src.get("name"), [i["key"] for i in src.get("items") or []], src.get("optional"))
            if "persistentVolumeClaim" in vol and (vol["persistentVolumeClaim"] or {}).get("claimName") not in claims:
                failures.append(f"{where}: volume {vol.get('name')} claims a PVC the render does not hold")
        for c in mc.containers(spec):
            cw = f"{where}: container {c.get('name')}"
            image = c.get("image", "")
            if not mc.DIGEST.search(image):
                failures.append(f"{cw}: image is not pinned by digest")
            elif image.endswith(mc.ZERO_DIGEST):
                failures.append(f"{cw}: image has the placeholder digest")
            sc = c.get("securityContext") or {}
            if sc.get("privileged"):
                failures.append(f"{cw}: privileged")
            if sc.get("allowPrivilegeEscalation") is not False:
                failures.append(f"{cw}: allowPrivilegeEscalation is not false")
            if (sc.get("capabilities") or {}).get("add"):
                failures.append(f"{cw}: capabilities added")
            for field in ("runAsUser", "runAsGroup"):
                if field in sc:
                    failures.append(f"{cw}: {field} is fixed")
            if (sc.get("seccompProfile") or pod_sc.get("seccompProfile") or {}).get("type") != "RuntimeDefault":
                failures.append(f"{cw}: seccomp profile is not RuntimeDefault")
            for p in c.get("ports") or []:
                if p.get("hostPort"):
                    failures.append(f"{cw}: hostPort")
            res = c.get("resources") or {}
            for part in ("requests", "limits"):
                for r in ("cpu", "memory"):
                    if r not in (res.get(part) or {}):
                        failures.append(f"{cw}: no {part}.{r}")
            for env in c.get("env") or []:
                vf = env.get("valueFrom") or {}
                if "secretKeyRef" in vf:
                    failures.append(f"{cw}: env {env.get('name')} reads a Secret")
                if "configMapKeyRef" in vf:
                    ref(cw, vf["configMapKeyRef"].get("name"), [vf["configMapKeyRef"].get("key")],
                        vf["configMapKeyRef"].get("optional"))
                if env.get("name") in PROXY_ARGS and "value" in env:
                    failures.append(f"{cw}: env {env.get('name')} is a literal (proxy settings come from the contract)")
            for src in c.get("envFrom") or []:
                if "secretRef" in src:
                    failures.append(f"{cw}: envFrom reads a Secret")
                if "configMapRef" in src:
                    ref(cw, src["configMapRef"].get("name"), [], src["configMapRef"].get("optional"))
            if obj.get("kind") == "Job":
                failures.extend(_check_kaniko_args(cw, c.get("args") or [], product, proxy_keys))
    return failures


def render_target(target: str, product: str, digests: dict[str, str] | None = None,
                  contracts_file: Path = mc.DEFAULT_CONTRACTS) -> list[dict]:
    """The renamed, checked objects of a target; raises Refused with the reason."""
    refused = mc.validate_product(product)
    if refused:
        raise Refused(f"product name {product!r} {refused}")
    digests = digests or {}
    for name, digest in digests.items():
        if not DIGEST_VALUE.match(digest or "") or digest == mc.ZERO_DIGEST:
            raise Refused(f"the {name} digest is not sha256:<64 hex> or is the placeholder")
    text, _ = mc.render(TARGETS[target])
    objects = mc.to_objects(text)
    contracts = mc.rename_contracts(json.loads(contracts_file.read_text()), product)
    if target == "build":
        objects = mc.rename_objects(objects, product)
        failures = check_build(objects, product, contracts)
    else:
        if digests and set_digests(objects, digests) == 0:
            raise Refused("no placeholder digest matched the given images")
        objects = mc.rename_objects(objects, product)
        release = set(digests) == set(IMAGES)
        failures, _ = mc.check(objects, contracts, release=release, product=product)
    if failures:
        raise Refused("the render fails its check:\n" + "\n".join(f"  {f}" for f in failures))
    return objects


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", choices=sorted(TARGETS), default="pilot")
    ap.add_argument("--product", help="default: the PRODUCT= line of deploy/rwsafe/product.env")
    ap.add_argument("--dataplane-digest")
    ap.add_argument("--control-digest")
    ap.add_argument("--kinds", help="comma-separated kinds to keep (default: every object)")
    ap.add_argument("--phase", choices=("all", "control", "icap"), default="all",
                    help="pilot and k3s only: `control` leaves out the ICAP step's objects (PILOT_RUNBOOK.md step 9)")
    ap.add_argument("--output", type=Path, help="write here instead of stdout")
    args = ap.parse_args(argv)
    product = args.product or mc.default_product()
    digests = {k: v for k, v in (("dataplane", args.dataplane_digest), ("control", args.control_digest)) if v}
    if digests and args.target == "build":
        print("render: digests apply to the pilot and k3s targets only", file=sys.stderr)
        return 2
    try:
        objects = render_target(args.target, product, digests)
    except Refused as e:
        print(f"render refused: {e}", file=sys.stderr)
        return 1
    if args.phase != "all":
        if args.target == "build":
            print("render: --phase applies to the pilot and k3s targets only", file=sys.stderr)
            return 2
        try:
            objects = select_phase(objects, product, args.phase)
        except Refused as e:
            print(f"render refused: {e}", file=sys.stderr)
            return 1
    if args.kinds:
        keep = {k.strip() for k in args.kinds.split(",") if k.strip()}
        objects = [o for o in objects if o.get("kind") in keep]
    placeholders = [mc.ident(o) for o in objects if mc.pod_template(o) is not None
                    and any(c.get("image", "").endswith(mc.ZERO_DIGEST) for c in mc.containers(mc.pod_template(o)[1]))]
    if placeholders:
        print("render refused: a workload still has the placeholder digest (" + ", ".join(placeholders) + "); give "
              "--dataplane-digest and --control-digest, or --kinds for the isolation objects", file=sys.stderr)
        return 1
    text = json.dumps({"apiVersion": "v1", "kind": "List", "items": objects}, indent=1) + "\n"
    if args.output:
        args.output.write_text(text)
    else:
        sys.stdout.write(text)
    kinds: dict[str, int] = {}
    for o in objects:
        kinds[o.get("kind")] = kinds.get(o.get("kind"), 0) + 1
    print(f"render: target {args.target}, product {product}, {len(objects)} objects ("
          + ", ".join(f"{n} {k}" for k, n in sorted(kinds.items())) + ")", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
