#!/usr/bin/env python3
"""Render a deploy target under the product name, with the built image digests (docs/operations/PILOT_RUNBOOK.md).

The committed manifests are written with `rwsafe`; the product's deployed name is set in one place,
deploy/rwsafe/product.env (PO, 2026-10-31), and this wrapper renames every cluster-visible name to it
(tools/deploy/manifest_check.rename_objects): namespaces, PriorityClasses, ServiceAccounts, Services, PVCs, Secret and
ConfigMap names, the part-of label, selectors, in-cluster Service DNS names and registry repositories.

Targets:
  pilot  deploy/rwsafe/overlays/pilot (default)
  k3s    deploy/rwsafe/overlays/k3s
  build  deploy/rwsafe/build (the kaniko Jobs and their context loader)

For `pilot` and `k3s` the whole render passes the manifest check first (with --release semantics when both digests are
given) and nothing is printed otherwise; `build` passes its own build check. The output is one JSON `List` that
`kubectl apply --server-side -f` reads; `--kinds` keeps only the named kinds (the isolation step applies Namespaces,
PriorityClasses, ResourceQuotas and LimitRanges before anything else). Nothing here contacts a cluster: kubectl runs
offline (KUBECONFIG=/dev/null). No value of an estate, Secret or address is ever part of a render.

Standard library only; needs kubectl (or kustomize) on PATH.

Usage: python3 -B tools/pilot/render.py [--target pilot|k3s|build] [--product NAME]
           [--dataplane-digest sha256:<64 hex>] [--control-digest sha256:<64 hex>] [--kinds Kind,Kind] [--output FILE]
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
    "build": mc.REPO_ROOT / "deploy/rwsafe/build",
}
DIGEST_VALUE = re.compile(r"^sha256:[0-9a-f]{64}$")
# The images the deploy pins, by their source (committed) repository name.
IMAGES = {"dataplane": f"{mc.IN_CLUSTER_REGISTRY}/{mc.SOURCE_PRODUCT}-dataplane",
          "control": f"{mc.IN_CLUSTER_REGISTRY}/{mc.SOURCE_PRODUCT}-control"}


class Refused(Exception):
    pass


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


def check_build(objects: list[dict], product: str) -> list[str]:
    """The build target's rules: Jobs and the loader in `<product>-build`, digest-pinned images, every kaniko
    destination a `<product>-*` repository of the in-cluster registry, no Secret, no token, the batch class, and no
    neXus name or leftover source name."""
    failures: list[str] = []
    namespace = f"{product}-build"
    for obj in objects:
        where = mc.ident(obj)
        if obj.get("kind") == "Secret":
            failures.append(f"{where}: a Secret is rendered")
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
        for c in mc.containers(spec):
            if not mc.DIGEST.search(c.get("image", "")):
                failures.append(f"{where}: container {c.get('name')}: image is not pinned by digest")
            for arg in c.get("args") or []:
                if arg.startswith("--destination="):
                    target = arg.split("=", 1)[1]
                    if not target.startswith(f"{mc.IN_CLUSTER_REGISTRY}/{product}-"):
                        failures.append(f"{where}: destination is not a {product}-* repository of the in-cluster "
                                        f"registry")
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
    if target == "build":
        objects = mc.rename_objects(objects, product)
        failures = check_build(objects, product)
    else:
        if digests and set_digests(objects, digests) == 0:
            raise Refused("no placeholder digest matched the given images")
        objects = mc.rename_objects(objects, product)
        contracts = mc.rename_contracts(json.loads(contracts_file.read_text()), product)
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
