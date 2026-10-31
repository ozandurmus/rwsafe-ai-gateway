#!/usr/bin/env python3
"""Self-test of tools/pilot/render.py: the pilot and build targets render under the default and another product name,
pass their checks, take the built digests, and refuse what they must. Offline (kubectl with KUBECONFIG=/dev/null).

Usage: python3 -B tools/pilot/test_render.py
"""
from __future__ import annotations

import contextlib
import copy
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import render  # noqa: E402

mc = render.mc
DIGESTS = {"dataplane": "sha256:" + "a" * 64, "control": "sha256:" + "b" * 64}
_BUILD = {p: render.render_target("build", p) for p in ("rwsafe", "acme")}


def run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = render.main(argv)
    return rc, out.getvalue(), err.getvalue()


class PilotTarget(unittest.TestCase):
    def test_pilot_with_digests_is_releasable_under_both_names(self):
        for product in ("rwsafe", "acme"):
            with self.subTest(product):
                objects = render.render_target("pilot", product, DIGESTS)
                images = {c["image"] for o in objects if mc.pod_template(o)
                          for c in mc.containers(mc.pod_template(o)[1])}
                self.assertIn(f"{mc.IN_CLUSTER_REGISTRY}/{product}-dataplane@{DIGESTS['dataplane']}", images)
                self.assertIn(f"{mc.IN_CLUSTER_REGISTRY}/{product}-control@{DIGESTS['control']}", images)
                namespaces = {o["metadata"]["name"] for o in objects if o["kind"] == "Namespace"}
                self.assertEqual(namespaces, {product, f"{product}-build", f"{product}-security"})
                classes = {o["metadata"]["name"] for o in objects if o["kind"] == "PriorityClass"}
                self.assertEqual(classes, {f"{product}-dataplane", f"{product}-control", f"{product}-batch"})

    def test_pilot_shape(self):
        objects = render.render_target("pilot", "rwsafe", DIGESTS)
        text = json.dumps(objects)
        self.assertNotIn("11344", text)
        self.assertNotIn("RWSAFE_TLS_CERT", text)
        self.assertNotIn("RWSAFE_LDAP_URL", text)
        self.assertNotIn("rwsafe-icap-tls", text)
        self.assertNotIn("rwsafe-ldap-bind", text)
        policies = {o["metadata"]["name"] for o in objects if o["kind"] == "NetworkPolicy"}
        self.assertFalse({"rwsafe-control-to-directory", "rwsafe-control-to-siem",
                          "rwsafe-control-from-traefik"} & policies)
        self.assertFalse(any(o["kind"] == "Ingress" for o in objects))
        icap = next(o for o in objects if o["kind"] == "Deployment" and o["metadata"]["name"] == "rwsafe-icap")
        self.assertEqual(icap["spec"]["replicas"], 2)
        lb = next(o for o in objects if o["kind"] == "Service" and o["metadata"]["name"] == "rwsafe-icap-lb")
        self.assertEqual([p["port"] for p in lb["spec"]["ports"]], [1344])
        control_cm = next(o for o in objects if o["kind"] == "ConfigMap"
                          and o["metadata"]["name"] == "rwsafe-control-config")["data"]
        self.assertEqual(control_cm["RWSAFE_BREAK_GLASS_ENABLED"], "true")
        self.assertEqual(control_cm["RWSAFE_SIEM_ENABLED"], "false")
        self.assertEqual(control_cm["RWSAFE_CAPTURE_MODE"], "off")
        icap_cm = next(o for o in objects if o["kind"] == "ConfigMap"
                       and o["metadata"]["name"] == "rwsafe-icap-config")["data"]
        self.assertNotIn("RWSAFE_GROUP_CLAIM_ENCODING", icap_cm)
        self.assertEqual(icap_cm["RWSAFE_CAPTURE_MODE"], "off")
        seed = next(o for o in objects if o["kind"] == "ConfigMap"
                    and o["metadata"]["name"].startswith("rwsafe-policy-seed-"))
        self.assertIn("registry-seed.yaml", seed["data"])

    def test_bad_digest_and_bad_product_are_refused(self):
        with self.assertRaises(render.Refused):
            render.render_target("pilot", "rwsafe", {"dataplane": "sha256:" + "0" * 64, "control": DIGESTS["control"]})
        with self.assertRaises(render.Refused):
            render.render_target("pilot", "rwsafe", {"dataplane": "latest", "control": DIGESTS["control"]})
        for product in ("nexus", "ui2-x", "Bad"):
            with self.subTest(product), self.assertRaises(render.Refused):
                render.render_target("pilot", product, DIGESTS)

    def test_main_refuses_a_workload_with_the_placeholder_digest(self):
        rc, out, err = run(["--target", "pilot"])
        self.assertEqual(rc, 1)
        self.assertEqual(out, "")
        self.assertIn("placeholder digest", err)

    def test_main_isolation_objects_without_digests(self):
        rc, out, err = run(["--kinds", "Namespace,PriorityClass,ResourceQuota,LimitRange", "--product", "acme"])
        self.assertEqual(rc, 0, err)
        items = json.loads(out)["items"]
        self.assertEqual({o["kind"] for o in items}, {"Namespace", "PriorityClass", "ResourceQuota", "LimitRange"})
        self.assertTrue(all(o["metadata"]["name"].startswith("acme") or o["metadata"].get("namespace", "")
                            .startswith("acme") for o in items))

    def test_main_output_passes_the_release_check(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "app.json"
            rc, _, err = run(["--product", "acme", "--dataplane-digest", DIGESTS["dataplane"],
                              "--control-digest", DIGESTS["control"], "--output", str(target)])
            self.assertEqual(rc, 0, err)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = mc.main(["--rendered", str(target), "--release", "--product", "acme"])
            self.assertEqual(rc, 0, out.getvalue())


class BuildTarget(unittest.TestCase):
    def test_build_renders_under_both_names(self):
        for product, objects in _BUILD.items():
            with self.subTest(product):
                self.assertEqual(render.check_build(objects, product), [])
                jobs = [o for o in objects if o["kind"] == "Job"]
                self.assertEqual({j["metadata"]["name"] for j in jobs},
                                 {f"{product}-build-dataplane", f"{product}-build-control"})
                destinations = {a for j in jobs for c in mc.containers(mc.pod_template(j)[1]) for a in c["args"]
                                if a.startswith("--destination=")}
                self.assertEqual(destinations, {
                    f"--destination={mc.IN_CLUSTER_REGISTRY}/{product}-dataplane:$(IMAGE_TAG)",
                    f"--destination={mc.IN_CLUSTER_REGISTRY}/{product}-control:$(IMAGE_TAG)"})
                refs = json.dumps(objects)
                for name in ("build-config", "build-proxy", "build-ca", "build-context"):
                    self.assertIn(f'"{product}-{name}"', refs)
                self.assertTrue(all(o["metadata"]["namespace"] == f"{product}-build" for o in objects))

    def test_build_check_refuses_foreign_destination_secret_and_tag(self):
        cases = {
            "destination": lambda o: mc.containers(mc.pod_template(next(x for x in o if x["kind"] == "Job"))[1])[0]
            ["args"].__setitem__(2, f"--destination={mc.IN_CLUSTER_REGISTRY}/other-dataplane:x"),
            "tag": lambda o: mc.containers(mc.pod_template(next(x for x in o if x["kind"] == "Job"))[1])[0]
            .__setitem__("image", "gcr.io/kaniko-project/executor:latest"),
            "secret": lambda o: o.append({"apiVersion": "v1", "kind": "Secret", "metadata": {
                "name": "acme-x", "namespace": "acme-build", "labels": {mc.PART_OF: "acme"}}}),
            "token": lambda o: mc.pod_template(next(x for x in o if x["kind"] == "Job"))[1]
            .__setitem__("automountServiceAccountToken", True),
        }
        for name, mutate in cases.items():
            with self.subTest(name):
                objects = copy.deepcopy(_BUILD["acme"])
                mutate(objects)
                self.assertNotEqual(render.check_build(objects, "acme"), [])

    def test_digests_are_refused_for_the_build_target(self):
        rc, _, _ = run(["--target", "build", "--dataplane-digest", DIGESTS["dataplane"]])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main(verbosity=1)
