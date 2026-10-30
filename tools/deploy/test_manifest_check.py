#!/usr/bin/env python3
"""Self-test of the manifest check: the compliant fixture passes, every rule fails on a fixture or a one-field mutation
of it, and the committed k3s overlay passes. Standard library only; needs kubectl on PATH (offline: KUBECONFIG is
/dev/null, nothing reaches a cluster).

Usage: python3 -B tools/deploy/test_manifest_check.py
"""
from __future__ import annotations

import contextlib
import copy
import io
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import manifest_check as mc  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CONTRACTS = {"secrets": {"fixture-secret": {"keys": ["value"]}},
             "configMaps": {"fixture-estate": {"keys": ["names"]}}}
_COMPLIANT = mc.to_objects((FIXTURES / "compliant.yaml").read_text())
_VIOLATING = mc.to_objects((FIXTURES / "violating.yaml").read_text())


def compliant() -> list[dict]:
    return copy.deepcopy(_COMPLIANT)


def deployment(objects: list[dict]) -> dict:
    return next(o for o in objects if o["kind"] == "Deployment")


def pod(objects: list[dict]) -> dict:
    return deployment(objects)["spec"]["template"]["spec"]


def container(objects: list[dict]) -> dict:
    return pod(objects)["containers"][0]


class CompliantFixture(unittest.TestCase):
    def test_compliant_fixture_passes(self):
        failures, notes = mc.check(compliant(), CONTRACTS)
        self.assertEqual(failures, [])
        self.assertEqual(notes, [])


class ViolatingFixture(unittest.TestCase):
    def setUp(self):
        self.failures, _ = mc.check(copy.deepcopy(_VIOLATING), CONTRACTS)
        self.text = "\n".join(self.failures)

    def test_reports_every_violation(self):
        for expected in (
            "not below neXus's service class", "preemptionPolicy is not Never", "globalDefault is true",
            "a Secret is rendered", "NodePort Service", "no priorityClassName", "tolerates disk pressure",
            "hostNetwork is true", "automountServiceAccountToken is not false", "is a hostPath",
            "emptyDir scratch has no sizeLimit", "image is `latest`", "not pinned by digest", "privileged",
            "allowPrivilegeEscalation is not false", "readOnlyRootFilesystem is not true", "do not drop ALL",
            "capabilities added", "runAsNonRoot is not true", "seccomp profile", "hostPort 8080", "no requests.cpu",
            "no limits.memory", "fixture-unknown-secret is neither rendered nor in the runtime contract",
            "no default-deny NetworkPolicy", "no NetworkPolicy selects", "without a PodDisruptionBudget",
        ):
            self.assertIn(expected, self.text)


class Mutations(unittest.TestCase):
    def assertFails(self, objects: list[dict], fragment: str, release: bool = False):
        failures, _ = mc.check(objects, CONTRACTS, release=release)
        self.assertTrue(any(fragment in f for f in failures), f"expected {fragment!r} in {failures}")

    def test_placeholder_digest_is_a_note_and_a_release_failure(self):
        objects = compliant()
        container(objects)["image"] = "registry.example.invalid/fixture-app@" + mc.ZERO_DIGEST
        failures, notes = mc.check(objects, CONTRACTS)
        self.assertEqual(failures, [])
        self.assertTrue(any("placeholder digest" in n for n in notes))
        self.assertFails(objects, "placeholder digest in a release render", release=True)

    def test_tag_without_digest_fails(self):
        objects = compliant()
        container(objects)["image"] = "registry.example.invalid/fixture-app:1.0"
        self.assertFails(objects, "not pinned by digest")

    def test_unknown_priority_class_fails(self):
        objects = compliant()
        pod(objects)["priorityClassName"] = "system-cluster-critical"
        self.assertFails(objects, "is not an rwsafe PriorityClass")

    def test_secret_key_outside_the_contract_fails(self):
        objects = compliant()
        pod(objects)["volumes"][1]["secret"]["items"] = [{"key": "other", "path": "other"}]
        self.assertFails(objects, "key(s) other not in the runtime contract")

    def test_rendered_contract_configmap_fails(self):
        objects = compliant()
        objects.append({"apiVersion": "v1", "kind": "ConfigMap",
                        "metadata": {"name": "fixture-estate", "namespace": "fixture"}, "data": {"names": "x"}})
        self.assertFails(objects, "uncommitted contract ConfigMap is rendered")

    def test_missing_configmap_key_fails(self):
        objects = compliant()
        container(objects)["env"].append({"name": "X", "valueFrom": {
            "configMapKeyRef": {"name": "fixture-config", "key": "MISSING"}}})
        self.assertFails(objects, "MISSING not in the rendered ConfigMap")

    def test_quota_counts_the_surge_pod(self):
        objects = compliant()
        container(objects)["resources"]["limits"]["cpu"] = "700m"  # 3 pods x 700m = 2.1 > 2
        self.assertFails(objects, "limits.cpu needs 2.1")

    def test_limitrange_maximum(self):
        objects = compliant()
        container(objects)["resources"]["limits"]["memory"] = "2Gi"
        self.assertFails(objects, "above LimitRange max")

    def test_ui2_namespace_reference_fails(self):
        objects = compliant()
        policy = next(o for o in objects if o["kind"] == "NetworkPolicy" and o["metadata"]["name"] == "fixture-app")
        policy["spec"]["ingress"][0]["from"] = [{"namespaceSelector": {"matchLabels": {
            "kubernetes.io/metadata.name": "ui2"}}}]
        self.assertFails(objects, "names a ui2* (neXus) object")

    def test_default_deny_with_rules_does_not_count(self):
        objects = compliant()
        deny = next(o for o in objects if o["kind"] == "NetworkPolicy" and o["metadata"]["name"] == "default-deny")
        deny["spec"]["ingress"] = [{}]
        self.assertFails(objects, "no default-deny NetworkPolicy")

    def test_container_level_run_as_root_fails(self):
        objects = compliant()
        container(objects)["securityContext"]["runAsNonRoot"] = False
        self.assertFails(objects, "runAsNonRoot is not true")

    def test_projected_token_fails(self):
        objects = compliant()
        pod(objects)["volumes"].append({"name": "token", "projected": {"sources": [
            {"serviceAccountToken": {"path": "token"}}]}})
        self.assertFails(objects, "projects a ServiceAccount token")

    def test_quantities(self):
        self.assertEqual(mc.quantity("1500m"), 1.5)
        self.assertEqual(mc.quantity("2Gi"), 2 * 2**30)
        self.assertEqual(mc.quantity("4"), 4.0)


class CommittedOverlay(unittest.TestCase):
    def test_k3s_overlay_passes(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = mc.main([])
        self.assertEqual(rc, 0, out.getvalue())
        self.assertIn("manifest check PASS", out.getvalue())

    def test_k3s_overlay_is_not_releasable_with_placeholder_digests(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = mc.main(["--release"])
        self.assertEqual(rc, 1)
        self.assertIn("placeholder digest in a release render", out.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=1)
