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
            "above the rwsafe ceiling 1000", "PSA enforce is privileged", "PSA audit is not restricted",
            "PSA warn is not restricted", "ServiceAccount automountServiceAccountToken is not false",
            "PodDisruptionBudget selects no workload", "tolerates taint fixture.example.invalid/dedicated",
            "pod runAsUser 185 is fixed", "pod seccomp profile is not RuntimeDefault", "emptyDir ram is memory-backed",
            "emptyDir ram sizeLimit 1Gi is above the cap 512Mi", "Namespace/fixture: no ResourceQuota",
            "Namespace/fixture: no LimitRange",
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

    # PR 18 review D-04: the whole object tree, keys and values, and tokens of names and URLs.
    def test_ui2_anywhere_in_the_tree_fails(self):
        cases = {
            "ConfigMap data URL": lambda o: next(x for x in o if x["kind"] == "ConfigMap")["data"].update(
                {"DB_URL": "jdbc:postgresql://ui2-db.example.invalid:5432/x"}),
            "ConfigMap data key": lambda o: next(x for x in o if x["kind"] == "ConfigMap")["data"].update(
                {"ui2-setting": "1"}),
            "env value": lambda o: container(o)["env"].append({"name": "PEER", "value": "http://ui2-service:8080/"}),
            "claimName": lambda o: pod(o)["volumes"].append(
                {"name": "data", "persistentVolumeClaim": {"claimName": "ui2-db-data"}}),
            "matchExpressions": lambda o: next(x for x in o if x["kind"] == "NetworkPolicy"
                                               and x["metadata"]["name"] == "fixture-app")["spec"]["ingress"][0]
            .update({"from": [{"namespaceSelector": {"matchExpressions": [
                {"key": "kubernetes.io/metadata.name", "operator": "In", "values": ["ui2"]}]}}]}),
            "label value": lambda o: deployment(o)["metadata"].setdefault("labels", {}).update(
                {"app.kubernetes.io/part-of": "nexus-ui2"}),
            "pod template label key": lambda o: deployment(o)["spec"]["template"]["metadata"]["labels"].update(
                {"ui2.example.invalid/tier": "x"}),
            "serviceName": lambda o: deployment(o)["spec"].update({"serviceName": "ui2-service-internal"}),
        }
        for name, mutate in cases.items():
            with self.subTest(name):
                objects = compliant()
                mutate(objects)
                self.assertFails(objects, "names a ui2* (neXus) object")

    def test_rwsafe_names_are_not_mistaken_for_ui2(self):
        self.assertFalse(mc.names_nexus("rwsafe-icap.rwsafe.svc.cluster.local:8091/internal/v1/policy/snapshot"))
        self.assertFalse(mc.names_nexus("app.kubernetes.io/part-of"))
        self.assertTrue(mc.names_nexus("UI2-DB"))

    # PR 18 review D-05: one mutation per rule.
    def test_init_container_counts_in_the_quota(self):
        objects = compliant()
        pod(objects)["initContainers"] = [dict(copy.deepcopy(container(objects)), name="init",
                                               resources={"requests": {"cpu": "400m", "memory": "128Mi"},
                                                          "limits": {"cpu": "700m", "memory": "512Mi"}})]
        self.assertFails(objects, "limits.cpu needs 2.1")

    def test_volume_claim_templates_count_in_the_quota(self):
        objects = compliant()
        quota = next(o for o in objects if o["kind"] == "ResourceQuota")
        quota["spec"]["hard"]["requests.storage"] = "10Gi"
        objects.append({"apiVersion": "apps/v1", "kind": "StatefulSet",
                        "metadata": {"name": "fixture-db", "namespace": "fixture"},
                        "spec": {"replicas": 1, "selector": {"matchLabels": {"app.kubernetes.io/name": "fixture-app"}},
                                 "template": copy.deepcopy(deployment(objects)["spec"]["template"]),
                                 "volumeClaimTemplates": [{"metadata": {"name": "data"}, "spec": {
                                     "resources": {"requests": {"storage": "20Gi"}}}}]}})
        self.assertFails(objects, "requests.storage needs")

    def test_namespace_without_quota_or_limitrange_fails(self):
        for kind in ("ResourceQuota", "LimitRange"):
            with self.subTest(kind):
                objects = [o for o in compliant() if o["kind"] != kind]
                self.assertFails(objects, f"Namespace/fixture: no {kind}")

    def test_psa_labels(self):
        objects = compliant()
        ns = next(o for o in objects if o["kind"] == "Namespace")
        ns["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] = "baseline"
        self.assertFails(objects, "PSA enforce is baseline, not restricted")
        ns["metadata"]["name"] = "rwsafe-build"
        failures, _ = mc.check(objects, CONTRACTS)
        self.assertFalse(any("PSA enforce" in f for f in failures), "baseline is the build namespace's exception")
        del ns["metadata"]["labels"]["pod-security.kubernetes.io/audit"]
        self.assertFails(objects, "PSA audit is not restricted")

    def test_emptydir_caps_and_memory_medium(self):
        objects = compliant()
        pod(objects)["volumes"][0]["emptyDir"]["sizeLimit"] = "513Mi"
        self.assertFails(objects, "sizeLimit 513Mi is above the cap 512Mi")
        objects = compliant()
        pod(objects)["volumes"][0]["emptyDir"]["medium"] = "Memory"
        self.assertFails(objects, "emptyDir tmp is memory-backed")

    def test_build_namespace_emptydir_cap_is_4gi(self):
        objects = compliant()
        for o in objects:
            if o["kind"] == "Namespace":
                o["metadata"]["name"] = "rwsafe-build"
            elif o["metadata"].get("namespace") == "fixture":
                o["metadata"]["namespace"] = "rwsafe-build"
        pod(objects)["volumes"][0]["emptyDir"]["sizeLimit"] = "4Gi"
        failures, _ = mc.check(objects, CONTRACTS)
        self.assertFalse(any("above the cap" in f for f in failures), failures)
        pod(objects)["volumes"][0]["emptyDir"]["sizeLimit"] = "5Gi"
        self.assertFails(objects, "above the cap 4Gi")

    def test_any_toleration_fails(self):
        objects = compliant()
        pod(objects)["tolerations"] = [{"key": "fixture.example.invalid/gpu", "operator": "Exists"}]
        self.assertFails(objects, "tolerates taint fixture.example.invalid/gpu")

    def test_seccomp_localhost_fails(self):
        objects = compliant()
        pod(objects)["securityContext"]["seccompProfile"] = {"type": "Localhost", "localhostProfile": "x.json"}
        self.assertFails(objects, "seccomp profile is not RuntimeDefault")

    def test_fixed_uid_or_gid_fails(self):
        for where, field in (("pod", "runAsUser"), ("pod", "runAsGroup"), ("container", "runAsUser"),
                             ("container", "runAsGroup")):
            with self.subTest(f"{where} {field}"):
                objects = compliant()
                target = pod(objects) if where == "pod" else container(objects)
                target["securityContext"][field] = 185
                self.assertFails(objects, f"{field} 185 is fixed")

    def test_service_account_must_not_automount(self):
        objects = compliant()
        sa = next(o for o in objects if o["kind"] == "ServiceAccount")
        del sa["automountServiceAccountToken"]
        self.assertFails(objects, "ServiceAccount automountServiceAccountToken is not false")

    def test_pdb_bounds(self):
        for spec, fragment in (({"minAvailable": 0}, "minAvailable 0 is not between"),
                               ({"minAvailable": 2}, "minAvailable 2 is not between"),
                               ({"minAvailable": "100%"}, "minAvailable 100% is not between"),
                               ({"maxUnavailable": 0}, "maxUnavailable 0 is not between"),
                               ({}, "sets neither minAvailable nor maxUnavailable")):
            with self.subTest(str(spec)):
                objects = compliant()
                pdb = next(o for o in objects if o["kind"] == "PodDisruptionBudget")
                pdb["spec"] = {"selector": pdb["spec"]["selector"], **spec}
                self.assertFails(objects, fragment)

    # Q-1 (PO decision Q-10): no rwsafe PriorityClass above 1000.
    def test_priority_ceiling(self):
        objects = compliant()
        next(o for o in objects if o["kind"] == "PriorityClass")["value"] = 1001
        self.assertFails(objects, "above the rwsafe ceiling 1000")

    # PR 18 review D-03: egress names its destination; the documentation placeholder is refused in a release render.
    def test_egress_without_destination_fails(self):
        objects = compliant()
        policy = next(o for o in objects if o["kind"] == "NetworkPolicy" and o["metadata"]["name"] == "fixture-app")
        policy["spec"]["egress"].append({"ports": [{"protocol": "TCP", "port": 636}]})
        self.assertFails(objects, "egress rule without a destination")

    def test_documentation_ip_block_is_a_note_and_a_release_failure(self):
        objects = compliant()
        policy = next(o for o in objects if o["kind"] == "NetworkPolicy" and o["metadata"]["name"] == "fixture-app")
        policy["spec"]["egress"].append({"to": [{"ipBlock": {"cidr": "198.51.100.0/28"}}],
                                         "ports": [{"protocol": "TCP", "port": 636}]})
        failures, notes = mc.check(objects, CONTRACTS)
        self.assertEqual(failures, [])
        self.assertTrue(any("documentation-range placeholder" in n for n in notes))
        self.assertFails(objects, "documentation-range placeholder in a release render", release=True)
        policy["spec"]["egress"][-1]["to"][0]["ipBlock"]["cidr"] = "0.0.0.0/0"
        self.assertFails(objects, "ipBlock 0.0.0.0/0 is every address")

    # Deploy wiring 2: the directory and the SIEM each have their own placeholder (the estate patch replaces by text).
    def test_shared_documentation_placeholder_fails(self):
        objects = compliant()
        policy = next(o for o in objects if o["kind"] == "NetworkPolicy" and o["metadata"]["name"] == "fixture-app")
        policy["spec"]["egress"].append({"to": [{"ipBlock": {"cidr": "192.0.2.0/24"}}],
                                         "ports": [{"protocol": "TCP", "port": 636}]})
        second = copy.deepcopy(policy)
        second["metadata"]["name"] = "fixture-app-to-siem"
        second["spec"]["egress"] = [policy["spec"]["egress"][-1]]
        objects.append(second)
        self.assertFails(objects, "documentation-range placeholder 192.0.2.0/24 is shared by")
        second["spec"]["egress"][0] = {"to": [{"ipBlock": {"cidr": "198.51.100.0/24"}}],
                                       "ports": [{"protocol": "TCP", "port": 6514}]}
        failures, _ = mc.check(objects, CONTRACTS)
        self.assertEqual(failures, [])

    def test_claimed_pvc_must_be_rendered_and_within_the_limitrange(self):
        objects = compliant()
        pod(objects)["volumes"].append({"name": "store", "persistentVolumeClaim": {"claimName": "fixture-store"}})
        self.assertFails(objects, "claims PVC fixture-store, which the render does not hold")
        objects.append({"apiVersion": "v1", "kind": "PersistentVolumeClaim",
                        "metadata": {"name": "fixture-store", "namespace": "fixture"},
                        "spec": {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "1Gi"}}}})
        limitrange = next(o for o in objects if o["kind"] == "LimitRange")
        limitrange["spec"]["limits"].append({"type": "PersistentVolumeClaim", "max": {"storage": "1Gi"}})
        failures, _ = mc.check(objects, CONTRACTS)
        self.assertEqual(failures, [])
        objects[-1]["spec"]["resources"]["requests"]["storage"] = "2Gi"
        self.assertFails(objects, "requests.storage 2Gi above LimitRange PVC max 1Gi")

    # PR 27 review D-01: an empty estate value (null or empty cidr) and a malformed one fail, release or not.
    def test_ip_block_without_a_valid_cidr_fails(self):
        for cidr, fragment in ((None, "ipBlock has no cidr"), ("", "ipBlock has no cidr"),
                               ("not-a-network", "ipBlock cidr is not a network")):
            for release in (False, True):
                with self.subTest(cidr=cidr, release=release):
                    objects = compliant()
                    policy = next(o for o in objects
                                  if o["kind"] == "NetworkPolicy" and o["metadata"]["name"] == "fixture-app")
                    policy["spec"]["egress"].append({"to": [{"ipBlock": {"cidr": cidr}}],
                                                     "ports": [{"protocol": "TCP", "port": 636}]})
                    self.assertFails(objects, fragment, release=release)

    def test_ip_block_null_cidr_from_a_rendered_empty_value_fails(self):
        objects = compliant()
        policy = next(o for o in objects if o["kind"] == "NetworkPolicy" and o["metadata"]["name"] == "fixture-app")
        policy["spec"]["egress"].append({"to": [{"ipBlock": {}}], "ports": [{"protocol": "TCP", "port": 636}]})
        self.assertFails(objects, "ipBlock has no cidr")

    # PR 27 review D-03: ingress without `from`, empty peers and empty selectors in peers.
    def test_ingress_without_source_and_empty_peers_fail(self):
        def with_rule(direction, rule):
            objects = compliant()
            policy = next(o for o in objects if o["kind"] == "NetworkPolicy" and o["metadata"]["name"] == "fixture-app")
            policy["spec"].setdefault(direction, []).append(rule)
            policy["spec"]["policyTypes"] = ["Ingress", "Egress"]
            return objects
        self.assertFails(with_rule("ingress", {"ports": [{"protocol": "TCP", "port": 9400}]}),
                         "ingress rule without a source")
        self.assertFails(with_rule("ingress", {"from": [{}]}), "ingress peer is empty")
        self.assertFails(with_rule("egress", {"to": [{}]}), "egress peer is empty")
        self.assertFails(with_rule("ingress", {"from": [{"namespaceSelector": {}}]}),
                         "ingress peer has an empty namespaceSelector")
        self.assertFails(with_rule("ingress", {"from": [{"podSelector": {}}]}), "ingress peer has an empty podSelector")
        self.assertFails(with_rule("egress", {"to": [{"namespaceSelector": {"matchLabels": {"a": "b"}},
                                                      "podSelector": {}}]}), "egress peer has an empty podSelector")
        objects = with_rule("ingress", {"from": [{"podSelector": {}}]})
        mc.EMPTY_SELECTOR_EXCEPTIONS["NetworkPolicy/fixture/fixture-app"] = "fixture: every pod of the namespace"
        try:
            failures, _ = mc.check(objects, CONTRACTS)
            self.assertEqual(failures, [], "a listed exception passes")
        finally:
            mc.EMPTY_SELECTOR_EXCEPTIONS.clear()
        self.assertEqual(mc.EMPTY_SELECTOR_EXCEPTIONS, {}, "no committed policy needs an exception")

    # PR 27 review D-05: projected Secret and ConfigMap sources, and claim templates under the LimitRange maximum.
    def test_projected_sources_go_through_the_contract(self):
        for source, fragment in (({"secret": {"name": "fixture-unknown"}}, "Secret fixture-unknown is neither"),
                                 ({"secret": {"name": "fixture-secret", "items": [{"key": "other", "path": "o"}]}},
                                  "key(s) other not in the runtime contract"),
                                 ({"configMap": {"name": "fixture-unknown-cm"}}, "ConfigMap fixture-unknown-cm is")):
            with self.subTest(str(source)):
                objects = compliant()
                pod(objects)["volumes"].append({"name": "proj", "projected": {"sources": [source]}})
                self.assertFails(objects, fragment)
        objects = compliant()
        pod(objects)["volumes"].append({"name": "proj", "projected": {"sources": [
            {"secret": {"name": "fixture-secret", "items": [{"key": "value", "path": "v"}]}}]}})
        self.assertEqual(mc.check(objects, CONTRACTS)[0], [])

    def test_volume_claim_templates_are_within_the_limitrange_maximum(self):
        objects = compliant()
        next(o for o in objects if o["kind"] == "LimitRange")["spec"]["limits"].append(
            {"type": "PersistentVolumeClaim", "max": {"storage": "1Gi"}})
        objects.append({"apiVersion": "apps/v1", "kind": "StatefulSet",
                        "metadata": {"name": "fixture-db", "namespace": "fixture"},
                        "spec": {"replicas": 1, "selector": {"matchLabels": {"app.kubernetes.io/name": "fixture-app"}},
                                 "template": copy.deepcopy(deployment(objects)["spec"]["template"]),
                                 "volumeClaimTemplates": [{"metadata": {"name": "data"}, "spec": {
                                     "resources": {"requests": {"storage": "2Gi"}}}}]}})
        self.assertFails(objects, "volumeClaimTemplate data: requests.storage 2Gi above LimitRange PVC max 1Gi")

    # PR 27 review D-06: all requested storage together within the host-free budget.
    def test_requested_storage_of_all_namespaces_is_within_the_host_budget(self):
        objects = compliant()
        for name, size in (("fixture-a", "100Gi"), ("fixture-b", "39Gi")):
            objects.append({"apiVersion": "v1", "kind": "PersistentVolumeClaim",
                            "metadata": {"name": name, "namespace": "other"},
                            "spec": {"resources": {"requests": {"storage": size}}}})
        self.assertFails(objects, "requested storage of all namespaces is 139Gi, above the host-free budget 138Gi")
        objects[-1]["spec"]["resources"]["requests"]["storage"] = "38Gi"
        failures, _ = mc.check(objects, CONTRACTS)
        self.assertFalse(any("host-free budget" in f for f in failures), failures)

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
        for policy in ("rwsafe-control-to-directory", "rwsafe-control-to-siem"):
            self.assertIn(f"NetworkPolicy/rwsafe/{policy}: egress ipBlock is a documentation-range placeholder in a "
                          f"release render", out.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=1)
