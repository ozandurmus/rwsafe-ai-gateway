#!/usr/bin/env python3
"""Self-test of the manifest check: the compliant fixture passes, every rule fails on a fixture or a one-field mutation
of it, and the committed k3s overlay passes. Standard library only; needs kubectl on PATH (offline: KUBECONFIG is
/dev/null, nothing reaches a cluster).

Usage: python3 -B tools/deploy/test_manifest_check.py
"""
from __future__ import annotations

import base64
import contextlib
import copy
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import manifest_check as mc  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CONTRACTS = {"secrets": {"fixture-secret": {"keys": ["value"]}},
             "configMaps": {"fixture-estate": {"keys": ["names"]}}}
_COMPLIANT = mc.to_objects((FIXTURES / "compliant.yaml").read_text())
_VIOLATING = mc.to_objects((FIXTURES / "violating.yaml").read_text())
CONTRACTS_FILE_JSON = json.loads(mc.DEFAULT_CONTRACTS.read_text())


def compliant() -> list[dict]:
    return copy.deepcopy(_COMPLIANT)


def deployment(objects: list[dict]) -> dict:
    return next(o for o in objects if o["kind"] == "Deployment")


def pod(objects: list[dict]) -> dict:
    return deployment(objects)["spec"]["template"]["spec"]


def container(objects: list[dict]) -> dict:
    return pod(objects)["containers"][0]


def cronjob(objects: list[dict]) -> dict:
    return next(o for o in objects if o["kind"] == "CronJob")


def probe_pod(objects: list[dict]) -> dict:
    return mc.pod_template(cronjob(objects))[1]


def probe_container(objects: list[dict]) -> dict:
    return probe_pod(objects)["containers"][0]


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
        container(objects)["resources"]["limits"]["cpu"] = "700m"  # 3 pods x 700m + the probe's 200m = 2.3 > 2
        self.assertFails(objects, "limits.cpu needs 2.3")

    def test_cronjob_pod_counts_in_the_quota(self):
        objects = compliant()
        self.assertEqual(mc.check(objects, CONTRACTS)[0], [])
        probe_container(objects)["resources"]["limits"]["cpu"] = "600m"  # 3 x 500m + 600m = 2.1 > 2
        self.assertFails(objects, "limits.cpu needs 2.1")

    def test_cronjob_pod_follows_the_pod_rules(self):
        for mutate, fragment in (
                (lambda o: probe_pod(o).pop("priorityClassName"), "no priorityClassName"),
                (lambda o: probe_pod(o).update(automountServiceAccountToken=True), "automountServiceAccountToken"),
                (lambda o: probe_container(o)["securityContext"].update(readOnlyRootFilesystem=False),
                 "readOnlyRootFilesystem is not true"),
                (lambda o: probe_container(o)["resources"].pop("limits"), "no limits.cpu"),
                (lambda o: probe_container(o).update(image="registry.example.invalid/fixture-app:1.0"),
                 "not pinned by digest"),
                (lambda o: probe_pod(o).update(securityContext={"runAsNonRoot": True}),
                 "seccomp profile is not RuntimeDefault"),
                (lambda o: cronjob(o)["spec"]["jobTemplate"]["spec"]["template"]["metadata"]["labels"].update(
                    {"app.kubernetes.io/name": "fixture-other"}), "no NetworkPolicy selects this workload's pods")):
            with self.subTest(fragment):
                objects = compliant()
                mutate(objects)
                self.assertFails(objects, fragment)

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

    # PO 2026-10-31: neXus's repositories and any `nexus*` token are out of bounds too.
    def test_nexus_tokens_fail(self):
        self.assertTrue(mc.names_nexus("registry.kube-system.svc.cluster.local/nexus-ui2-service:abc"))
        self.assertTrue(mc.names_nexus("far below every neXus service pod"))
        self.assertFalse(mc.names_nexus("connexus"))
        objects = compliant()
        container(objects)["image"] = ("registry.kube-system.svc.cluster.local/nexus-ui2-build-cache@sha256:"
                                       + "1" * 64)
        self.assertFails(objects, "names a ui2* (neXus) object")

    def test_load_balancer_port_in_use_on_the_host_fails(self):
        for port in (80, 443, 22, 6443):
            with self.subTest(port):
                objects = compliant()
                objects.append({"apiVersion": "v1", "kind": "Service",
                                "metadata": {"name": "fixture-lb", "namespace": "fixture"},
                                "spec": {"type": "LoadBalancer", "ports": [{"port": port, "targetPort": 8080}]}})
                self.assertFails(objects, f"LoadBalancer port {port} is already in use on the host")

    def test_nexus_cluster_ports_fail(self):
        objects = compliant()
        container(objects)["ports"] = [{"name": "x", "containerPort": 8086}]
        self.assertFails(objects, "containerPort 8086 is one of neXus's cluster ports")

    def test_in_cluster_registry_repository_must_be_the_products(self):
        objects = compliant()
        container(objects)["image"] = "registry.kube-system.svc.cluster.local/other-app@sha256:" + "1" * 64
        self.assertFails(objects, "in-cluster registry repository other-app is not a rwsafe-* repository")
        container(objects)["image"] = "registry.kube-system.svc.cluster.local/rwsafe-app@sha256:" + "1" * 64
        failures, _ = mc.check(objects, CONTRACTS)
        self.assertFalse(any("registry repository" in f for f in failures), failures)


    # PR 18 review D-05: one mutation per rule.
    def test_init_container_counts_in_the_quota(self):
        objects = compliant()
        pod(objects)["initContainers"] = [dict(copy.deepcopy(container(objects)), name="init",
                                               resources={"requests": {"cpu": "400m", "memory": "128Mi"},
                                                          "limits": {"cpu": "700m", "memory": "512Mi"}})]
        self.assertFails(objects, "limits.cpu needs 2.3")

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
        # HOSTA_MEASUREMENT_2026_10_31: 305 GiB free minus the 5 % eviction reserve of 1005 GiB = 254 GiB.
        for name, size in (("fixture-a", "200Gi"), ("fixture-b", "55Gi")):
            objects.append({"apiVersion": "v1", "kind": "PersistentVolumeClaim",
                            "metadata": {"name": name, "namespace": "other"},
                            "spec": {"resources": {"requests": {"storage": size}}}})
        self.assertFails(objects, "requested storage of all namespaces is 255Gi, above the host-free budget 254Gi")
        objects[-1]["spec"]["resources"]["requests"]["storage"] = "54Gi"
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


class ProductName(unittest.TestCase):
    """PO 2026-10-31: the product name is one parameter (deploy/rwsafe/product.env) for every cluster-visible name."""

    def test_default_is_rwsafe(self):
        self.assertEqual(mc.default_product(), "rwsafe")

    def test_invalid_names_are_refused(self):
        for name in ("nexus", "nexus2", "ui2x", "Rwsafe", "a", "kube-x", "system", "x_y", "-x", "x-", "a--b",
                     "averyveryverylongname1"):
            with self.subTest(name):
                self.assertIsNotNone(mc.validate_product(name))
        for name in ("rwsafe", "acme", "ai-guard", "g7"):
            with self.subTest(name):
                self.assertIsNone(mc.validate_product(name))

    def test_swap_name(self):
        self.assertEqual(mc.swap_name("rwsafe", "acme"), "acme")
        self.assertEqual(mc.swap_name("rwsafe-icap-lb", "acme"), "acme-icap-lb")
        self.assertEqual(mc.swap_name("rwsafe_app", "acme"), "rwsafe_app")
        self.assertEqual(mc.swap_name("kube-system", "acme"), "kube-system")

    def test_rename_covers_names_references_labels_dns_and_registry(self):
        obj = {"apiVersion": "apps/v1", "kind": "Deployment",
               "metadata": {"name": "rwsafe-icap", "namespace": "rwsafe",
                            "labels": {"app.kubernetes.io/part-of": "rwsafe", "rwsafe.io/x": "true"}},
               "spec": {"selector": {"matchLabels": {"app.kubernetes.io/name": "rwsafe-icap"}},
                        "template": {"spec": {
                            "serviceAccountName": "rwsafe-icap", "priorityClassName": "rwsafe-dataplane",
                            "containers": [{"name": "icap",
                                            "image": "registry.kube-system.svc.cluster.local/rwsafe-dataplane@sha256:"
                                                     + "1" * 64,
                                            "env": [{"name": "RWSAFE_URL",
                                                     "value": "http://rwsafe-control.rwsafe.svc.cluster.local:8091/x"},
                                                    {"name": "POSTGRESQL_DATABASE", "value": "rwsafe"},
                                                    {"name": "K", "valueFrom": {"secretKeyRef": {
                                                        "name": "rwsafe-db-credentials",
                                                        "key": "rwsafe.migration.password"}}}],
                                            "volumeMounts": [{"name": "k", "mountPath": "/run/secrets/rwsafe-x"}]}],
                            "volumes": [{"name": "k", "secret": {"secretName": "rwsafe-x", "items": [
                                {"key": "rwsafe-snapshot-1.pem", "path": "rwsafe-snapshot-1.pem"}]}},
                                        {"name": "c", "configMap": {"name": "rwsafe-estate"}},
                                        {"name": "p", "persistentVolumeClaim": {"claimName": "rwsafe-db-data"}}]}}}}
        out = mc.rename_objects([obj], "acme")[0]
        self.assertEqual(out["metadata"]["name"], "acme-icap")
        self.assertEqual(out["metadata"]["namespace"], "acme")
        self.assertEqual(out["metadata"]["labels"], {"app.kubernetes.io/part-of": "acme", "acme.io/x": "true"})
        self.assertEqual(out["spec"]["selector"]["matchLabels"]["app.kubernetes.io/name"], "acme-icap")
        spec = out["spec"]["template"]["spec"]
        self.assertEqual((spec["serviceAccountName"], spec["priorityClassName"]), ("acme-icap", "acme-dataplane"))
        c = spec["containers"][0]
        self.assertTrue(c["image"].startswith("registry.kube-system.svc.cluster.local/acme-dataplane@"))
        self.assertEqual(c["env"][0]["value"], "http://acme-control.acme.svc.cluster.local:8091/x")
        self.assertEqual(c["env"][1]["value"], "rwsafe")   # the database name is application-internal
        self.assertEqual(c["env"][2]["valueFrom"]["secretKeyRef"],
                         {"name": "acme-db-credentials", "key": "rwsafe.migration.password"})
        self.assertEqual(c["volumeMounts"][0]["mountPath"], "/run/secrets/rwsafe-x")   # inside the container
        self.assertEqual(spec["volumes"][0]["secret"]["secretName"], "acme-x")
        self.assertEqual(spec["volumes"][0]["secret"]["items"][0]["key"], "rwsafe-snapshot-1.pem")
        self.assertEqual(spec["volumes"][1]["configMap"]["name"], "acme-estate")
        self.assertEqual(spec["volumes"][2]["persistentVolumeClaim"]["claimName"], "acme-db-data")
        self.assertEqual(mc.source_name_references(out), [])
        self.assertEqual(mc.rename_objects([obj], "rwsafe")[0], obj)

    def test_leftover_source_name_fails_under_another_product(self):
        objects = mc.rename_objects(compliant(), "acme")
        deployment(objects)["metadata"]["labels"] = {"app.kubernetes.io/name": "rwsafe-left"}
        failures, _ = mc.check(objects, mc.rename_contracts(CONTRACTS, "acme"), product="acme")
        self.assertTrue(any("still names rwsafe under product acme" in f for f in failures), failures)

    def test_part_of_label_follows_the_product(self):
        objects = compliant()
        failures, _ = mc.check(objects, CONTRACTS, product="acme")
        self.assertTrue(any("Namespace is not labelled part-of acme" in f for f in failures), failures)

    def test_contract_names_follow_the_product(self):
        renamed = mc.rename_contracts({"namespace": "rwsafe", "secrets": {"rwsafe-x": {"keys": ["k"]}},
                                       "configMaps": {"rwsafe-y": {"keys": ["rwsafe-k"]}},
                                       "build": {"namespace": "rwsafe-build", "configMaps": {"rwsafe-b": {}}}}, "acme")
        self.assertEqual(renamed["namespace"], "acme")
        self.assertEqual(set(renamed["secrets"]), {"acme-x"})
        self.assertEqual(renamed["configMaps"]["acme-y"]["keys"], ["rwsafe-k"])
        self.assertEqual((renamed["build"]["namespace"], set(renamed["build"]["configMaps"])),
                         ("acme-build", {"acme-b"}))

    # PR 33 review D-06: Ingress backends, short Service names in URLs, annotation keys and Service selectors.
    def test_rename_covers_ingress_urls_annotations_and_service_selectors(self):
        ingress = {"apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
                   "metadata": {"name": "rwsafe-admin", "namespace": "rwsafe",
                                "annotations": {"rwsafe.io/route": "admin"}},
                   "spec": {"rules": [{"http": {"paths": [{"path": "/", "pathType": "Prefix", "backend": {
                       "service": {"name": "rwsafe-control", "port": {"number": 8080}}}}]}}]}}
        cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "rwsafe-x", "namespace": "rwsafe"},
              "data": {"URL": "http://rwsafe-control:8091/x", "BARE": "http://rwsafe/x"}}
        out = mc.rename_objects([ingress, cm], "acme")
        backend = out[0]["spec"]["rules"][0]["http"]["paths"][0]["backend"]["service"]
        self.assertEqual(backend["name"], "acme-control")
        self.assertEqual(out[0]["metadata"]["annotations"], {"acme.io/route": "admin"})
        self.assertEqual(out[1]["data"], {"URL": "http://acme-control:8091/x", "BARE": "http://acme/x"})
        self.assertEqual(mc.source_name_references(out[0]) + mc.source_name_references(out[1]), [])
        for leftover in ({"data": {"URL": "http://rwsafe:8091/"}},
                         {"metadata": {"annotations": {"rwsafe.io/x": "1"}}},
                         {"spec": {"selector": {"rwsafe.io/tier": "x"}}},
                         {"spec": {"url": "http://rwsafe/"}}):
            with self.subTest(leftover):
                self.assertNotEqual(mc.source_name_references(leftover), [])

    # PR 33 review D-05: a LoadBalancer opens no node port and no health-check node port.
    def test_load_balancer_node_ports_fail(self):
        base = {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "rwsafe-lb", "namespace": "fixture"},
                "spec": {"type": "LoadBalancer", "allocateLoadBalancerNodePorts": False,
                         "externalTrafficPolicy": "Cluster", "ports": [{"port": 1344, "targetPort": 1344}]}}
        objects = compliant() + [copy.deepcopy(base)]
        failures, _ = mc.check(objects, CONTRACTS)
        self.assertFalse(any("LoadBalancer" in f for f in failures), failures)
        for field, value, fragment in (("allocateLoadBalancerNodePorts", None, "allocates node ports"),
                                       ("allocateLoadBalancerNodePorts", True, "allocates node ports"),
                                       ("externalTrafficPolicy", "Local", "health-check node port")):
            with self.subTest(f"{field}={value}"):
                svc = copy.deepcopy(base)
                if value is None:
                    svc["spec"].pop(field)
                else:
                    svc["spec"][field] = value
                failures, _ = mc.check(compliant() + [svc], CONTRACTS)
                self.assertTrue(any(fragment in f for f in failures), failures)

    def test_invalid_product_exits_2(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = mc.main(["--product", "nexus"])
        self.assertEqual(rc, 2)
        self.assertIn("names neXus", out.getvalue())


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

    # PO 2026-10-31: another product name renders and passes, with nothing left of the source name.
    def test_k3s_and_pilot_overlays_pass_under_another_product_name(self):
        for overlay in ("k3s", "pilot"):
            with self.subTest(overlay):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    rc = mc.main(["--overlay", str(mc.REPO_ROOT / "deploy/rwsafe/overlays" / overlay),
                                  "--product", "acme"])
                self.assertEqual(rc, 0, out.getvalue())
                self.assertIn("product acme", out.getvalue())
                self.assertNotIn("NetworkPolicy/rwsafe/", out.getvalue())

    # The pilot needs no SIEM placeholder, and its unfilled directory egress is a note (PILOT_RUNBOOK.md step 14.5):
    # with --release only the image digests remain (the control plane, the ICAP engine and the synthetic probe, which
    # runs the data plane image).
    def test_pilot_overlay_release_fails_only_on_the_image_digests(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = mc.main(["--overlay", str(mc.REPO_ROOT / "deploy/rwsafe/overlays/pilot"), "--release"])
        self.assertEqual(rc, 1)
        fails = [line for line in out.getvalue().splitlines() if line.startswith("FAIL")]
        self.assertEqual(len(fails), 3, fails)
        self.assertTrue(all("placeholder digest in a release render" in f for f in fails), fails)
        self.assertTrue(any("CronJob/rwsafe/rwsafe-icap-probe" in f for f in fails), fails)

    # The synthetic probe is inside the pilot quota under both product names: it passes as committed, and a probe
    # whose CPU limit no longer fits beside the workloads and their surge pods fails the quota rule.
    def test_pilot_quota_counts_the_probe_under_both_names(self):
        for product in ("rwsafe", "acme"):
            with self.subTest(product):
                text, _ = mc.render(mc.REPO_ROOT / "deploy/rwsafe/overlays/pilot")
                objects = mc.rename_objects(mc.to_objects(text), product)
                contracts = mc.rename_contracts(CONTRACTS_FILE_JSON, product)
                failures, _ = mc.check(objects, contracts, product=product, pilot=True)
                self.assertEqual(failures, [])
                probe = next(o for o in objects if mc.ident(o) == f"CronJob/{product}/{product}-icap-probe")
                mc.containers(mc.pod_template(probe)[1])[0]["resources"]["limits"]["cpu"] = "1"
                failures, _ = mc.check(objects, contracts, product=product, pilot=True)
                self.assertTrue(any(f.startswith(f"ResourceQuota/{product}/{product}-compute: limits.cpu needs")
                                    for f in failures), failures)


class DirectoryKey(unittest.TestCase):
    """PO decision Q-47, decision 1.2: the control plane mounts the product's own directory key Secret, optional (a
    missing key leaves directory sign-in unavailable, never the pod down), under the contract, in k3s and the pilot."""

    def test_the_control_plane_mounts_the_directory_key_from_the_contract(self):
        for overlay in ("k3s", "pilot"):
            for product in ("rwsafe", "acme"):
                with self.subTest(overlay=overlay, product=product):
                    text, _ = mc.render(mc.REPO_ROOT / "deploy/rwsafe/overlays" / overlay)
                    objects = mc.rename_objects(mc.to_objects(text), product)
                    contracts = mc.rename_contracts(CONTRACTS_FILE_JSON, product)
                    self.assertEqual(contracts["secrets"][f"{product}-directory-key"]["keys"], ["key"])
                    control = next(o for o in objects if mc.ident(o) == f"Deployment/{product}/{product}-control")
                    spec = mc.pod_template(control)[1]
                    volume = next(v for v in spec["volumes"] if v["name"] == "directory-key")
                    self.assertEqual(volume["secret"]["secretName"], f"{product}-directory-key")
                    self.assertTrue(volume["secret"]["optional"])
                    self.assertEqual(volume["secret"]["items"], [{"key": "key", "path": "key"}])
                    c = mc.containers(spec)[0]
                    self.assertIn({"name": "directory-key", "mountPath": "/run/secrets/rwsafe-directory-key",
                                   "readOnly": True}, c["volumeMounts"])
                    env = {e["name"]: e.get("value") for e in c["env"]}
                    self.assertEqual(env["RWSAFE_DIRECTORY_KEY_FILE"], "/run/secrets/rwsafe-directory-key/key")

    # PR 50 review D-02: the deploy-time directory values only seed the stored settings, so the control plane starts
    # without them; in the pilot it needs nothing of the contract beyond what tools/pilot/bootstrap_secrets.sh creates.
    def test_the_control_plane_starts_without_the_directory_seed_objects(self):
        for overlay in ("k3s", "pilot"):
            with self.subTest(overlay=overlay):
                text, _ = mc.render(mc.REPO_ROOT / "deploy/rwsafe/overlays" / overlay)
                control = next(o for o in mc.to_objects(text) if mc.ident(o) == "Deployment/rwsafe/rwsafe-control")
                spec = mc.pod_template(control)[1]
                for e in mc.containers(spec)[0].get("env", []):
                    if e["name"] in ("RWSAFE_LDAP_URL", "RWSAFE_LDAP_BIND_DN", "RWSAFE_LDAP_USER_SEARCH_BASE"):
                        self.assertTrue(e["valueFrom"]["configMapKeyRef"].get("optional"), e["name"])
                for v in spec["volumes"]:
                    if v["name"] in ("ldap-bind", "directory-key"):
                        self.assertTrue(v["secret"].get("optional"), v["name"])

    def test_the_pilot_control_plane_needs_only_what_bootstrap_creates(self):
        created = {("secret", "rwsafe-db-credentials"), ("secret", "rwsafe-privacy-hmac-key"),
                   ("secret", "rwsafe-snapshot-signing-key"), ("secret", "rwsafe-directory-key"),
                   ("configMap", "rwsafe-estate:estate-dictionary.txt")}
        contract = CONTRACTS_FILE_JSON
        text, _ = mc.render(mc.REPO_ROOT / "deploy/rwsafe/overlays/pilot")
        control = next(o for o in mc.to_objects(text) if mc.ident(o) == "Deployment/rwsafe/rwsafe-control")
        spec = mc.pod_template(control)[1]
        required = set()
        for v in spec["volumes"]:
            if "secret" in v and not v["secret"].get("optional"):
                required.add(("secret", v["secret"]["secretName"]))
            if "configMap" in v and not v["configMap"].get("optional") and v["configMap"]["name"] in contract["configMaps"]:
                for item in v["configMap"].get("items", [{"key": "*"}]):
                    required.add(("configMap", f"{v['configMap']['name']}:{item['key']}"))
        for c in mc.containers(spec):
            for e in c.get("env", []):
                ref = e.get("valueFrom", {}).get("configMapKeyRef") or e.get("valueFrom", {}).get("secretKeyRef")
                if ref and not ref.get("optional") and (ref["name"] in contract["configMaps"]
                                                        or ref["name"] in contract["secrets"]):
                    kind = "configMap" if "configMapKeyRef" in e["valueFrom"] else "secret"
                    required.add((kind, f"{ref['name']}:{ref['key']}" if kind == "configMap" else ref["name"]))
        self.assertTrue(required <= created, sorted(required - created))

    def test_a_directory_key_item_outside_the_contract_fails(self):
        text, _ = mc.render(mc.REPO_ROOT / "deploy/rwsafe/overlays/k3s")
        objects = mc.to_objects(text)
        control = next(o for o in objects if mc.ident(o) == "Deployment/rwsafe/rwsafe-control")
        volume = next(v for v in mc.pod_template(control)[1]["volumes"] if v["name"] == "directory-key")
        volume["secret"]["items"] = [{"key": "plaintext", "path": "key"}]
        failures, _ = mc.check(objects, CONTRACTS_FILE_JSON)
        self.assertTrue(any("plaintext not in the runtime contract" in f for f in failures), failures)


def pilot_objects(product: str) -> tuple[list[dict], dict]:
    text, _ = mc.render(mc.REPO_ROOT / "deploy/rwsafe/overlays/pilot")
    return mc.rename_objects(mc.to_objects(text), product), mc.rename_contracts(CONTRACTS_FILE_JSON, product)


_PILOT_RENDER = {p: pilot_objects(p) for p in ("rwsafe", "acme")}


class AdminIngress(unittest.TestCase):
    """The admin UI through the host's Traefik (70-admin-ingress.yaml): one Host() rule for `ui.<product>.local` to
    `<product>-control:8080`, TLS from `<product>-admin-tls`; every deviation is refused under both product names."""

    def setUp(self):
        self.renders = copy.deepcopy(_PILOT_RENDER)

    def ingress(self, objects: list[dict]) -> dict:
        found = [o for o in objects if o["kind"] == "Ingress"]
        self.assertEqual(len(found), 1)
        return found[0]

    def failures_after(self, product: str, mutate) -> list[str]:
        objects, contracts = self.renders[product]
        mutate(self.ingress(objects), objects, contracts)
        failures, _ = mc.check(objects, contracts, product=product, pilot=True)
        return failures

    def assert_refused(self, mutate, expected: str):
        for product in ("rwsafe", "acme"):
            with self.subTest(product):
                self.renders = copy.deepcopy(_PILOT_RENDER)
                failures = self.failures_after(product, mutate)
                self.assertTrue(any(f.startswith(f"Ingress/{product}/{product}-admin:") and expected in f
                                    for f in failures), failures)

    def test_committed_ingress_is_renamed_and_passes(self):
        for product, (objects, contracts) in self.renders.items():
            with self.subTest(product):
                ing = self.ingress(objects)
                self.assertEqual(mc.ident(ing), f"Ingress/{product}/{product}-admin")
                self.assertEqual(ing["spec"]["ingressClassName"], "traefik")
                self.assertEqual(ing["spec"]["rules"][0]["host"], f"ui.{product}.local")
                self.assertEqual(ing["spec"]["tls"], [{"hosts": [f"ui.{product}.local"],
                                                       "secretName": f"{product}-admin-tls"}])
                self.assertEqual(ing["spec"]["rules"][0]["http"]["paths"][0]["backend"],
                                 {"service": {"name": f"{product}-control", "port": {"number": 8080}}})
                self.assertNotIn("defaultBackend", ing["spec"])
                if product != mc.SOURCE_PRODUCT:
                    self.assertEqual(mc.source_name_references(ing), [])
                self.assertEqual(mc.check(objects, contracts, product=product, pilot=True)[0], [])
                self.assertIn(f"{product}-admin-tls", contracts["secrets"])

    def test_a_leftover_source_host_fails_under_another_product(self):
        objects, contracts = self.renders["acme"]
        self.ingress(objects)["spec"]["rules"][0]["host"] = "ui.rwsafe.local"
        failures, _ = mc.check(objects, contracts, product="acme", pilot=True)
        self.assertTrue(any("still names rwsafe" in f for f in failures), failures)
        self.assertTrue(any(f"rule host is not {mc.admin_host('acme')}" in f for f in failures), failures)

    def test_catch_all_rule_is_refused(self):
        def catch_all(ing, *_):
            ing["spec"]["rules"][0].pop("host")
        self.assert_refused(catch_all, "rule without a host (a catch-all rule)")

        def second_catch_all(ing, *_):
            ing["spec"]["rules"].append({"http": copy.deepcopy(ing["spec"]["rules"][0]["http"])})
        self.assert_refused(second_catch_all, "2 rules, not exactly one")
        self.assert_refused(second_catch_all, "catch-all rule")

        def default_backend(ing, *_):
            ing["spec"]["defaultBackend"] = copy.deepcopy(ing["spec"]["rules"][0]["http"]["paths"][0]["backend"])
        self.assert_refused(default_backend, "defaultBackend")

    def test_a_second_ingress_is_refused(self):
        # PR 43 review D-05: each Ingress passing on its own is not enough; a second one is an unreviewed route.
        def second(ing, objects, _):
            other = copy.deepcopy(ing)
            other["metadata"]["name"] = other["metadata"]["name"] + "-two"
            objects.append(other)
        self.assert_refused(second, "2 Ingress objects rendered")

    def test_foreign_backend_is_refused(self):
        def foreign_service(ing, *_):
            ing["spec"]["rules"][0]["http"]["paths"][0]["backend"]["service"]["name"] = "other-frontend"
        self.assert_refused(foreign_service, "backend is not")

        for port in (8091, 8092, 9400):
            def internal_port(ing, *_, port=port):
                ing["spec"]["rules"][0]["http"]["paths"][0]["backend"]["service"]["port"] = {"number": port}
            self.assert_refused(internal_port, "(the admin port only)")

        def named_port(ing, *_):
            ing["spec"]["rules"][0]["http"]["paths"][0]["backend"]["service"]["port"] = {"name": "http"}
        self.assert_refused(named_port, "backend is not")

        def resource_backend(ing, *_):
            ing["spec"]["rules"][0]["http"]["paths"][0]["backend"] = {
                "resource": {"apiGroup": "example.test", "kind": "Bucket", "name": "x"}}
        self.assert_refused(resource_backend, "backend is not")

        def service_not_rendered(_, objects, __):
            objects[:] = [o for o in objects if not (o["kind"] == "Service" and o["metadata"]["name"].endswith("-control"))]
        self.assert_refused(service_not_rendered, "is not rendered")

    def test_other_hosts_are_refused(self):
        for host in (mc.admin_host("other"), "rwsafe.pilot.test", "*.rwsafe.local", "ui.rwsafe.local.example.test", ""):
            def other(ing, *_, host=host):
                ing["spec"]["rules"][0]["host"] = host.replace("rwsafe", ing["metadata"]["namespace"])
            self.assert_refused(other, "rule host is not" if host else "catch-all")

    def test_class_namespace_and_annotations(self):
        def other_class(ing, *_):
            ing["spec"]["ingressClassName"] = "nginx"
        self.assert_refused(other_class, "class is nginx, not traefik")

        def no_class(ing, *_):
            ing["spec"].pop("ingressClassName")
        self.assert_refused(no_class, "class is unset")

        def other_namespace(ing, *_):
            ing["metadata"]["namespace"] = "default"
        for product in ("rwsafe", "acme"):
            with self.subTest(product):
                self.renders = copy.deepcopy(_PILOT_RENDER)
                failures = self.failures_after(product, other_namespace)
                self.assertTrue(any(f.startswith(f"Ingress/default/{product}-admin: Ingress is not in namespace")
                                    for f in failures), failures)

        for key in ("traefik.ingress.kubernetes.io/router.middlewares", "traefik.ingress.kubernetes.io/router.priority",
                    "Traefik.Ingress.Kubernetes.io/router.priority", "kubernetes.io/ingress.class"):
            def annotated(ing, *_, key=key):
                ing["metadata"].setdefault("annotations", {})[key] = "x"
            self.assert_refused(annotated, f"annotation {key}")

    def test_tls_must_be_the_products_secret_for_the_one_host(self):
        def no_tls(ing, *_):
            ing["spec"].pop("tls")
        self.assert_refused(no_tls, "0 TLS entries")

        def default_store(ing, *_):
            ing["spec"]["tls"][0].pop("secretName")
        self.assert_refused(default_store, "TLS Secret is not")

        for secret in ("other-frontend-tls", "rwsafe-icap-tls", "default-cert"):
            def foreign(ing, *_, secret=secret):
                ing["spec"]["tls"][0]["secretName"] = secret.replace("rwsafe", ing["metadata"]["namespace"])
            self.assert_refused(foreign, "TLS Secret is not")

        def extra_host(ing, *_):
            ing["spec"]["tls"][0]["hosts"].append(mc.admin_host("other"))
        self.assert_refused(extra_host, "TLS hosts are not exactly")

        def not_in_contract(_, __, contracts):
            contracts["secrets"] = {n: v for n, v in contracts["secrets"].items() if not n.endswith("-admin-tls")}
        self.assert_refused(not_in_contract, "not in the runtime contract")

    def test_traefik_crd_is_refused(self):
        objects, contracts = self.renders["rwsafe"]
        objects.append({"apiVersion": "traefik.io/v1alpha1", "kind": "IngressRoute",
                        "metadata": {"name": "rwsafe-admin", "namespace": "rwsafe"}, "spec": {}})
        failures, _ = mc.check(objects, contracts)
        self.assertIn("IngressRoute/rwsafe/rwsafe-admin: a Traefik CRD object is rendered; the admin UI is reached "
                      "through one Ingress only", failures)

    def test_traefik_is_admitted_to_the_admin_port_only(self):
        for product, (objects, _) in self.renders.items():
            with self.subTest(product):
                policy = next(o for o in objects if mc.ident(o) == f"NetworkPolicy/{product}/{product}-control-from-traefik")
                self.assertEqual(policy["spec"]["podSelector"], {"matchLabels": {
                    "app.kubernetes.io/name": f"{product}-control"}})
                [rule] = policy["spec"]["ingress"]
                self.assertEqual(rule["ports"], [{"protocol": "TCP", "port": 8080}])
                self.assertEqual(rule["from"], [{
                    "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}},
                    "podSelector": {"matchLabels": {"app.kubernetes.io/name": "traefik"}}}])


def _v4(*octets: int, prefix: int) -> str:
    """A synthetic network built at runtime (the privacy gate refuses a non-documentation dotted literal)."""
    return ".".join(str(o) for o in octets) + f"/{prefix}"


class DirectoryEgress(unittest.TestCase):
    """PILOT_RUNBOOK.md step 14.5: `<product>-control-to-directory` holds only the LDAP settings screen's four ports,
    TCP, and ipBlock peers that directory_block_problem accepts; the pilot's unfilled placeholder is a release note."""

    def setUp(self):
        self.renders = copy.deepcopy(_PILOT_RENDER)

    @staticmethod
    def policy(objects: list[dict], product: str) -> dict:
        return next(o for o in objects if mc.ident(o) == f"NetworkPolicy/{product}/{product}-control-to-directory")

    def failures_after(self, product: str, mutate, release: bool = False, pilot: bool = True) -> list[str]:
        objects, contracts = copy.deepcopy(self.renders[product])
        mutate(self.policy(objects, product))
        failures, _ = mc.check(objects, contracts, release=release, product=product, pilot=pilot)
        return failures

    def assert_refused(self, mutate, expected: str):
        for product in ("rwsafe", "acme"):
            with self.subTest(product):
                failures = self.failures_after(product, mutate)
                self.assertTrue(any(f.startswith(f"NetworkPolicy/{product}/{product}-control-to-directory:")
                                    and expected in f for f in failures), failures)

    def test_committed_pilot_policy_passes_and_its_placeholder_is_a_release_note(self):
        for product, (objects, contracts) in self.renders.items():
            with self.subTest(product):
                failures, notes = mc.check(objects, contracts, release=True, product=product, pilot=True)
                self.assertFalse([f for f in failures if "directory" in f], failures)
                self.assertTrue(any("keeps the documentation-range placeholder, which reaches nothing" in n
                                    for n in notes), notes)
                # Outside the pilot the same placeholder fails a release render (the estate patch must fill it).
                failures, _ = mc.check(objects, contracts, release=True, product=product, pilot=False)
                self.assertTrue(any(f"{product}-control-to-directory: egress ipBlock is a documentation-range "
                                    f"placeholder in a release render" in f for f in failures), failures)

    def test_filled_ranges_pass(self):
        def fill(p):
            p["spec"]["egress"][0]["to"] = [{"ipBlock": {"cidr": "203.0.113.0/24"}},
                                            {"ipBlock": {"cidr": "198.51.100.7/32"}}]
        for product in ("rwsafe", "acme"):
            with self.subTest(product):
                self.assertEqual(self.failures_after(product, fill), [])

    def test_a_port_outside_the_four_is_refused(self):
        self.assert_refused(lambda p: p["spec"]["egress"][0]["ports"].append({"protocol": "TCP", "port": 22}),
                            "opens a port other than TCP 389, 636, 3268, 3269")
        self.assert_refused(lambda p: p["spec"]["egress"][0]["ports"].append({"protocol": "UDP", "port": 389}),
                            "opens a port other than TCP")
        self.assert_refused(lambda p: p["spec"]["egress"][0]["ports"][0].update({"endPort": 636}),
                            "opens a port other than TCP")
        self.assert_refused(lambda p: p["spec"]["egress"][0].pop("ports"), "has no ports")

    def test_a_selector_peer_is_refused(self):
        self.assert_refused(lambda p: p["spec"]["egress"][0]["to"].append(
            {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}),
            "a peer other than an ipBlock")
        self.assert_refused(lambda p: p["spec"]["egress"][0]["to"].append(
            {"podSelector": {"matchLabels": {"app": "x"}}}), "a peer other than an ipBlock")
        self.assert_refused(lambda p: p["spec"]["egress"][0]["to"][0].update(
            {"podSelector": {"matchLabels": {"app": "x"}}}), "a peer other than an ipBlock")

    def test_broad_or_forbidden_blocks_are_refused(self):
        cases = {
            _v4(10, 0, 0, 0, prefix=8): "broader than /16",
            _v4(0, 0, 0, 0, prefix=0): "broader than /16",
            _v4(10, 42, 0, 0, prefix=24): "the cluster's pod range",
            _v4(10, 43, 0, 0, prefix=24): "the cluster's Service range",
            _v4(127, 0, 0, 0, prefix=16): "loopback",
            _v4(169, 254, 0, 0, prefix=16): "link-local",
            _v4(224, 0, 0, 0, prefix=24): "multicast",
        }
        for cidr, rule in cases.items():
            with self.subTest(rule):
                self.assert_refused(lambda p, c=cidr: p["spec"]["egress"][0]["to"][0]["ipBlock"].update({"cidr": c}),
                                    rule)
        self.assert_refused(lambda p: p["spec"]["egress"][0]["to"][0]["ipBlock"].update(
            {"cidr": "203.0.113.0/24", "except": ["203.0.113.0/28"]}), "with except")

    def test_more_than_eight_blocks_and_other_shapes_are_refused(self):
        self.assert_refused(lambda p: p["spec"]["egress"][0].update(
            {"to": [{"ipBlock": {"cidr": f"203.0.113.{i * 16}/28"}} for i in range(9)]}), "9 ipBlocks, more than 8")
        self.assert_refused(lambda p: p["spec"].update({"policyTypes": ["Ingress", "Egress"]}), "not Egress only")
        self.assert_refused(lambda p: p["spec"].update({"egress": []}), "has no egress rule")

    # PR 54 review D-01: the policy's place and selector, the CIDR form, overlaps, public space, and the pilot's gaps.
    def test_namespace_and_selector_are_held(self):
        for product in ("rwsafe", "acme"):
            with self.subTest(product):
                failures = self.failures_after(product, lambda p: p["metadata"].update({"namespace": "default"}))
                self.assertIn(f"NetworkPolicy/default/{product}-control-to-directory: the directory policy is not in "
                              f"namespace {product}", failures)
        self.assert_refused(lambda p: p["spec"].update({"podSelector": {}}), "does not select exactly the")
        self.assert_refused(lambda p: p["spec"]["podSelector"]["matchLabels"].update(
            {"app.kubernetes.io/name": "other"}), "does not select exactly the")

    def test_cidr_form_overlap_and_public_space_are_refused(self):
        self.assert_refused(lambda p: p["spec"]["egress"][0]["to"][0]["ipBlock"].update({"cidr": "198.51.100.7"}),
                            "has no /prefix")
        self.assert_refused(lambda p: p["spec"]["egress"][0]["to"].append({"ipBlock": {"cidr": "192.0.2.64/26"}}),
                            "overlaps another")
        self.assert_refused(lambda p: p["spec"]["egress"][0]["to"][0]["ipBlock"].update(
            {"cidr": _v4(11, 1, 0, 0, prefix=16)}), "RFC 1918")

        def private(p):
            p["spec"]["egress"][0]["to"] = [{"ipBlock": {"cidr": _v4(10, 20, 0, 0, prefix=16)}},
                                            {"ipBlock": {"cidr": _v4(172, 16, 5, 0, prefix=24)}}]
        for product in ("rwsafe", "acme"):
            with self.subTest(product):
                self.assertEqual(self.failures_after(product, private), [])

    def test_pilot_requires_the_policy_and_no_other_ip_block(self):
        for product in ("rwsafe", "acme"):
            with self.subTest(product):
                objects, contracts = copy.deepcopy(self.renders[product])
                other = next(o for o in objects if mc.ident(o) == f"NetworkPolicy/{product}/{product}-allow-dns")
                other["spec"]["egress"][0]["to"].append({"ipBlock": {"cidr": "203.0.113.0/24"}})
                failures, _ = mc.check(objects, contracts, product=product, pilot=True)
                self.assertTrue(any(f"{product}-allow-dns: an ipBlock outside {product}-control-to-directory" in f
                                    for f in failures), failures)
                objects, contracts = copy.deepcopy(self.renders[product])
                renamed = self.policy(objects, product)
                renamed["metadata"]["name"] = f"{product}-control-to-ldap"
                failures, _ = mc.check(objects, contracts, product=product, pilot=True)
                self.assertTrue(any(f"{product}-control-to-directory: missing from the pilot's render" in f
                                    for f in failures), failures)
                self.assertTrue(any(f"{product}-control-to-ldap: an ipBlock outside" in f for f in failures), failures)

    def test_k3s_directory_policy_passes_the_same_rules(self):
        text, _ = mc.render(mc.DEFAULT_OVERLAY)
        objects = mc.to_objects(text)
        failures, _ = mc.check(objects, CONTRACTS_FILE_JSON)
        self.assertFalse([f for f in failures if "directory" in f], failures)
        self.assertEqual(mc.directory_block_problem("192.0.2.0/24"), None)


class SingleApprovalSwitch(unittest.TestCase):
    """PO decision Q-47 and PR 47 review D-01: the single-approval switch is named only as RWSAFE_POLICY_SINGLE_APPROVAL
    in the control ConfigMap, "true" in the committed pilot overlay only; any other spelling or place is refused."""

    def control_config(self, objects: list[dict], product: str = "rwsafe") -> dict:
        return next(o for o in objects if mc.ident(o) == f"ConfigMap/{product}/{product}-control-config")

    def single_approval_failures(self, failures: list[str]) -> list[str]:
        return [f for f in failures if "Q-47" in f]

    def test_the_committed_pilot_overlay_turns_it_on_and_passes(self):
        for product in ("rwsafe", "acme"):
            with self.subTest(product):
                objects, contracts = copy.deepcopy(_PILOT_RENDER[product])
                self.assertEqual(self.control_config(objects, product)["data"][mc.SINGLE_APPROVAL_ENV], "true")
                self.assertEqual(mc.check(objects, contracts, product=product, pilot=True)[0], [])
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    rc = mc.main(["--overlay", str(mc.PILOT_OVERLAY), "--product", product])
                self.assertEqual(rc, 0, out.getvalue())

    def test_the_pilot_render_is_refused_when_not_declared_the_pilots(self):
        objects, contracts = copy.deepcopy(_PILOT_RENDER["rwsafe"])
        failures = self.single_approval_failures(mc.check(objects, contracts)[0])
        self.assertEqual(failures, ['ConfigMap/rwsafe/rwsafe-control-config: RWSAFE_POLICY_SINGLE_APPROVAL is "true" '
                                    'in a render other than the pilot\'s render; the single-approval switch (PO '
                                    'decision Q-47) is "true" in the pilot overlay only, else "false"'])
        self.control_config(objects)["data"][mc.SINGLE_APPROVAL_ENV] = "false"
        self.assertEqual(self.single_approval_failures(mc.check(objects, contracts)[0]), [],
                         "\"false\" in the one place is accepted everywhere")
        with tempfile.TemporaryDirectory() as d:
            rendered = Path(d) / "pilot.yaml"
            text, _ = mc.render(mc.PILOT_OVERLAY)
            rendered.write_text(text)
            for extra, expected in (([], 1), (["--pilot"], 0)):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    rc = mc.main(["--rendered", str(rendered)] + extra)
                self.assertEqual(rc, expected, out.getvalue())

    def test_pilot_is_declared_for_a_rendered_file_only(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = mc.main(["--overlay", str(mc.REPO_ROOT / "deploy/rwsafe/overlays/k3s"), "--pilot"])
        self.assertEqual(rc, 2)
        self.assertIn("--pilot declares a --rendered file", out.getvalue())

    def test_no_committed_render_or_contract_mentions_it_elsewhere(self):
        for overlay in ("k3s", "pilot"):
            for product in ("rwsafe", "acme"):
                with self.subTest(overlay=overlay, product=product):
                    text, _ = mc.render(mc.REPO_ROOT / "deploy/rwsafe/overlays" / overlay)
                    objects = mc.rename_objects(mc.to_objects(text), product)
                    contracts = mc.rename_contracts(CONTRACTS_FILE_JSON, product)
                    failures, _ = mc.check(objects, contracts, product=product, pilot=overlay == "pilot")
                    self.assertEqual(self.single_approval_failures(failures), [])
                    mentions = [mc.ident(o) for o in objects
                                if any(mc._mentions_single_approval(t) for _, t in mc._strings(o))]
                    self.assertEqual(mentions, [f"ConfigMap/{product}/{product}-control-config"]
                                     if overlay == "pilot" else [])

    def test_the_one_place_takes_true_only_in_the_pilot_and_never_another_value(self):
        for pilot, value, refused in ((True, "yes", True), (True, "TRUE", True), (True, "", True), (True, None, True),
                                      (True, "false", False), (False, "true", True), (False, "1", True),
                                      (False, "false", False)):
            with self.subTest(pilot=pilot, value=value):
                objects, contracts = copy.deepcopy(_PILOT_RENDER["rwsafe"])
                self.control_config(objects)["data"][mc.SINGLE_APPROVAL_ENV] = value
                failures = self.single_approval_failures(mc.check(objects, contracts, pilot=pilot)[0])
                self.assertEqual(len(failures), 1 if refused else 0, failures)

    # PR 47 review D-01: every other place or spelling is refused, in the pilot too.

    def assert_mention_refused(self, mutate, where: str):
        for pilot in (False, True):
            with self.subTest(where=where, pilot=pilot):
                objects, contracts = copy.deepcopy(_PILOT_RENDER["rwsafe"])
                mutate(objects, contracts)
                failures = self.single_approval_failures(mc.check(objects, contracts, pilot=pilot)[0])
                self.assertTrue(any(where in f for f in failures), failures)

    def control_pod(self, objects: list[dict]) -> dict:
        return mc.containers(mc.pod_template(next(
            o for o in objects if mc.ident(o) == "Deployment/rwsafe/rwsafe-control"))[1])[0]

    def test_other_configmap_keys_values_and_binary_data_are_refused(self):
        def other_key(name):
            def mutate(objects, _):
                self.control_config(objects)["data"][name] = "true"
            return mutate
        for name in ("RWSAFE_POLICY_SINGLEAPPROVAL", "rwsafe.policy.single-approval", "rwsafe_policy_single_approval"):
            self.assert_mention_refused(other_key(name), f"data.{name}")

        def spring_json(objects, _):
            self.control_config(objects)["data"]["SPRING_APPLICATION_JSON"] = json.dumps(
                {"rwsafe": {"policy": {"snapshot-refresh": "PT6H", "single-approval": True}}})
        self.assert_mention_refused(spring_json, "data.SPRING_APPLICATION_JSON")

        def tool_options(objects, _):
            self.control_config(objects)["data"]["JAVA_TOOL_OPTIONS"] = "-Drwsafe.policy.single-approval=true"
        self.assert_mention_refused(tool_options, "data.JAVA_TOOL_OPTIONS")

        def another_configmap(objects, _):
            config = copy.deepcopy(self.control_config(objects))
            config["metadata"]["name"] = "rwsafe-other-config"
            objects.append(config)
        self.assert_mention_refused(another_configmap, f"data.{mc.SINGLE_APPROVAL_ENV}")

        def binary(objects, _):
            self.control_config(objects)["binaryData"] = {
                "application.properties": base64.b64encode(b"rwsafe.policy.single-approval=true").decode()}
        self.assert_mention_refused(binary, "binaryData.application.properties (decoded)")

    def test_env_names_values_valuefrom_command_and_args_are_refused(self):
        def env(entry):
            def mutate(objects, _):
                self.control_pod(objects).setdefault("env", []).append(entry)
            return mutate
        self.assert_mention_refused(env({"name": mc.SINGLE_APPROVAL_ENV, "value": "true"}), "env")
        self.assert_mention_refused(env({"name": mc.SINGLE_APPROVAL_ENV, "valueFrom": {"configMapKeyRef": {
            "name": "rwsafe-estate", "key": "trusted-proxies"}}}), "env")
        self.assert_mention_refused(env({"name": "JDK_JAVA_OPTIONS",
                                         "value": "-Drwsafe.policy.single-approval=true"}), "env")
        self.assert_mention_refused(env({"name": "SPRING_APPLICATION_JSON",
                                         "value": '{"rwsafe":{"policy":{"singleApproval":true}}}'}), "env")

        def args(objects, _):
            self.control_pod(objects)["args"] = [
                "--spring.application.json={\"rwsafe\":{\"policy\":{\"x\":1,\"single-approval\":true}}}"]
        self.assert_mention_refused(args, "args[0]")

        def command(objects, _):
            self.control_pod(objects)["command"] = ["java", "-Drwsafe.policy.single_approval=true", "-jar", "app.jar"]
        self.assert_mention_refused(command, "command[1]")

    def test_contract_names_and_keys_are_refused(self):
        def secret_key(_, contracts):
            contracts["secrets"]["rwsafe-db-credentials"]["keys"].append("rwsafe.policy.single-approval")
        self.assert_mention_refused(secret_key, "runtime contract secrets/rwsafe-db-credentials")

        def configmap_key(_, contracts):
            contracts["configMaps"]["rwsafe-estate"]["keys"].append("RWSAFE_POLICY_SINGLE_APPROVAL")
        self.assert_mention_refused(configmap_key, "runtime contract configMaps/rwsafe-estate")

        def build_configmap(_, contracts):
            contracts["build"]["configMaps"]["rwsafe-single-approval"] = {"keys": ["value"]}
        self.assert_mention_refused(build_configmap, "runtime contract build.configMaps/rwsafe-single-approval")


class DirectoryTestSwitch(unittest.TestCase):
    """PR 50 review Q-1 (confirmation): the directory's test-only switch (plain LDAP and loopback targets) is named by
    no render and no contract, the pilot's included; every shape a deploy could set it in is refused."""

    def switch_failures(self, failures: list[str]) -> list[str]:
        return [f for f in failures if "directory test-only switch" in f]

    def control_config(self, objects: list[dict]) -> dict:
        return next(o for o in objects if mc.ident(o) == "ConfigMap/rwsafe/rwsafe-control-config")

    def control_pod(self, objects: list[dict]) -> dict:
        return mc.containers(mc.pod_template(next(
            o for o in objects if mc.ident(o) == "Deployment/rwsafe/rwsafe-control"))[1])[0]

    def assert_refused(self, mutate, where: str):
        for pilot in (False, True):
            with self.subTest(where=where, pilot=pilot):
                objects, contracts = copy.deepcopy(_PILOT_RENDER["rwsafe"])
                mutate(objects, contracts)
                failures = self.switch_failures(mc.check(objects, contracts, pilot=pilot)[0])
                self.assertTrue(any(where in f for f in failures), failures)

    def test_no_committed_render_or_contract_names_it(self):
        for overlay in ("k3s", "pilot"):
            for product in ("rwsafe", "acme"):
                with self.subTest(overlay=overlay, product=product):
                    text, _ = mc.render(mc.REPO_ROOT / "deploy/rwsafe/overlays" / overlay)
                    objects = mc.rename_objects(mc.to_objects(text), product)
                    contracts = mc.rename_contracts(CONTRACTS_FILE_JSON, product)
                    failures, _ = mc.check(objects, contracts, product=product, pilot=overlay == "pilot")
                    self.assertEqual(self.switch_failures(failures), [])

    def test_every_spelling_matches(self):
        for text in ("RWSAFE_IDENTITY_DIRECTORYLOOPBACKFORTESTS", "rwsafe.identity.directory-loopback-for-tests",
                     "rwsafe_identity_directory_loopback_for_tests", "directoryLoopbackForTests",
                     '{"rwsafe":{"identity":{"directory-loopback-for-tests":true}}}', "loopback-for-tests"):
            self.assertTrue(mc._mentions_directory_test_switch(text), text)
        for text in ("RWSAFE_LDAP_URL", "loopback", "for-tests", None, 1):
            self.assertFalse(mc._mentions_directory_test_switch(text), text)

    def test_configmap_keys_values_and_binary_data_are_refused(self):
        for name in ("RWSAFE_IDENTITY_DIRECTORYLOOPBACKFORTESTS", "rwsafe.identity.directory-loopback-for-tests"):
            def key(objects, _, name=name):
                self.control_config(objects)["data"][name] = "true"
            self.assert_refused(key, f"data.{name}")

        def spring_json(objects, _):
            self.control_config(objects)["data"]["SPRING_APPLICATION_JSON"] = json.dumps(
                {"rwsafe": {"identity": {"directory-loopback-for-tests": True}}})
        self.assert_refused(spring_json, "data.SPRING_APPLICATION_JSON")

        def tool_options(objects, _):
            self.control_config(objects)["data"]["JAVA_TOOL_OPTIONS"] = (
                "-Drwsafe.identity.directory-loopback-for-tests=true")
        self.assert_refused(tool_options, "data.JAVA_TOOL_OPTIONS")

        def binary(objects, _):
            self.control_config(objects)["binaryData"] = {"application.properties": base64.b64encode(
                b"rwsafe.identity.directory-loopback-for-tests=true").decode()}
        self.assert_refused(binary, "binaryData.application.properties (decoded)")

    def test_env_command_args_and_annotations_are_refused(self):
        def env(entry):
            def mutate(objects, _):
                self.control_pod(objects).setdefault("env", []).append(entry)
            return mutate
        self.assert_refused(env({"name": "RWSAFE_IDENTITY_DIRECTORYLOOPBACKFORTESTS", "value": "true"}), "env")
        self.assert_refused(env({"name": "JDK_JAVA_OPTIONS",
                                 "value": "-Drwsafe.identity.directory-loopback-for-tests=true"}), "env")
        self.assert_refused(env({"name": "JAVA_TOOL_OPTIONS",
                                 "value": "-Drwsafe.identity.directoryLoopbackForTests=true"}), "env")
        self.assert_refused(env({"name": "SPRING_APPLICATION_JSON",
                                 "value": '{"rwsafe":{"identity":{"directoryLoopbackForTests":true}}}'}), "env")

        def args(objects, _):
            self.control_pod(objects)["args"] = ["--rwsafe.identity.directory-loopback-for-tests=true"]
        self.assert_refused(args, "args[0]")

        def command(objects, _):
            self.control_pod(objects)["command"] = ["java", "-Drwsafe.identity.directory-loopback-for-tests=true",
                                                    "-jar", "app.jar"]
        self.assert_refused(command, "command[1]")

        def annotation(objects, _):
            control = next(o for o in objects if mc.ident(o) == "Deployment/rwsafe/rwsafe-control")
            control["metadata"].setdefault("annotations", {})["note"] = "directory-loopback-for-tests"
        self.assert_refused(annotation, "metadata.annotations.note")

    def test_contract_names_and_keys_are_refused(self):
        def secret_key(_, contracts):
            contracts["secrets"]["rwsafe-db-credentials"]["keys"].append("rwsafe.identity.directory-loopback-for-tests")
        self.assert_refused(secret_key, "runtime contract secrets/rwsafe-db-credentials")

        def configmap_name(_, contracts):
            contracts["configMaps"]["rwsafe-loopback-for-tests"] = {"keys": ["value"]}
        self.assert_refused(configmap_name, "runtime contract configMaps/rwsafe-loopback-for-tests")

        def build_key(_, contracts):
            contracts["build"]["configMaps"]["rwsafe-build-config"]["keys"].append("DIRECTORY_LOOPBACK_FOR_TESTS")
        self.assert_refused(build_key, "runtime contract build.configMaps/rwsafe-build-config")


if __name__ == "__main__":
    unittest.main(verbosity=1)
