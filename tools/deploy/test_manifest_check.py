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
import json
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

    # The pilot needs no directory or SIEM placeholder: with --release only the image digests remain (the control
    # plane, the ICAP engine and the synthetic probe, which runs the data plane image).
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
                failures, _ = mc.check(objects, contracts, product=product)
                self.assertEqual(failures, [])
                probe = next(o for o in objects if mc.ident(o) == f"CronJob/{product}/{product}-icap-probe")
                mc.containers(mc.pod_template(probe)[1])[0]["resources"]["limits"]["cpu"] = "1"
                failures, _ = mc.check(objects, contracts, product=product)
                self.assertTrue(any(f.startswith(f"ResourceQuota/{product}/{product}-compute: limits.cpu needs")
                                    for f in failures), failures)


if __name__ == "__main__":
    unittest.main(verbosity=1)
