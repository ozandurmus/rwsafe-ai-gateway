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
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import directory_range  # noqa: E402
import icap_clients  # noqa: E402
import proxy_settings  # noqa: E402
import render  # noqa: E402

mc = render.mc
# Hermetic: never the host's own directory range file (PILOT_RUNBOOK.md step 14.5), which may exist where this runs.
_NO_RANGE_DIR = tempfile.TemporaryDirectory()
render.default_directory_env = lambda product: Path(_NO_RANGE_DIR.name) / "absent" / "directory.env"
render.default_icap_clients_env = lambda product: Path(_NO_RANGE_DIR.name) / "absent" / "icap-clients.env"
HELPER = Path(__file__).resolve().parent / "directory_range.sh"
ICAP_HELPER = Path(__file__).resolve().parent / "icap_clients.sh"
DIGESTS = {"dataplane": "sha256:" + "a" * 64, "control": "sha256:" + "b" * 64}
_BUILD = {p: render.render_target("build", p) for p in ("rwsafe", "acme")}
_CONTRACTS = {p: mc.rename_contracts(json.loads(mc.DEFAULT_CONTRACTS.read_text()), p) for p in ("rwsafe", "acme")}
_PILOT = {p: render.render_target("pilot", p, DIGESTS) for p in ("rwsafe", "acme")}


def job(objects: list[dict]) -> dict:
    return next(o for o in objects if o["kind"] == "Job")


def kaniko(objects: list[dict]) -> dict:
    return mc.containers(mc.pod_template(job(objects))[1])[0]


def job_spec(objects: list[dict]) -> dict:
    return mc.pod_template(job(objects))[1]


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
        # The LDAP settings screen's password key (PO decision Q-47): mounted optional, the pilot keeps it.
        control = next(o for o in objects if o["kind"] == "Deployment" and o["metadata"]["name"] == "rwsafe-control")
        key = next(v for v in mc.pod_template(control)[1]["volumes"] if v["name"] == "directory-key")
        self.assertEqual(key["secret"]["secretName"], "rwsafe-directory-key")
        self.assertTrue(key["secret"]["optional"])
        policies = {o["metadata"]["name"] for o in objects if o["kind"] == "NetworkPolicy"}
        self.assertNotIn("rwsafe-control-to-siem", policies)
        self.assertIn("rwsafe-control-to-directory", policies)
        self.assertIn("rwsafe-control-from-traefik", policies)
        self.assertEqual([mc.ident(o) for o in objects if o["kind"] == "Ingress"], ["Ingress/rwsafe/rwsafe-admin"])
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
                rc = mc.main(["--rendered", str(target), "--release", "--product", "acme", "--pilot"])
            self.assertEqual(rc, 0, out.getvalue())


def is_lb(o: dict) -> bool:
    return o["kind"] == "Service" and o["spec"].get("type") == "LoadBalancer"


class Phases(unittest.TestCase):
    """PR 33 review D-05: step 9 (control) and step 9b (icap) apply nothing that opens 1344 on the node; step 12
    (servicelb) applies only the LoadBalancer Service, after the firewall rule of step 11 is verified."""

    def test_control_phase_holds_no_icap_object_and_no_load_balancer(self):
        for product, objects in _PILOT.items():
            with self.subTest(product):
                control = render.select_phase(objects, product, "control")
                icap = render.select_phase(objects, product, "icap")
                servicelb = render.select_phase(objects, product, "servicelb")
                ingress = render.select_phase(objects, product, "ingress")
                self.assertEqual(sorted(mc.ident(o) for o in control + icap + servicelb + ingress),
                                 sorted(mc.ident(o) for o in objects))
                self.assertFalse(any(is_lb(o) for o in control + icap + ingress))
                self.assertEqual(sorted(mc.ident(o) for o in ingress), [
                    f"Ingress/{product}/{product}-admin", f"NetworkPolicy/{product}/{product}-control-from-traefik"])
                self.assertFalse(any(o["kind"] == "Ingress" for o in control + icap + servicelb))
                self.assertEqual([mc.ident(o) for o in servicelb], [f"Service/{product}/{product}-icap-lb"])
                self.assertFalse(any(o["metadata"]["name"].startswith(f"{product}-icap") for o in control))
                self.assertEqual({o["metadata"]["name"] for o in icap if o["kind"] != "ConfigMap"} | {"cm"}, {
                    f"{product}-icap", f"{product}-icap-from-proxies", f"{product}-icap-metrics-from-scraper",
                    f"{product}-icap-probe", "cm"})
                self.assertEqual({o["kind"] for o in icap if o["metadata"]["name"] == f"{product}-icap-probe"},
                                 {"ServiceAccount", "CronJob", "NetworkPolicy"})
                kinds = {o["kind"] for o in control}
                self.assertTrue({"StatefulSet", "Deployment", "Namespace", "PriorityClass"} <= kinds)
                self.assertFalse(any(o["kind"] == "Deployment" and o["metadata"]["name"] == f"{product}-icap"
                                     for o in control))

    def test_main_phase_control(self):
        rc, out, err = run(["--product", "acme", "--dataplane-digest", DIGESTS["dataplane"],
                            "--control-digest", DIGESTS["control"], "--phase", "control"])
        self.assertEqual(rc, 0, err)
        items = json.loads(out)["items"]
        self.assertFalse(any(o["metadata"]["name"].startswith("acme-icap") for o in items))

    def test_main_phase_icap_and_servicelb(self):
        args = ["--product", "acme", "--dataplane-digest", DIGESTS["dataplane"], "--control-digest", DIGESTS["control"]]
        rc, out, err = run(args + ["--phase", "icap"])
        self.assertEqual(rc, 0, err)
        items = json.loads(out)["items"]
        self.assertFalse(any(is_lb(o) for o in items))
        self.assertIn("CronJob/acme/acme-icap-probe", [mc.ident(o) for o in items])
        rc, out, err = run(args + ["--phase", "servicelb"])
        self.assertEqual(rc, 0, err)
        self.assertEqual([mc.ident(o) for o in json.loads(out)["items"]], ["Service/acme/acme-icap-lb"])

    def test_main_phase_ingress(self):
        rc, out, err = run(["--product", "acme", "--dataplane-digest", DIGESTS["dataplane"],
                            "--control-digest", DIGESTS["control"], "--phase", "ingress"])
        self.assertEqual(rc, 0, err)
        items = json.loads(out)["items"]
        self.assertEqual(sorted(mc.ident(o) for o in items),
                         ["Ingress/acme/acme-admin", "NetworkPolicy/acme/acme-control-from-traefik"])
        ingress = next(o for o in items if o["kind"] == "Ingress")
        self.assertEqual(ingress["spec"]["rules"][0]["host"], mc.admin_host("acme"))
        self.assertEqual(ingress["spec"]["tls"][0]["secretName"], "acme-admin-tls")
        self.assertIn("2 objects (1 Ingress, 1 NetworkPolicy)", err)


class ForwardedHeaders(unittest.TestCase):
    """Behind Traefik the control plane trusts X-Forwarded-* only from a pod address (10-pilot-config.yaml); Tomcat's
    remote-IP valve matches the TCP peer's address against the whole expression (Java `matches()`, here fullmatch)."""

    @staticmethod
    def address(*octets: int) -> str:
        return ".".join(str(o) for o in octets)

    def test_pilot_trusts_forwarded_headers_from_the_pod_network_only(self):
        import re
        for product, objects in _PILOT.items():
            with self.subTest(product):
                data = next(o for o in objects if o["kind"] == "ConfigMap"
                            and o["metadata"]["name"] == f"{product}-control-config")["data"]
                self.assertEqual(data["RWSAFE_FORWARD_HEADERS"], "native")
                self.assertEqual(data["RWSAFE_COOKIE_SECURE"], "true")
                trusted = re.compile(data["RWSAFE_TRUSTED_PROXIES"])
                for octets in ((10, 42, 0, 9), (10, 42, 255, 254)):
                    self.assertTrue(trusted.fullmatch(self.address(*octets)), octets)
                # The port-forward's loopback peer, other private and documentation ranges, IPv6 loopback, and a pod
                # address with something appended: never trusted.
                for peer in (self.address(127, 0, 0, 1), self.address(10, 43, 0, 1), self.address(10, 4, 2, 1),
                             self.address(192, 0, 2, 10), self.address(198, 51, 100, 7), "::1", "0:0:0:0:0:0:0:1",
                             self.address(10, 42, 0, 9) + ".1", "1" + self.address(10, 42, 0, 9)):
                    self.assertIsNone(trusted.fullmatch(peer), peer)


class Probe(unittest.TestCase):
    """The synthetic probe (60-icap-probe.yaml): the data plane image with the probe's main class, its own
    ServiceAccount without a token, the ICAP Service as its only destination besides DNS, under both product names."""

    def test_probe_shape(self):
        for product, objects in _PILOT.items():
            with self.subTest(product):
                cron = next(o for o in objects if mc.ident(o) == f"CronJob/{product}/{product}-icap-probe")
                self.assertEqual(cron["spec"]["concurrencyPolicy"], "Forbid")
                self.assertLessEqual(cron["spec"]["successfulJobsHistoryLimit"], 3)
                self.assertLessEqual(cron["spec"]["failedJobsHistoryLimit"], 3)
                self.assertLessEqual(cron["spec"]["jobTemplate"]["spec"]["activeDeadlineSeconds"], 300)
                self.assertEqual(cron["spec"]["jobTemplate"]["spec"]["backoffLimit"], 0)
                spec = mc.pod_template(cron)[1]
                self.assertEqual(spec["priorityClassName"], f"{product}-batch")
                self.assertEqual(spec["serviceAccountName"], f"{product}-icap-probe")
                c = spec["containers"][0]
                self.assertEqual(c["image"], f"{mc.IN_CLUSTER_REGISTRY}/{product}-dataplane@{DIGESTS['dataplane']}")
                self.assertEqual(c["command"][-1], "io.rwsafe.dataplane.boot.IcapProbe")
                self.assertEqual({e["name"]: e["value"] for e in c["env"]}["RWSAFE_PROBE_TARGET"],
                                 f"icap://{product}-icap:1344")
                labels = mc.pod_template(cron)[0]["labels"]
                self.assertEqual(labels["app.kubernetes.io/name"], f"{product}-icap-probe")
                # Never selected by the ICAP Services or the PDB (they select component icap).
                self.assertNotEqual(labels.get("app.kubernetes.io/component"), "icap")

    def test_only_the_probe_and_the_e2e_job_reach_icap_and_the_probe_reaches_nothing_else(self):
        for product, objects in _PILOT.items():
            with self.subTest(product):
                policies = {o["metadata"]["name"]: o["spec"] for o in objects if o["kind"] == "NetworkPolicy"}
                icap_from = [p["podSelector"]["matchLabels"]["app.kubernetes.io/name"]
                             for r in policies[f"{product}-icap"]["ingress"] for p in r["from"]]
                self.assertEqual(icap_from, [f"{product}-icap-e2e", f"{product}-icap-probe"])
                probe = policies[f"{product}-icap-probe"]
                self.assertEqual(set(probe["policyTypes"]), {"Ingress", "Egress"})
                self.assertNotIn("ingress", probe)
                egress = [(json.dumps(r["to"], sort_keys=True), sorted((p["protocol"], p["port"]) for p in r["ports"]))
                          for r in probe["egress"]]
                self.assertEqual(len(egress), 2)
                self.assertIn(f'"app.kubernetes.io/name": "{product}-icap"', egress[0][0])
                self.assertEqual(egress[0][1], [("TCP", 1344)])
                self.assertIn('"k8s-app": "kube-dns"', egress[1][0])
                self.assertEqual(egress[1][1], [("TCP", 53), ("UDP", 53)])


class K3sTarget(unittest.TestCase):
    # PR 33 review D-06: the k3s target renders and passes under another name too.
    def test_k3s_under_another_name(self):
        with self.assertRaises(render.Refused):   # the k3s overlay still holds its directory and SIEM placeholders
            render.render_target("k3s", "acme", DIGESTS)
        objects = render.render_target("k3s", "acme")
        self.assertEqual(mc.source_name_references(objects), [])
        lb = next(o for o in objects if o["kind"] == "Service" and o["spec"].get("type") == "LoadBalancer")
        self.assertEqual((lb["metadata"]["name"], lb["spec"]["allocateLoadBalancerNodePorts"],
                          lb["spec"]["externalTrafficPolicy"]), ("acme-icap-lb", False, "Cluster"))


def v4(*octets: int, prefix: int | None = None) -> str:
    """A synthetic address built at runtime (the privacy gate refuses a non-documentation dotted literal)."""
    return ".".join(str(o) for o in octets) + (f"/{prefix}" if prefix is not None else "")


GOOD_RANGES = ["192.0.2.0/24", "198.51.100.7"]
# What the range rules refuse, with the rule each one breaks.
BAD_RANGES = {
    v4(0, 0, 0, 0, prefix=0): "broader than /16",
    v4(10, 0, 0, 0, prefix=8): "broader than /16",
    v4(10, 42, 3, 0, prefix=24): "the cluster's pod range",
    v4(10, 43, 0, 10): "the cluster's Service range",
    v4(127, 0, 0, 1): "loopback",
    v4(169, 254, 1, 0, prefix=24): "link-local",
    v4(224, 0, 0, 0, prefix=24): "multicast",
    v4(255, 255, 255, 255): "reserved or broadcast",
    v4(0, 0, 0, 0): "\"this network\"",
    "192.0.2.1/24": "host bits",
    "2001:db8::/64": "not IPv4",
    "dc-one.example.invalid": "not an IPv4",
    " 192.0.2.0/24": "spaces",
    # PR 54 review Q-1: public address space is refused (RFC 1918 private ranges only, besides the placeholders).
    v4(11, 0, 0, 0, prefix=16): "RFC 1918",
    v4(100, 64, 0, 0, prefix=16): "RFC 1918",
}
PRIVATE_RANGES = [v4(10, 20, 0, 0, prefix=16), v4(172, 16, 5, 0, prefix=24), v4(192, 168, 9, 9)]


def range_file(directory: str, text: str, mode: int = 0o600) -> Path:
    path = Path(directory) / "directory.env"
    path.write_text(text)
    os.chmod(path, mode)
    return path


def directory_rule(objects: list[dict], product: str) -> dict:
    policy = render.directory_policy(objects, product)
    return policy["spec"]["egress"][0]


class DirectoryEgress(unittest.TestCase):
    """PILOT_RUNBOOK.md step 14.5: the pilot keeps the directory egress with the screen's four ports and a placeholder
    that reaches nothing; the render fills it from the host's owner-only range file and prints counts only."""

    def test_committed_pilot_policy_is_the_placeholder_on_the_four_ports(self):
        for product, objects in _PILOT.items():
            with self.subTest(product):
                policy = render.directory_policy(objects, product)
                self.assertEqual(policy["spec"]["policyTypes"], ["Egress"])
                self.assertEqual(policy["spec"]["podSelector"],
                                 {"matchLabels": {"app.kubernetes.io/name": f"{product}-control"}})
                rule = directory_rule(objects, product)
                self.assertEqual(rule["to"], [{"ipBlock": {"cidr": "192.0.2.0/24"}}])
                self.assertEqual(sorted((p["protocol"], p["port"]) for p in rule["ports"]),
                                 [("TCP", 389), ("TCP", 636), ("TCP", 3268), ("TCP", 3269)])
                # the control phase applies it (step 9 and 14.5)
                self.assertIn(policy, render.select_phase(objects, product, "control"))

    def test_render_target_fills_the_ranges_and_passes_the_release_check(self):
        objects = render.render_target("pilot", "acme", DIGESTS, directory_ranges=["192.0.2.0/25", "203.0.113.9/32"])
        rule = directory_rule(objects, "acme")
        self.assertEqual(rule["to"], [{"ipBlock": {"cidr": "192.0.2.0/25"}}, {"ipBlock": {"cidr": "203.0.113.9/32"}}])
        self.assertEqual(len(rule["ports"]), 4)

    def test_render_target_refuses_bad_ranges_through_the_check(self):
        for bad in (v4(10, 42, 0, 0, prefix=16), v4(10, 0, 0, 0, prefix=8)):
            with self.subTest(bad), self.assertRaises(render.Refused) as ctx:
                render.render_target("pilot", "rwsafe", DIGESTS, directory_ranges=[bad])
            self.assertNotIn(bad, str(ctx.exception))
        with self.assertRaises(render.Refused):
            render.render_target("k3s", "rwsafe", directory_ranges=["192.0.2.0/24"])

    def test_main_with_a_range_file_prints_only_the_count(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as out_dir:
            path = range_file(d, "# synthetic\nDIRECTORY_CIDR=203.0.113.0/26\n\nDIRECTORY_CIDR=198.51.100.7\n")
            # the whole render: the pilot release check needs every policy (PR 56 review D-01)
            target = Path(out_dir) / "app.json"
            rc, out, err = run(["--product", "acme", "--dataplane-digest", DIGESTS["dataplane"],
                                "--control-digest", DIGESTS["control"],
                                "--directory-env", str(path), "--output", str(target)])
            self.assertEqual(rc, 0, err)
            self.assertEqual(out, "")
            self.assertIn("directory egress: 2 range(s)", err)
            for value in ("203.0.113", "198.51.100"):
                self.assertNotIn(value, err)
            self.assertEqual(os.stat(target).st_mode & 0o777, 0o600)
            items = json.loads(target.read_text())["items"]
            self.assertEqual(directory_rule(items, "acme")["to"],
                             [{"ipBlock": {"cidr": "203.0.113.0/26"}}, {"ipBlock": {"cidr": "198.51.100.7/32"}}])
            check_out = io.StringIO()
            with contextlib.redirect_stdout(check_out):
                rc = mc.main(["--rendered", str(target), "--release", "--product", "acme", "--pilot"])
            self.assertEqual(rc, 0, check_out.getvalue())
            # The NetworkPolicies of the control phase alone need no digests (step 14.5).
            rc, out, err = run(["--product", "acme", "--phase", "control", "--kinds", "NetworkPolicy",
                                "--directory-env", str(path)])
            self.assertEqual(rc, 0, err)
            self.assertIn("directory egress: 2 range(s)", err)
            self.assertTrue(all(o["kind"] == "NetworkPolicy" for o in json.loads(out)["items"]))

    def test_main_without_the_file_keeps_the_placeholder_with_a_note(self):
        rc, out, err = run(["--product", "acme", "--dataplane-digest", DIGESTS["dataplane"],
                            "--control-digest", DIGESTS["control"], "--phase", "control"])
        self.assertEqual(rc, 0, err)
        self.assertIn("directory egress: no range file; the policy keeps its placeholder", err)
        items = json.loads(out)["items"]
        self.assertEqual(directory_rule(items, "acme")["to"], [{"ipBlock": {"cidr": "192.0.2.0/24"}}])
        # Another phase does not hold the policy and says nothing about it.
        rc, _, err = run(["--product", "acme", "--dataplane-digest", DIGESTS["dataplane"],
                          "--control-digest", DIGESTS["control"], "--phase", "ingress"])
        self.assertEqual(rc, 0, err)
        self.assertNotIn("directory egress", err)

    def test_main_refuses_an_unusable_file_without_printing_a_value(self):
        cases = {
            "loose mode": ("DIRECTORY_CIDR=192.0.2.0/24\n", 0o644, "group or others"),
            "unknown key": ("LDAP_CIDR=192.0.2.0/24\n", 0o600, "line 1 is not DIRECTORY_CIDR"),
            "empty": ("# nothing\n", 0o600, "no DIRECTORY_CIDR value"),
            "overlap": ("DIRECTORY_CIDR=192.0.2.0/24\nDIRECTORY_CIDR=192.0.2.64/26\n", 0o600, "value 2 overlaps value 1"),
            "too many": ("".join(f"DIRECTORY_CIDR=203.0.113.{i * 16}/28\n" for i in range(9)), 0o600, "more than 8"),
        }
        for bad, rule in BAD_RANGES.items():
            cases[rule] = (f"DIRECTORY_CIDR={bad}\n", 0o600, rule)
        for name, (text, mode, rule) in cases.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as d:
                path = range_file(d, text, mode)
                rc, out, err = run(["--product", "acme", "--phase", "control", "--kinds", "NetworkPolicy",
                                    "--directory-env", str(path)])
                self.assertEqual(rc, 1, err)
                self.assertEqual(out, "")
                self.assertIn(rule, err)
                for line in text.splitlines():
                    value = line.partition("=")[2].strip()
                    if value:
                        self.assertNotIn(value, err)

    def test_main_refuses_a_symlink_a_missing_named_file_and_another_target(self):
        with tempfile.TemporaryDirectory() as d:
            real = range_file(d, "DIRECTORY_CIDR=192.0.2.0/24\n")
            link = Path(d) / "link.env"
            link.symlink_to(real)
            rc, _, err = run(["--product", "acme", "--phase", "control", "--kinds", "NetworkPolicy",
                              "--directory-env", str(link)])
            self.assertEqual(rc, 1)
            self.assertIn("symbolic link", err)
            rc, _, err = run(["--product", "acme", "--phase", "control", "--kinds", "NetworkPolicy",
                              "--directory-env", str(Path(d) / "missing.env")])
            self.assertEqual(rc, 1)
            self.assertIn("does not exist", err)
            rc, _, _ = run(["--target", "k3s", "--directory-env", str(real)])
            self.assertEqual(rc, 2)

    def test_a_filled_render_is_never_written_into_the_repository(self):
        with tempfile.TemporaryDirectory() as d:
            path = range_file(d, "DIRECTORY_CIDR=192.0.2.0/24\n")
            target = mc.REPO_ROOT / "build" / "never-written.json"
            rc, out, err = run(["--product", "acme", "--phase", "control", "--kinds", "NetworkPolicy",
                                "--directory-env", str(path), "--output", str(target)])
            self.assertEqual(rc, 1)
            self.assertIn("outside the repository", err)
            self.assertFalse(target.exists())

    def test_the_committed_tree_holds_no_range_file(self):
        tracked = subprocess.run(["git", "-C", str(mc.REPO_ROOT), "ls-files"], capture_output=True, text=True)
        if tracked.returncode != 0:   # a `git archive` copy on the host has no .git
            self.skipTest("not a git checkout")
        self.assertFalse([f for f in tracked.stdout.splitlines() if f.endswith("directory.env")])


class DirectoryRangeFile(unittest.TestCase):
    """PR 54 review D-02: write refuses the repository and symbolic links and leaves no temporary file behind; load
    refuses before reading, never prints a path, and turns every read problem into a refusal."""

    def test_write_refuses_the_repository_and_symlinks(self):
        with self.assertRaises(directory_range.RangeFileError):
            directory_range.write(mc.REPO_ROOT / "build" / "directory.env", ["192.0.2.0/24"])
        self.assertFalse((mc.REPO_ROOT / "build" / "directory.env").exists())
        with tempfile.TemporaryDirectory() as d:
            real = Path(d) / "real"
            real.mkdir()
            link = Path(d) / "link"
            link.symlink_to(real)
            for target in (link / "directory.env", Path(d) / "file-link.env"):
                if target.name == "file-link.env":
                    target.symlink_to(real / "x.env")
                with self.subTest(target.name), self.assertRaises(directory_range.RangeFileError) as ctx:
                    directory_range.write(target, ["192.0.2.0/24"])
                self.assertIn("symbolic link", str(ctx.exception))
            self.assertEqual(list(real.iterdir()), [])

    def test_write_leaves_no_temporary_file_on_failure(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "directory.env"
            target.mkdir()   # os.replace onto a directory fails after the temporary file was written
            with self.assertRaises(directory_range.RangeFileError) as ctx:
                directory_range.write(target, ["192.0.2.0/24"])
            self.assertNotIn(d, str(ctx.exception))
            self.assertEqual(sorted(p.name for p in Path(d).iterdir()), ["directory.env"])

    def test_load_refuses_unreadable_and_non_utf8_files_without_a_path(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "directory.env"
            path.write_bytes(b"DIRECTORY_CIDR=192.0.2.0/24\n\xff\xfe\n")
            os.chmod(path, 0o600)
            with self.assertRaises(directory_range.RangeFileError) as ctx:
                directory_range.load(path)
            self.assertIn("not UTF-8", str(ctx.exception))
            os.chmod(path, 0o000)
            try:
                if os.access(path, os.R_OK):
                    self.skipTest("running with privileges that read a 0000 file")
                with self.assertRaises(directory_range.RangeFileError) as ctx:
                    directory_range.load(path)
                self.assertNotIn(d, str(ctx.exception))
            finally:
                os.chmod(path, 0o600)
            # a loose mode is refused before the content is read (the content here would not even parse)
            path.write_bytes(b"\xff")
            os.chmod(path, 0o644)
            with self.assertRaises(directory_range.RangeFileError) as ctx:
                directory_range.load(path)
            self.assertIn("group or others", str(ctx.exception))
            self.assertNotIn("UTF-8", str(ctx.exception))

    def test_gitignore_covers_the_file_and_its_temporary_name(self):
        lines = (mc.REPO_ROOT / ".gitignore").read_text().splitlines()
        self.assertIn("directory.env", lines)
        self.assertIn(".directory.env.incoming", lines)


class RenderOutput(unittest.TestCase):
    """PR 54 review D-03: --output is a regular file only, never through a symbolic link, never a terminal or device."""

    def test_output_refuses_links_and_devices(self):
        with tempfile.TemporaryDirectory() as d:
            ranges = range_file(d, "DIRECTORY_CIDR=192.0.2.0/24\n")
            real = Path(d) / "real.json"
            link = Path(d) / "link.json"
            link.symlink_to(real)
            for target in (str(link), "/dev/null", "/dev/stdout"):
                with self.subTest(target):
                    rc, out, err = run(["--product", "acme", "--phase", "control", "--kinds", "NetworkPolicy",
                                        "--directory-env", str(ranges), "--output", target])
                    self.assertEqual(rc, 1, err)
                    self.assertIn("render refused: --output", err)
                    self.assertNotIn(d, err)
            self.assertFalse(real.exists())


class DirectoryRangeHelper(unittest.TestCase):
    """tools/pilot/directory_range.sh (the PO, on the host): reads ranges without echo, checks each, writes the 0600
    file, prints only the count; tools/pilot/directory_range.py holds the rules."""

    def helper(self, typed: str, dest: Path) -> subprocess.CompletedProcess:
        env = {k: v for k, v in os.environ.items() if k not in ("PRODUCT", "DIRECTORY_ENV")}
        env["DIRECTORY_ENV"] = str(dest)
        return subprocess.run(["bash", str(HELPER)], input=typed, capture_output=True, text=True, env=env, timeout=60)

    def test_rules(self):
        self.assertEqual(directory_range.entry_problems(GOOD_RANGES), [])
        self.assertEqual(directory_range.entry_problems(PRIVATE_RANGES), [])
        # PR 54 review D-02: an invalid earlier range is a refusal, never an exception that carries it.
        self.assertTrue(directory_range.next_problems(["2001:db8::/64"], "192.0.2.0/24"))
        self.assertTrue(directory_range.next_problems(["not-a-range"], "192.0.2.0/24"))
        for bad, rule in BAD_RANGES.items():
            with self.subTest(rule):
                problems = directory_range.entry_problems([bad])
                self.assertTrue(problems and rule in problems[0], problems)
                self.assertNotIn(bad.strip(), " ".join(problems))
        self.assertEqual(directory_range.normalise("198.51.100.7"), "198.51.100.7/32")

    def test_helper_writes_the_accepted_ranges_and_prints_the_count(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "directory.env"
            refused = v4(10, 42, 7, 0, prefix=24)
            typed = "\n".join(["192.0.2.0/24", refused, "198.51.100.7", "192.0.2.128/25", ""]) + "\n"
            res = self.helper(typed, dest)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("2 range(s) written", res.stdout)
            self.assertIn("range 2 not taken", res.stderr)
            self.assertIn("range 4 not taken", res.stderr)
            for value in ("192.0.2", "198.51.100", refused):
                self.assertNotIn(value, res.stdout + res.stderr)
            self.assertEqual(os.stat(dest).st_mode & 0o777, 0o600)
            self.assertEqual(directory_range.load(dest), ["192.0.2.0/24", "198.51.100.7/32"])
            # Running it again replaces the file as a whole.
            res = self.helper("203.0.113.0/24\n", dest)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(directory_range.load(dest), ["203.0.113.0/24"])

    def test_helper_writes_nothing_without_an_accepted_range(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "directory.env"
            res = self.helper(v4(10, 0, 0, 0, prefix=8) + "\n\n", dest)
            self.assertEqual(res.returncode, 1)
            self.assertIn("no range accepted", res.stderr)
            self.assertFalse(dest.exists())

    def test_helper_takes_at_most_eight(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "directory.env"
            typed = "".join(f"203.0.113.{i * 16}/28\n" for i in range(10))
            res = self.helper(typed, dest)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("8 range(s) written", res.stdout)
            self.assertEqual(len(directory_range.load(dest)), 8)

    def test_helper_accepts_crlf_lines_and_a_crlf_blank_line_ends(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "directory.env"
            res = self.helper("192.0.2.0/24\r\n\r\n198.51.100.0/24\r\n", dest)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(directory_range.load(dest), ["192.0.2.0/24"])

    def home_helper(self, home: Path, typed: str) -> subprocess.CompletedProcess:
        env = {k: v for k, v in os.environ.items() if k not in ("PRODUCT", "DIRECTORY_ENV")}
        env["HOME"] = str(home)
        return subprocess.run(["bash", str(HELPER)], input=typed, capture_output=True, text=True, env=env, timeout=60)

    def test_helper_writes_the_default_path_and_refuses_a_symlinked_directory(self):
        product = mc.default_product()
        with tempfile.TemporaryDirectory() as d:
            home = Path(d) / "home"
            home.mkdir()
            res = self.home_helper(home, "192.0.2.0/24\n\n")
            self.assertEqual(res.returncode, 0, res.stderr)
            dest = home / ".config" / product / "pilot" / "directory.env"
            self.assertEqual(directory_range.load(dest), ["192.0.2.0/24"])
            self.assertNotIn(str(home), res.stdout + res.stderr)
            self.assertEqual(os.stat(dest.parent).st_mode & 0o777, 0o700)
            check = subprocess.run([sys.executable, "-B", str(HELPER.with_suffix(".py")), "--check", "--product",
                                    product], capture_output=True, text=True, env={**os.environ, "HOME": str(home)},
                                   timeout=60)
            self.assertEqual(check.returncode, 0, check.stderr)
            self.assertIn("1 range(s) valid", check.stdout)
            other = Path(d) / "elsewhere"
            other.mkdir()
            home2 = Path(d) / "home2"
            (home2 / ".config").mkdir(parents=True)
            (home2 / ".config" / product).symlink_to(other)
            res = self.home_helper(home2, "192.0.2.0/24\n\n")
            self.assertEqual(res.returncode, 1)
            self.assertIn("symbolic link", res.stderr)
            self.assertEqual(list(other.iterdir()), [])

    def test_helper_refuses_arguments(self):
        res = subprocess.run(["bash", str(HELPER), "192.0.2.0/24"], capture_output=True, text=True, timeout=60)
        self.assertEqual(res.returncode, 2)
        self.assertNotIn("192.0.2", res.stderr)


# Synthetic private addresses, built at runtime (the privacy gate refuses a non-documentation dotted literal).
PROXIES = [v4(10, 20, 30, 41), v4(10, 20, 30, 42), v4(172, 16, 5, 9)]
# What the ICAP client rules refuse, with the rule each one breaks.
BAD_PROXIES = {
    "192.0.2.10": "not a private (RFC 1918)",
    "198.51.100.7": "not a private (RFC 1918)",
    v4(8, 8, 4, 4): "not a private (RFC 1918)",
    v4(10, 20, 30, 0, prefix=24): "not a single IPv4 address",
    v4(10, 20, 30, 41, prefix=32): "not a single IPv4 address",
    v4(10, 42, 0, 7): "the cluster's pod range",
    v4(10, 43, 0, 10): "the cluster's Service range",
    v4(127, 0, 0, 1): "loopback",
    v4(169, 254, 1, 1): "link-local",
    v4(224, 0, 0, 1): "multicast",
    v4(255, 255, 255, 255): "reserved or broadcast",
    v4(0, 0, 0, 0): "\"this network\"",
    "2001:db8::1": "not IPv4",
    "proxy-one.example.invalid": "not a single IPv4 address",
    " " + v4(10, 20, 30, 41): "spaces",
}


def clients_file(directory: str, text: str, mode: int = 0o600) -> Path:
    path = Path(directory) / "icap-clients.env"
    path.write_text(text)
    os.chmod(path, mode)
    return path


def clients_rule(objects: list[dict], product: str) -> dict:
    return render.icap_clients_policy(objects, product)["spec"]["ingress"][0]


ICAP_POLICIES = ["--product", "acme", "--phase", "icap", "--kinds", "NetworkPolicy"]


class IcapClients(unittest.TestCase):
    """PILOT_RUNBOOK.md step 11.5: the ICAP pods admit TCP 1344 from the ProxySG addresses only; the committed policy
    holds a documentation /32 placeholder that admits no proxy; the render fills it from the host's owner-only file and
    prints counts only."""

    def test_committed_pilot_policy_is_the_placeholder_on_1344(self):
        for product, objects in _PILOT.items():
            with self.subTest(product):
                policy = render.icap_clients_policy(objects, product)
                self.assertEqual(policy["metadata"]["namespace"], product)
                self.assertEqual(policy["spec"]["policyTypes"], ["Ingress"])
                self.assertEqual(policy["spec"]["podSelector"],
                                 {"matchLabels": {"app.kubernetes.io/name": f"{product}-icap"}})
                rule = clients_rule(objects, product)
                self.assertEqual(rule["from"], [{"ipBlock": {"cidr": mc.ICAP_CLIENTS_PLACEHOLDER}}])
                self.assertEqual(rule["ports"], [{"protocol": "TCP", "port": 1344}])
                # the ICAP phase applies it (steps 9b and 11.5), and the ServiceLB-pod policy is gone
                self.assertIn(policy, render.select_phase(objects, product, "icap"))
                names = {o["metadata"]["name"] for o in objects if o["kind"] == "NetworkPolicy"}
                self.assertNotIn(f"{product}-icap-from-servicelb", names)
                self.assertIn(f"{product}-icap", names)

    def test_render_target_fills_the_addresses(self):
        objects = render.render_target("pilot", "acme", DIGESTS, icap_addresses=PROXIES)
        self.assertEqual(clients_rule(objects, "acme")["from"], [{"ipBlock": {"cidr": f"{a}/32"}} for a in PROXIES])

    def test_render_target_refuses_bad_addresses_through_the_check(self):
        for bad in (v4(10, 42, 0, 7), "192.0.2.10"):
            with self.subTest(bad), self.assertRaises(render.Refused) as ctx:
                render.render_target("pilot", "rwsafe", DIGESTS, icap_addresses=[bad])
            self.assertNotIn(bad, str(ctx.exception))
        with self.assertRaises(render.Refused):
            render.render_target("k3s", "rwsafe", icap_addresses=PROXIES[:1])

    def test_main_with_a_file_prints_only_the_count(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as out_dir:
            path = clients_file(d, "# synthetic\r\n" + "".join(f"PROXY_ADDR={a}\n" for a in PROXIES) + "\n")
            target = Path(out_dir) / "app.json"
            rc, out, err = run(["--product", "acme", "--dataplane-digest", DIGESTS["dataplane"],
                                "--control-digest", DIGESTS["control"],
                                "--icap-clients-env", str(path), "--output", str(target)])
            self.assertEqual(rc, 0, err)
            self.assertEqual(out, "")
            self.assertIn("render: icap clients: 3 address(es)", err)
            for a in PROXIES:
                self.assertNotIn(a, err)
            self.assertEqual(os.stat(target).st_mode & 0o777, 0o600)
            items = json.loads(target.read_text())["items"]
            self.assertEqual(clients_rule(items, "acme")["from"], [{"ipBlock": {"cidr": f"{a}/32"}} for a in PROXIES])
            check_out = io.StringIO()
            with contextlib.redirect_stdout(check_out):
                rc = mc.main(["--rendered", str(target), "--release", "--product", "acme", "--pilot"])
            self.assertEqual(rc, 0, check_out.getvalue())
            # The ICAP phase's NetworkPolicies alone need no digests (step 11.5).
            rc, out, err = run(ICAP_POLICIES + ["--icap-clients-env", str(path)])
            self.assertEqual(rc, 0, err)
            self.assertIn("icap clients: 3 address(es)", err)
            items = json.loads(out)["items"]
            self.assertTrue(items and all(o["kind"] == "NetworkPolicy" for o in items))
            self.assertIn("NetworkPolicy/acme/acme-icap-from-proxies", [mc.ident(o) for o in items])

    def test_main_without_the_file_keeps_the_placeholder_with_a_note(self):
        rc, out, err = run(ICAP_POLICIES)
        self.assertEqual(rc, 0, err)
        self.assertIn("icap clients: no ICAP clients file; the policy keeps its placeholder, which admits no proxy", err)
        self.assertEqual(clients_rule(json.loads(out)["items"], "acme")["from"],
                         [{"ipBlock": {"cidr": mc.ICAP_CLIENTS_PLACEHOLDER}}])
        rc, _, err = run(["--product", "acme", "--phase", "ingress"])
        self.assertEqual(rc, 0, err)
        self.assertNotIn("icap clients", err)

    def test_main_refuses_an_unusable_file_without_printing_a_value(self):
        a, b = PROXIES[0], PROXIES[1]
        cases = {
            "loose mode": (f"PROXY_ADDR={a}\n", 0o640, "group or others"),
            "unknown key": (f"PROXY={a}\n", 0o600, "line 1 is not PROXY_ADDR"),
            "empty": ("# nothing\n", 0o600, "no PROXY_ADDR value"),
            "repeat": (f"PROXY_ADDR={a}\nPROXY_ADDR={b}\nPROXY_ADDR={a}\n", 0o600, "value 3 repeats value 1"),
            "too many": ("".join(f"PROXY_ADDR={v4(10, 20, 31, i)}\n" for i in range(1, 10)), 0o600, "more than 8"),
        }
        for bad, rule in BAD_PROXIES.items():
            cases[rule + bad] = (f"PROXY_ADDR={bad}\n", 0o600, rule)
        for name, (text, mode, rule) in cases.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as d:
                path = clients_file(d, text, mode)
                rc, out, err = run(ICAP_POLICIES + ["--icap-clients-env", str(path)])
                self.assertEqual(rc, 1, err)
                self.assertEqual(out, "")
                self.assertIn(rule, err)
                for line in text.splitlines():
                    value = line.partition("=")[2].strip()
                    if value:
                        self.assertNotIn(value, err)

    def test_main_refuses_a_symlink_a_missing_named_file_and_another_target(self):
        with tempfile.TemporaryDirectory() as d:
            real = clients_file(d, f"PROXY_ADDR={PROXIES[0]}\n")
            link = Path(d) / "link.env"
            link.symlink_to(real)
            rc, _, err = run(ICAP_POLICIES + ["--icap-clients-env", str(link)])
            self.assertEqual(rc, 1)
            self.assertIn("symbolic link", err)
            rc, _, err = run(ICAP_POLICIES + ["--icap-clients-env", str(Path(d) / "missing.env")])
            self.assertEqual(rc, 1)
            self.assertIn("does not exist", err)
            rc, _, _ = run(["--target", "k3s", "--icap-clients-env", str(real)])
            self.assertEqual(rc, 2)

    def test_a_filled_render_is_never_written_into_the_repository_or_a_device(self):
        with tempfile.TemporaryDirectory() as d:
            path = clients_file(d, f"PROXY_ADDR={PROXIES[0]}\n")
            target = mc.REPO_ROOT / "build" / "never-written.json"
            rc, out, err = run(ICAP_POLICIES + ["--icap-clients-env", str(path), "--output", str(target)])
            self.assertEqual(rc, 1)
            self.assertIn("the ICAP client addresses; --output must be outside the repository", err)
            self.assertFalse(target.exists())
            # A symbolic link, a device and /dev/stdout are refused as --output before anything is written.
            victim = Path(d) / "victim.json"
            victim.write_text("kept\n")
            link = Path(d) / "out.json"
            link.symlink_to(victim)
            for output in (str(link), os.devnull, "/dev/stdout"):
                with self.subTest(output):
                    rc, out, err = run(ICAP_POLICIES + ["--icap-clients-env", str(path), "--output", output])
                    self.assertEqual(rc, 1, err)
                    self.assertIn("render refused: --output", err)
                    self.assertEqual(out, "")
                    self.assertNotIn(PROXIES[0], err)
            self.assertEqual(victim.read_text(), "kept\n")

    def test_a_filled_render_goes_to_a_pipe_only(self):
        """PR 56 review D-02: without --output a filled render is written only to a pipe; a redirected file is refused
        before anything is written."""
        with tempfile.TemporaryDirectory() as d:
            path = clients_file(d, f"PROXY_ADDR={PROXIES[0]}\n")
            env = {k: v for k, v in os.environ.items() if k != "PRODUCT"}
            env["HOME"] = d
            argv = [sys.executable, "-B", str(Path(render.__file__)), *ICAP_POLICIES, "--icap-clients-env", str(path)]
            res = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=120)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn(f"{PROXIES[0]}/32", res.stdout)
            redirected = Path(d) / "redirected.json"
            with open(redirected, "w") as out:
                res = subprocess.run(argv, stdout=out, stderr=subprocess.PIPE, text=True, env=env, timeout=120)
            self.assertEqual(res.returncode, 1, res.stderr)
            self.assertIn("standard output is not a pipe", res.stderr)
            self.assertEqual(redirected.read_text(), "")
            # an --output in a symlinked directory is refused too (PR 56 review D-04)
            real = Path(d) / "real"
            real.mkdir()
            (Path(d) / "linked").symlink_to(real)
            rc, out, err = run(ICAP_POLICIES + ["--icap-clients-env", str(path),
                                                "--output", str(Path(d) / "linked" / "x.json")])
            self.assertEqual(rc, 1, err)
            self.assertIn("is in a directory that is a symbolic link", err)
            self.assertEqual(os.listdir(real), [])

    def test_the_committed_tree_holds_no_clients_file(self):
        tracked = subprocess.run(["git", "-C", str(mc.REPO_ROOT), "ls-files"], capture_output=True, text=True)
        if tracked.returncode != 0:
            self.skipTest("not a git checkout")
        self.assertFalse([f for f in tracked.stdout.splitlines() if f.endswith("icap-clients.env")])


class IcapClientsHelper(unittest.TestCase):
    """tools/pilot/icap_clients.sh (the PO, on the host): reads addresses without echo, checks each, writes the 0600
    file, prints only the count; tools/pilot/icap_clients.py and host_value_file.py hold the rules."""

    def helper(self, typed: str, dest: Path | None = None, home: str | None = None) -> subprocess.CompletedProcess:
        env = {k: v for k, v in os.environ.items() if k not in ("PRODUCT", "ICAP_CLIENTS_ENV")}
        if dest is not None:
            env["ICAP_CLIENTS_ENV"] = str(dest)
        if home is not None:
            env["HOME"] = home
        return subprocess.run(["bash", str(ICAP_HELPER)], input=typed, capture_output=True, text=True, env=env,
                              timeout=60)

    def test_rules(self):
        self.assertEqual(icap_clients.entry_problems(PROXIES), [])
        for bad, rule in BAD_PROXIES.items():
            with self.subTest(rule):
                problems = icap_clients.entry_problems([bad])
                self.assertTrue(problems and rule in problems[0], problems)
                self.assertNotIn(bad.strip(), " ".join(problems))
        self.assertEqual(icap_clients.next_problems(PROXIES[:1], PROXIES[0]), ["repeats an address typed earlier"])
        # PR 56 review D-04: the earlier addresses are checked too
        for accepted in (["192.0.2.10"], [PROXIES[0], PROXIES[0]]):
            self.assertEqual(icap_clients.next_problems(accepted, PROXIES[1]),
                             ["cannot be checked: an earlier address is not valid"])

    def test_load_and_write_refuse_a_symlinked_config_directory(self):
        """PR 56 review D-04: ~/.config/<product>/pilot/<file> is checked up to ~/.config, for reading and writing."""
        with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as elsewhere:
            (Path(elsewhere) / "acme" / "pilot").mkdir(parents=True)
            target = Path(elsewhere) / "acme" / "pilot" / "icap-clients.env"
            target.write_text(f"PROXY_ADDR={PROXIES[0]}\n")
            target.chmod(0o600)
            (Path(home) / ".config").symlink_to(elsewhere)
            via_link = Path(home) / ".config" / "acme" / "pilot" / "icap-clients.env"
            for action in (lambda: icap_clients.load(via_link), lambda: icap_clients.write(via_link, PROXIES[:1])):
                with self.assertRaises(icap_clients.Error) as ctx:
                    action()
                self.assertIn("symbolic link", str(ctx.exception))
            self.assertEqual(target.read_text(), f"PROXY_ADDR={PROXIES[0]}\n")

    def test_helper_asks_one_address_at_a_time_and_prints_the_count(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "icap-clients.env"
            refused = v4(10, 42, 1, 1)
            # address 1 taken, y; 2 (pod range), 3 (repeat), 4 (not private) refused and asked again; 5 taken; a
            # wrong answer is asked again; n writes
            typed = "\n".join([PROXIES[0] + "\r", "y", refused, PROXIES[0], "192.0.2.10", PROXIES[1], "x", "n"]) + "\n"
            res = self.helper(typed, dest)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("2 address(es) written", res.stdout)
            for n in (2, 3, 4):
                self.assertIn(f"adres {n} alinmadi", res.stderr)
            self.assertIn("y ya da n yazin", res.stderr)
            for value in PROXIES + [refused, "192.0.2.10"]:
                self.assertNotIn(value, res.stdout + res.stderr)
            self.assertEqual(os.stat(dest).st_mode & 0o777, 0o600)
            self.assertEqual(icap_clients.load(dest), PROXIES[:2])
            self.assertEqual(sorted(os.listdir(d)), ["icap-clients.env"])   # no temporary file left behind
            # One address (today's test proxy), then n: the file is replaced as a whole.
            res = self.helper(PROXIES[2] + "\nn\n", dest)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("1 address(es) written", res.stdout)
            self.assertEqual(icap_clients.load(dest), PROXIES[2:])

    def test_helper_writes_nothing_when_the_input_ends(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "icap-clients.env"
            for typed in (v4(127, 0, 0, 1) + "\n", "", PROXIES[0] + "\n", PROXIES[0] + "\ny\n"):
                with self.subTest(typed=len(typed)):
                    res = self.helper(typed, dest)
                    self.assertEqual(res.returncode, 1, res.stdout)
                    self.assertIn("input ended; nothing written", res.stderr)
                    self.assertFalse(dest.exists())

    def test_helper_takes_at_most_eight(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "icap-clients.env"
            res = self.helper("".join(f"{v4(192, 168, 7, i)}\ny\n" for i in range(1, 11)), dest)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("8 adres alindi", res.stdout)
            self.assertIn("8 address(es) written", res.stdout)
            self.assertEqual(len(icap_clients.load(dest)), 8)

    def test_helper_default_path_and_a_symlinked_config_directory(self):
        with tempfile.TemporaryDirectory() as home:
            res = self.helper(PROXIES[0] + "\nn\n", home=home)
            self.assertEqual(res.returncode, 0, res.stderr)
            product = mc.default_product()
            dest = Path(home) / ".config" / product / "pilot" / "icap-clients.env"
            self.assertEqual(icap_clients.load(dest), PROXIES[:1])
            self.assertEqual(os.stat(dest.parent).st_mode & 0o777, 0o700)
            self.assertIn(f"~/.config/{product}/pilot/icap-clients.env", res.stdout)
            self.assertNotIn(home, res.stdout + res.stderr)
        with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as elsewhere:
            (Path(home) / ".config").symlink_to(elsewhere)
            res = self.helper(PROXIES[0] + "\nn\n", home=home)
            self.assertEqual(res.returncode, 1)
            self.assertIn("symbolic link", res.stderr)
            self.assertEqual(os.listdir(elsewhere), [])

    def test_writer_refuses_the_repository_a_symlinked_target_or_directory(self):
        with self.assertRaises(icap_clients.Error) as ctx:
            icap_clients.write(mc.REPO_ROOT / "build" / "icap-clients.env", PROXIES[:1])
        self.assertIn("inside the repository", str(ctx.exception))
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as real:
            victim = Path(real) / "victim"
            victim.write_text("kept\n")
            link = Path(d) / "icap-clients.env"
            link.symlink_to(victim)
            with self.assertRaises(icap_clients.Error):
                icap_clients.write(link, PROXIES[:1])
            self.assertEqual(victim.read_text(), "kept\n")
            linked_dir = Path(d) / "pilot"
            linked_dir.symlink_to(real)
            with self.assertRaises(icap_clients.Error):
                icap_clients.write(linked_dir / "icap-clients.env", PROXIES[:1])
            self.assertEqual(sorted(os.listdir(real)), ["victim"])
            # A stale temporary file (or a link in its place) is removed, never followed.
            target = Path(d) / "fresh.env"
            (Path(d) / ".fresh.env.incoming").symlink_to(victim)
            self.assertEqual(icap_clients.write(target, PROXIES[:2]), 2)
            self.assertEqual(victim.read_text(), "kept\n")
            self.assertFalse((Path(d) / ".fresh.env.incoming").exists())

    def test_helper_refuses_arguments(self):
        res = subprocess.run(["bash", str(ICAP_HELPER), PROXIES[0]], capture_output=True, text=True, timeout=60)
        self.assertEqual(res.returncode, 2)
        self.assertNotIn(PROXIES[0], res.stderr)


class ProxySettings(unittest.TestCase):
    """PR 33 review D-03: the build's proxy file is refused with credentials or anything unexpected; no value printed."""
    KEYS = ["HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "GRADLE_OPTS"]
    GOOD = ("HTTP_PROXY=http://proxy.example.invalid:3128\nHTTPS_PROXY=http://proxy.example.invalid:3128\n"
            "NO_PROXY=.svc,.cluster.local,registry.kube-system.svc.cluster.local\n"
            "GRADLE_OPTS=-Dhttps.proxyHost=proxy.example.invalid -Dhttps.proxyPort=3128 "
            "-Dhttp.proxyHost=proxy.example.invalid -Dhttp.proxyPort=3128 -Dhttp.nonProxyHosts=*.svc|*.cluster.local\n")

    def test_valid_and_empty_settings_pass(self):
        self.assertEqual(proxy_settings.problems(self.GOOD, self.KEYS, 0o100600), [])
        empty = "# no proxy here\nHTTP_PROXY=\nHTTPS_PROXY=\nNO_PROXY=\nGRADLE_OPTS=\n"
        self.assertEqual(proxy_settings.problems(empty, self.KEYS, 0o100600), [])

    def test_contract_keys(self):
        self.assertEqual(proxy_settings.contract_keys(_CONTRACTS["rwsafe"]), self.KEYS)

    def test_refusals(self):
        user = "pilotuser"
        cases = {
            "credentials": self.GOOD.replace("http://proxy", f"http://{user}:x@proxy", 1),
            "proxy password": self.GOOD.replace("-Dhttp.proxyPort=3128", "-Dhttp.proxyPassword=x"),
            "proxy user": self.GOOD.replace("-Dhttp.proxyPort=3128", f"-Dhttp.proxyUser={user}"),
            "unknown key": self.GOOD + "TOKEN=x\n",
            "missing key": self.GOOD.replace("NO_PROXY=", "#NO_PROXY="),
            "repeated key": self.GOOD + "HTTP_PROXY=http://proxy.example.invalid:3128\n",
            "scheme": self.GOOD.replace("HTTP_PROXY=http://", "HTTP_PROXY=socks5://"),
            "path": self.GOOD.replace("HTTPS_PROXY=http://proxy.example.invalid:3128",
                                      "HTTPS_PROXY=http://proxy.example.invalid:3128/x"),
            "registry not exempt": self.GOOD.replace(",registry.kube-system.svc.cluster.local", ""),
            "not key=value": self.GOOD + "garbage\n",
        }
        for name, text in cases.items():
            with self.subTest(name):
                found = proxy_settings.problems(text, self.KEYS, 0o100600)
                self.assertNotEqual(found, [])
                self.assertFalse(any(user in f or "example.invalid" in f for f in found), found)
        self.assertNotEqual(proxy_settings.problems(self.GOOD, self.KEYS, 0o100644), [])

    def test_main_prints_no_value(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "build-proxy.env"
            f.write_text(self.GOOD.replace("http://proxy", "http://pilotuser:x@proxy", 1))
            f.chmod(0o600)
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = proxy_settings.main([str(f), str(mc.DEFAULT_CONTRACTS)])
            self.assertEqual(rc, 1)
            self.assertNotIn("pilotuser", out.getvalue() + err.getvalue())
            self.assertNotIn("example.invalid", out.getvalue() + err.getvalue())


class BuildTarget(unittest.TestCase):
    def test_build_renders_under_both_names(self):
        for product, objects in _BUILD.items():
            with self.subTest(product):
                self.assertEqual(render.check_build(objects, product, _CONTRACTS[product]), [])
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

    def test_committed_build_passes_its_check(self):
        for product in ("rwsafe", "acme"):
            with self.subTest(product):
                self.assertEqual(render.check_build(_BUILD[product], product, _CONTRACTS[product]), [])

    # PR 33 review D-02: every core rule on the build manifests, one mutation each.
    def test_build_check_refuses_each_violation(self):
        registry = mc.IN_CLUSTER_REGISTRY
        dest = f"--destination={registry}/acme-dataplane:x"

        def set_args(o, args):
            kaniko(o)["args"] = args

        def without_destination(o):
            set_args(o, [a for a in kaniko(o)["args"] if not a.startswith("--destination=")])

        cases = {
            "foreign destination": lambda o: set_args(o, [f"--destination={registry}/other-dataplane:x"
                                                          if a.startswith("--destination=") else a
                                                          for a in kaniko(o)["args"]]),
            "no destination": without_destination,
            "two destinations": lambda o: kaniko(o)["args"].append(dest),
            "short form": lambda o: (without_destination(o), kaniko(o)["args"].extend(["-d", dest[14:]])),
            "split form": lambda o: (without_destination(o), kaniko(o)["args"].extend(["--destination", dest[14:]])),
            "blanket tls skip": lambda o: kaniko(o)["args"].append("--skip-tls-verify"),
            "registry map to another repository": lambda o: kaniko(o)["args"].append(
                f"--registry-map=registry.access.redhat.com={registry}/other-mirror"),
            "registry map of an unmirrored registry": lambda o: kaniko(o)["args"].append(
                f"--registry-map=quay.io={registry}/acme-mirror"),
            "literal build arg": lambda o: kaniko(o)["args"].append("--build-arg=HTTP_PROXY=http://p.example.invalid:3128"),
            "unknown build arg": lambda o: kaniko(o)["args"].append("--build-arg=TOKEN=$(TOKEN)"),
            "tag": lambda o: kaniko(o).__setitem__("image", "gcr.io/kaniko-project/executor:latest"),
            "placeholder digest": lambda o: kaniko(o).__setitem__("image", "gcr.io/kaniko-project/executor@"
                                                                  + mc.ZERO_DIGEST),
            "secret": lambda o: o.append({"apiVersion": "v1", "kind": "Secret", "metadata": {
                "name": "acme-x", "namespace": "acme-build", "labels": {mc.PART_OF: "acme"}}}),
            "rendered contract configmap": lambda o: o.append({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {
                "name": "acme-build-proxy", "namespace": "acme-build", "labels": {mc.PART_OF: "acme"}},
                "data": {"HTTP_PROXY": ""}}),
            "unknown configmap": lambda o: kaniko(o)["envFrom"].append({"configMapRef": {"name": "acme-other"}}),
            "key outside the contract": lambda o: kaniko(o)["env"].append({"name": "X", "valueFrom": {
                "configMapKeyRef": {"name": "acme-build-config", "key": "other"}}}),
            "secret env": lambda o: kaniko(o)["env"].append({"name": "X", "valueFrom": {
                "secretKeyRef": {"name": "acme-x", "key": "k"}}}),
            "secret envFrom": lambda o: kaniko(o)["envFrom"].append({"secretRef": {"name": "acme-x"}}),
            "literal proxy env": lambda o: kaniko(o)["env"].append({"name": "HTTPS_PROXY", "value": "x"}),
            "token": lambda o: job_spec(o).__setitem__("automountServiceAccountToken", True),
            "host network": lambda o: job_spec(o).__setitem__("hostNetwork", True),
            "host path": lambda o: job_spec(o)["volumes"].append({"name": "h", "hostPath": {"path": "/x"}}),
            "host port": lambda o: kaniko(o).__setitem__("ports", [{"containerPort": 1, "hostPort": 1}]),
            "privileged": lambda o: kaniko(o)["securityContext"].__setitem__("privileged", True),
            "escalation": lambda o: kaniko(o)["securityContext"].__setitem__("allowPrivilegeEscalation", True),
            "capability": lambda o: kaniko(o)["securityContext"].__setitem__("capabilities", {"add": ["SYS_ADMIN"]}),
            "toleration": lambda o: job_spec(o).__setitem__("tolerations", [{
                "key": "node.kubernetes.io/disk-pressure", "operator": "Exists"}]),
            "no limits": lambda o: kaniko(o)["resources"].pop("limits"),
            "priority": lambda o: job_spec(o).__setitem__("priorityClassName", "system-cluster-critical"),
            "namespace": lambda o: job(o)["metadata"].__setitem__("namespace", "acme"),
            "memory emptyDir": lambda o: job_spec(o)["volumes"].append({"name": "m", "emptyDir": {
                "medium": "Memory", "sizeLimit": "1Gi"}}),
        }
        for name, mutate in cases.items():
            with self.subTest(name):
                objects = copy.deepcopy(_BUILD["acme"])
                mutate(objects)
                self.assertNotEqual(render.check_build(objects, "acme", _CONTRACTS["acme"]), [])

    # PR 33 review D-03: the proxy reaches only the build stage, as build arguments, never a runtime layer.
    # The control image also builds the admin UI in an `AS ui` stage first, whose output the Gradle stage copies into
    # /out/app/ui/; the runtime stage still copies one tree from the `build` stage only.
    def test_containerfiles_keep_the_proxy_in_the_build_stage(self):
        for name, stages in (("dataplane", ["build"]), ("control", ["ui", "build"])):
            with self.subTest(name):
                lines = [line.strip() for line in (mc.REPO_ROOT / f"deploy/images/{name}.Containerfile")
                         .read_text().splitlines() if line.strip() and not line.strip().startswith("#")]
                froms = [i for i, line in enumerate(lines) if line.startswith("FROM ")]
                self.assertEqual(len(froms), len(stages) + 1)
                for i, stage in enumerate(stages):
                    self.assertTrue(lines[froms[i]].endswith(f" AS {stage}"), lines[froms[i]])
                build, runtime = lines[froms[len(stages) - 1]:froms[-1]], lines[froms[-1]:]
                if "ui" in stages:
                    ui = lines[froms[0]:froms[1]]
                    for key in ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"):
                        self.assertIn(f"ARG {key}", ui)
                    self.assertEqual([line for line in build if line.startswith("COPY --from=")],
                                     ["COPY --from=ui /out/ui/ /out/app/ui/"])
                    self.assertTrue(any("npm ci --ignore-scripts" in line for line in ui), "npm ci, lockfile only")
                    self.assertFalse(any(line.startswith("RUN npm install") for line in ui), "never npm install")
                for key in render.PROXY_ARGS:
                    self.assertIn(f"ARG {key}", build)
                    self.assertFalse(any(key in line for line in runtime), f"{key} in the runtime stage")
                    self.assertFalse(any(line.startswith("ENV") and key in line for line in lines), key)
                self.assertEqual([line for line in runtime if line.startswith("COPY --from=")],
                                 ["COPY --from=build --chown=0:0 /out/app/ /app/"])
                self.assertFalse(any(line.startswith(("ARG", "ENV HTTP", "ENV HTTPS", "ENV NO_PROXY"))
                                     for line in lines[:froms[0]]))

    # PR 39 review D-03: the ui stage's CA join keeps every BEGIN line on a line of its own, even when a file lacks its
    # final newline (synthetic text, no certificate material).
    def test_the_ui_stage_joins_ca_files_with_a_newline(self):
        import subprocess
        text = (mc.REPO_ROOT / "deploy/images/control.Containerfile").read_text()
        joins = [line.strip().rstrip("\\").strip().rstrip(";") for line in text.splitlines()
                 if "> /tmp/corp-ca.bundle" in line]
        self.assertEqual(len(joins), 1, joins)
        self.assertTrue(joins[0].startswith("for pem in /tmp/corp-ca/*.pem;"), joins[0])
        begin, end = "-----BEGIN " + "CERTIFICATE-----", "-----END " + "CERTIFICATE-----"
        with tempfile.TemporaryDirectory() as tmp:
            ca = Path(tmp) / "corp-ca"
            ca.mkdir()
            (ca / "a.pem").write_text(f"{begin}\nsynthetic-a\n{end}")
            (ca / "b.pem").write_text(f"{begin}\nsynthetic-b\n{end}\n")
            bundle = Path(tmp) / "bundle"
            command = joins[0].replace("/tmp/corp-ca/", f"{ca}/").replace("/tmp/corp-ca.bundle", str(bundle))
            subprocess.run(["sh", "-c", command], check=True)
            lines = bundle.read_text().splitlines()
        self.assertEqual([line for line in lines if "BEGIN" in line or "END" in line], [begin, end, begin, end])

    def test_build_jobs_pass_the_proxy_only_as_build_arguments(self):
        for j in (o for o in _BUILD["acme"] if o["kind"] == "Job"):
            c = mc.containers(mc.pod_template(j)[1])[0]
            self.assertEqual(sorted(a for a in c["args"] if a.startswith("--build-arg=")),
                             sorted(f"--build-arg={k}=$({k})" for k in render.PROXY_ARGS))
            self.assertEqual(c["envFrom"], [{"configMapRef": {"name": "acme-build-proxy"}}])

    def test_digests_are_refused_for_the_build_target(self):
        rc, _, _ = run(["--target", "build", "--phase", "control"])
        self.assertEqual(rc, 2)
        rc, _, _ = run(["--target", "build", "--dataplane-digest", DIGESTS["dataplane"]])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main(verbosity=1)
