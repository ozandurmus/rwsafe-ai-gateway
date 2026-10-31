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
import proxy_settings  # noqa: E402
import render  # noqa: E402

mc = render.mc
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
        policies = {o["metadata"]["name"] for o in objects if o["kind"] == "NetworkPolicy"}
        self.assertFalse({"rwsafe-control-to-directory", "rwsafe-control-to-siem"} & policies)
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
                rc = mc.main(["--rendered", str(target), "--release", "--product", "acme"])
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
                    f"{product}-icap", f"{product}-icap-from-servicelb", f"{product}-icap-metrics-from-scraper",
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
