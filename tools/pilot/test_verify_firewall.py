#!/usr/bin/env python3
"""Self-test of tools/pilot/verify_firewall.sh: `bash -n`; the `--table` part against synthetic `nft -j` output (RFC 5737
addresses only) and its harmful variants (PR 40 review D-02); `--latest` against a stand-in kubectl (D-01); and the PO's
firewall block of step 11 in both runbooks with a stand-in sudo (D-04). The nft JSON shapes are the documented
libnftables ones; UNVERIFIED (2026-10-31) on HOST-A's nft release, which the PO's first run of the one-line check proves
(an unrecognised shape fails, it is never guessed).

Usage: python3 -B tools/pilot/test_verify_firewall.py
"""
from __future__ import annotations

import copy
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "verify_firewall.sh"
REPO = SCRIPT.parents[2]
TABLE = "rwsafe_pilot"
ADDRESSES = ["192.0.2.11", "192.0.2.12", "198.51.100.13"]


def table_json() -> dict:
    """What `nft -j list table inet rwsafe_pilot` prints for the rule of PILOT_RUNBOOK.md step 11."""
    local = {"match": {"op": "==", "left": {"fib": {"result": "type", "flags": ["daddr"]}}, "right": "local"}}
    dport = {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 1344}}
    return {"nftables": [
        {"metainfo": {"version": "1.0.9", "release_name": "synthetic", "json_schema_version": 1}},
        {"table": {"family": "inet", "name": TABLE, "handle": 7}},
        {"set": {"family": "inet", "name": "icap_clients", "table": TABLE, "type": "ipv4_addr", "handle": 1,
                 "flags": ["interval"], "elem": list(ADDRESSES)}},
        {"chain": {"family": "inet", "table": TABLE, "name": "prerouting", "handle": 2, "type": "filter",
                   "hook": "prerouting", "prio": -150, "policy": "accept"}},
        {"rule": {"family": "inet", "table": TABLE, "chain": "prerouting", "handle": 3, "expr": [
            local, dport,
            {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": "new"}},
            {"match": {"op": "!=", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "@icap_clients"}},
            {"drop": None}]}},
        {"rule": {"family": "inet", "table": TABLE, "chain": "prerouting", "handle": 4, "expr": [
            copy.deepcopy(local),
            {"match": {"op": "==", "left": {"meta": {"key": "nfproto"}}, "right": "ipv6"}},
            copy.deepcopy(dport), {"drop": None}]}},
    ]}


def sett(doc: dict) -> dict:
    return doc["nftables"][2]["set"]


def v4(doc: dict) -> list:
    return doc["nftables"][4]["rule"]["expr"]


def v6(doc: dict) -> list:
    return doc["nftables"][5]["rule"]["expr"]


def run(stdin: str, *args: str) -> tuple[int, str]:
    out = subprocess.run(["bash", str(SCRIPT), *args], input=stdin, capture_output=True, text=True, timeout=60,
                         env={"PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin", "PRODUCT": "rwsafe"})
    return out.returncode, out.stdout + out.stderr


class Syntax(unittest.TestCase):
    def test_bash_n(self):
        self.assertEqual(subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True).returncode, 0)

    def test_unknown_argument_is_usage(self):
        rc, out = run("", "--bogus")
        self.assertEqual(rc, 2, out)
        self.assertIn("usage", out)


class Table(unittest.TestCase):
    def test_the_runbook_rule_passes_and_no_address_is_printed(self):
        rc, out = run(json.dumps(table_json()), "--table")
        self.assertEqual(rc, 0, out)
        self.assertIn("result: PASS", out)
        self.assertIn("icap_clients: 1 set(s), 3 element(s), all single addresses", out)
        self.assertIn("2 rule(s); exactly 2 expected, each equal to step 11 in every field and operator: IPv4 1, IPv6 1, "
                      "other 0", out)
        for a in ADDRESSES:
            self.assertNotIn(a, out)
        self.assertNotIn("<ip>", out)

    def test_ct_state_printed_with_equals_also_passes(self):
        doc = table_json()
        v4(doc)[2]["match"].update(op="==", right=["new"])
        rc, out = run(json.dumps(doc), "--table")
        self.assertEqual(rc, 0, out)

    def assertTableFails(self, doc, fragment: str):
        rc, out = run(doc if isinstance(doc, str) else json.dumps(doc), "--table")
        self.assertEqual(rc, 1, out)
        self.assertIn(fragment, out)
        self.assertIn("result: FAIL", out)
        for a in ADDRESSES:
            self.assertNotIn(a, out)

    # PR 40 review D-02: each harmful or merely different variant fails, operators included.
    def test_every_harmful_variant_fails(self):
        rules_other = "other 1"

        def mutate(fn):
            doc = table_json()
            fn(doc)
            return doc

        cases = [
            # the table, the set, the chain
            (lambda d: d.update(nftables=[i for i in d["nftables"] if "table" not in i]), "0 table(s)"),
            (lambda d: d["nftables"].append({"table": {"family": "inet", "name": "other_table", "handle": 9}}),
             "2 table(s)"),
            (lambda d: d["nftables"].append({"map": {"family": "inet", "table": TABLE, "name": "m"}}),
             "1 object(s) of another kind"),
            (lambda d: sett(d).update(elem=[]), "0 element(s)"),
            (lambda d: sett(d)["elem"].pop(), "2 element(s)"),
            (lambda d: sett(d)["elem"].append("192.0.2.14"), "4 element(s)"),
            (lambda d: sett(d)["elem"].__setitem__(0, {"prefix": {"addr": "192.0.2.0", "len": 24}}),
             "not all single addresses"),
            (lambda d: sett(d)["elem"].__setitem__(0, {"range": ["192.0.2.1", "192.0.2.200"]}),
             "not all single addresses"),
            (lambda d: sett(d)["elem"].__setitem__(0, "0.0.0.0/0"), "not all single addresses"),
            (lambda d: sett(d).update(flags=["interval", "timeout"]), "icap_clients: 1 set(s)"),
            (lambda d: sett(d).update(comment="x"), "icap_clients: 1 set(s)"),
            (lambda d: d["nftables"][3]["chain"].update(prio=0), "1 chain(s)"),
            (lambda d: d["nftables"][3]["chain"].update(policy="drop"), "1 chain(s)"),
            (lambda d: d["nftables"].append({"chain": {"family": "inet", "table": TABLE, "name": "extra", "handle": 8}}),
             "2 chain(s)"),
            # the rules: operators
            (lambda d: v4(d)[1]["match"].update(op="!="), rules_other),       # tcp dport != 1344: every other port
            (lambda d: v4(d)[2]["match"].update(op="!="), rules_other),       # ct state != new
            (lambda d: v6(d)[1]["match"].update(op="!="), rules_other),       # meta nfproto != ipv6: IPv4 too
            (lambda d: v4(d)[0]["match"].update(op="!="), rules_other),       # fib daddr type != local: pod traffic
            (lambda d: v4(d)[3]["match"].update(op="=="), rules_other),       # saddr == @icap_clients: drops the proxy
            # the rules: fields and values
            (lambda d: v4(d)[0]["match"]["left"]["fib"].update(flags=["daddr", "iif"]), rules_other),
            (lambda d: v4(d)[1]["match"].update(right=1345), rules_other),
            (lambda d: v4(d)[3]["match"].update(right="@other_set"), rules_other),
            (lambda d: v4(d).__setitem__(-1, {"accept": None}), rules_other),
            (lambda d: v4(d).pop(0), rules_other),                            # without the fib match
            (lambda d: v4(d).insert(4, {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "x"}}),
             rules_other),                                                    # an extra, narrowing match
            (lambda d: v6(d).insert(3, {"counter": {"packets": 0, "bytes": 0}}), rules_other),
            (lambda d: d["nftables"][4]["rule"].update(comment="x"), rules_other),
            (lambda d: d["nftables"][4]["rule"].update(chain="input"), rules_other),
            # the rules: count
            (lambda d: d["nftables"].pop(5), "1 rule(s)"),
            (lambda d: d["nftables"].append(copy.deepcopy(d["nftables"][5])), "3 rule(s)"),
            (lambda d: d["nftables"].append({"rule": {"family": "inet", "table": TABLE, "chain": "prerouting",
                                                      "handle": 9, "expr": [{"accept": None}]}}), "3 rule(s)"),
        ]
        for i, (fn, fragment) in enumerate(cases):
            with self.subTest(i=i, expected=fragment):
                self.assertTableFails(mutate(fn), fragment)

    def test_not_json_and_unknown_shape_fail_loudly(self):
        self.assertTableFails("table inet rwsafe_pilot {", "not nft JSON")
        self.assertTableFails({"something": []}, "protocol drift")


# A stand-in kubectl for the orchestrator's part: two probe Jobs, the newer one Failed (no completionTime) and the older
# one Complete with a PASS report. Arguments decide the answer; nothing reaches a cluster.
FAKE_KUBECTL = r'''#!/usr/bin/env bash
a="$*"
case "${a}" in
  "get namespace rwsafe") exit 0 ;;
  *"component=icap --field-selector=status.phase=Running -o jsonpath"*) printf 'true\ntrue\n' ;;
  *"component=icap --field-selector=status.phase!=Succeeded -o name"*) printf 'pod/a\npod/b\n' ;;
  *"get jobs -l app.kubernetes.io/name=rwsafe-icap-probe"*)
    printf '2026-10-31T10:00:00Z rwsafe-icap-probe-old\n2026-10-31T10:15:00Z rwsafe-icap-probe-%s\n' "${NEWEST}" ;;
  *"get job rwsafe-icap-probe-old "*) printf 'Complete\n' ;;
  *"get job rwsafe-icap-probe-failed "*) printf 'Failed\n' ;;
  *"get job rwsafe-icap-probe-running "*) printf '' ;;
  *"job-name=rwsafe-icap-probe-old "*) printf 'probe result: PASS (7/7 as expected)\n' ;;
  *"job-name=rwsafe-icap-probe-failed "*)
    printf 'claude customer TCKN  expected redact got block icap 200 MISMATCH\nprobe result: FAIL (6/7 as expected)\n' ;;
  *"job-name="*) printf '' ;;
  *"get service"*) printf 'ClusterIP\nClusterIP\nClusterIP\n' ;;
  *"kube-system get pods"*) printf '' ;;
  *"get nodes"*) printf '192.0.2.5' ;;
  *) exit 1 ;;
esac
'''


class Latest(unittest.TestCase):
    """PR 40 review D-01: --latest judges the newest probe Job whatever its outcome."""

    def run_latest(self, newest: str) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as d:
            bin_dir = Path(d)
            for name, text in (("kubectl", FAKE_KUBECTL), ("ss", "#!/bin/sh\nexit 0\n"),
                               ("timeout", "#!/bin/sh\nexit 1\n")):   # connection refused
                (bin_dir / name).write_text(text)
                (bin_dir / name).chmod(0o755)
            out = subprocess.run(["bash", str(SCRIPT), "--latest"], capture_output=True, text=True, timeout=60, env={
                "PATH": f"{d}:/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin", "PRODUCT": "rwsafe",
                "KUBECTL": str(bin_dir / "kubectl"), "NEWEST": newest})
            return out.returncode, out.stdout + out.stderr

    def test_a_newer_failed_job_is_not_hidden_by_an_older_pass(self):
        rc, out = self.run_latest("failed")
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL newest probe Job (created 2026-10-31T10:15:00Z), Job Failed: probe result: FAIL", out)
        self.assertIn("MISMATCH", out)
        self.assertNotIn("192.0.2.5", out)

    def test_a_newer_unfinished_job_is_not_a_pass(self):
        rc, out = self.run_latest("running")
        self.assertEqual(rc, 1, out)
        self.assertIn("Job running: no probe report", out)

    def test_the_newest_complete_pass_passes(self):
        rc, out = self.run_latest("old")
        self.assertEqual(rc, 0, out)
        self.assertIn("ok   newest probe Job (created 2026-10-31T10:15:00Z), Job Complete: PASS (7/7 as expected)", out)
        self.assertIn("result: PASS", out)


def po_block(doc: Path) -> str:
    """The PO's firewall block of step 11: the fenced bash block that starts a `set -euo pipefail` subshell."""
    blocks = re.findall(r"```bash\n(\(\nset -euo pipefail\n.*?\n\))\n```", doc.read_text(encoding="utf-8"), re.S)
    if len(blocks) != 1:
        raise AssertionError(f"{doc.name}: expected one firewall block, found {len(blocks)}")
    return blocks[0]


class FirewallBlock(unittest.TestCase):
    """PR 40 review D-04: the block derives the product name itself, refuses without ~/rwsafe or a valid name, and
    stops at the first error; sudo is a stand-in that records what it would run."""

    def run_block(self, doc: Path, product_line: str | None, sudo_rc: int = 0) -> tuple[int, str, str]:
        with tempfile.TemporaryDirectory() as d:
            home, bin_dir = Path(d) / "home", Path(d) / "bin"
            bin_dir.mkdir()
            home.mkdir()
            if product_line is not None:
                (home / "rwsafe/deploy/rwsafe").mkdir(parents=True)
                (home / "rwsafe/deploy/rwsafe/product.env").write_text(f"# synthetic\n{product_line}\n")
            log = Path(d) / "sudo.log"
            (bin_dir / "sudo").write_text(f'#!/bin/sh\necho "$*" >> "{log}"\ncat >> "{log}"\nexit {sudo_rc}\n')
            (bin_dir / "sudo").chmod(0o755)
            block = po_block(doc).replace("<proxysg-address-1>", "192.0.2.11").replace(
                "<vekil-adresi-1>", "192.0.2.11")
            out = subprocess.run(["bash", "-c", block], capture_output=True, text=True, timeout=30,
                                 env={"HOME": str(home), "PATH": f"{bin_dir}:/usr/bin:/bin"})
            return out.returncode, out.stdout + out.stderr, log.read_text() if log.exists() else ""

    def test_both_runbooks(self):
        for doc in (REPO / "docs/operations/PILOT_RUNBOOK.md", REPO / "docs/operations/PILOT_ADIMLAR.md"):
            with self.subTest(doc.name):
                rc, out, sudo = self.run_block(doc, "PRODUCT=rwsafe")
                self.assertEqual(rc, 0, out)
                self.assertIn("table rwsafe_pilot written", out)
                self.assertTrue(sudo.startswith("nft -f -\n"), sudo)
                self.assertIn("table inet rwsafe_pilot {", sudo)
                for product_line in (None, "PRODUCT=", "# no product line", "PRODUCT=bad name"):
                    rc, out, sudo = self.run_block(doc, product_line)
                    self.assertNotEqual(rc, 0, (product_line, out))
                    self.assertEqual(sudo, "", (product_line, "sudo ran"))
                    self.assertNotIn("_pilot written", out)
                rc, out, _ = self.run_block(doc, "PRODUCT=rwsafe", sudo_rc=1)   # nft refused: stops there
                self.assertNotEqual(rc, 0, out)
                self.assertNotIn("written", out)


if __name__ == "__main__":
    unittest.main(verbosity=1)
