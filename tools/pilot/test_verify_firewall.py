#!/usr/bin/env python3
"""Self-test of tools/pilot/verify_firewall.sh: `bash -n`, and the `--table` part against synthetic `nft -j` output
(RFC 5737 addresses only). The nft JSON shapes are the documented libnftables ones; UNVERIFIED (2026-10-31) on HOST-A's
nft release, which the PO's first run of the one-line check proves (an unrecognised shape fails, it is never guessed).

Usage: python3 -B tools/pilot/test_verify_firewall.py
"""
from __future__ import annotations

import copy
import json
import subprocess
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "verify_firewall.sh"
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
            local,
            {"match": {"op": "==", "left": {"meta": {"key": "nfproto"}}, "right": "ipv6"}},
            dport, {"drop": None}]}},
    ]}


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
        self.assertIn("icap_clients: type ipv4_addr, 3 element(s)", out)
        self.assertIn("IPv4 outside @icap_clients 1, IPv6 1", out)
        for a in ADDRESSES:
            self.assertNotIn(a, out)
        self.assertNotIn("<ip>", out)

    def assertTableFails(self, doc, fragment: str):
        rc, out = run(doc if isinstance(doc, str) else json.dumps(doc), "--table")
        self.assertEqual(rc, 1, out)
        self.assertIn(fragment, out)
        self.assertIn("result: FAIL", out)
        for a in ADDRESSES:
            self.assertNotIn(a, out)

    def test_each_missing_part_fails(self):
        cases = []
        doc = table_json()
        doc["nftables"] = [i for i in doc["nftables"] if "table" not in i]
        cases.append((doc, "inet rwsafe_pilot missing"))
        doc = table_json()
        doc["nftables"][2]["set"]["elem"] = []
        cases.append((doc, "0 element(s)"))
        doc = table_json()
        doc["nftables"][3]["chain"]["prio"] = 0
        cases.append((doc, "priority 0"))
        doc = table_json()
        del doc["nftables"][5]
        cases.append((doc, "IPv6 0"))
        doc = table_json()
        doc["nftables"][4]["rule"]["expr"] = doc["nftables"][4]["rule"]["expr"][1:]   # without the fib match
        cases.append((doc, "IPv4 outside @icap_clients 0"))
        doc = table_json()
        doc["nftables"][4]["rule"]["expr"][-1] = {"accept": None}
        cases.append((doc, "IPv4 outside @icap_clients 0"))
        doc = table_json()
        doc["nftables"].append({"table": {"family": "inet", "name": "other_table", "handle": 9}})
        cases.append((doc, "1 other table(s)"))
        doc = table_json()
        doc["nftables"].append(copy.deepcopy(doc["nftables"][5]))
        cases.append((doc, "3 rule(s) in prerouting"))
        for doc, fragment in cases:
            with self.subTest(fragment):
                self.assertTableFails(doc, fragment)

    def test_not_json_and_unknown_shape_fail_loudly(self):
        self.assertTableFails("table inet rwsafe_pilot {", "not nft JSON")
        self.assertTableFails({"something": []}, "protocol drift")


if __name__ == "__main__":
    unittest.main(verbosity=1)
