#!/usr/bin/env python3
"""Self-test of the scanner baseline gate: blocking and unknown severities fail, exact unexpired acceptances suppress,
incomplete, unbounded or expired acceptances fail, and a missing, malformed or empty report is an error (fail closed).
The CI job also runs the real scanners on planted canaries. Standard library only.

Usage: python3 -B tools/security/test_baseline_gate.py
"""
from __future__ import annotations

import contextlib
import datetime as dt
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import baseline_gate as gate  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
TODAY = dt.date.today()


def _trivy(*vulns: tuple[str, str], misconfig: str | None = None) -> dict:
    results = [{"Target": "java/dataplane/gradle.lockfile", "Class": "lang-pkgs", "Type": "gradle",
                "Packages": [{"Name": "org.example:lib", "Version": "1.0"}],
                "Vulnerabilities": [{"VulnerabilityID": cve, "PkgName": "org.example:lib", "InstalledVersion": "1.0",
                                     "Severity": sev} for cve, sev in vulns]}]
    if misconfig:
        results.append({"Target": "deploy/rwsafe/overlays/k3s/x.yaml", "Class": "config", "Type": "kubernetes",
                        "Misconfigurations": [{"ID": "KSV001", "AVDID": "AVD-KSV-0001", "Severity": misconfig,
                                               "Status": "FAIL", "CauseMetadata": {"Resource": "Deployment/a",
                                                                                   "StartLine": 3}},
                                              {"ID": "KSV001", "AVDID": "AVD-KSV-0001", "Severity": misconfig,
                                               "Status": "FAIL", "CauseMetadata": {"Resource": "Deployment/b",
                                                                                   "StartLine": 30}},
                                              {"ID": "KSV002", "AVDID": "AVD-KSV-0002", "Severity": "CRITICAL",
                                               "Status": "PASS"}]})
    return {"SchemaVersion": 2, "Results": results}


def _semgrep(*severities: str, errors: list | None = None, scanned: list | None = None) -> dict:
    return {"results": [{"check_id": f"java.rule.{i}", "path": "java/x/A.java", "start": {"line": i + 1},
                         "extra": {"severity": sev}} for i, sev in enumerate(severities)],
            "errors": errors or [], "paths": {"scanned": ["java/x/A.java"] if scanned is None else scanned}}


def _accept(tool: str, rule: str, location: str, days: int = 30, **override: str) -> dict:
    entry = {"tool": tool, "rule": rule, "location": location, "reason": "self-test", "owner": "self-test",
             "review_date": (TODAY + dt.timedelta(days=days)).isoformat()}
    entry.update(override)
    return entry


POLICY = {"blocks_rollout": ["HIGH", "CRITICAL"], "semgrep_blocks": ["ERROR", "WARNING", "CRITICAL", "HIGH", "MEDIUM"],
          "max_acceptance_days_no_fix_available": 90}
LOCKFILE_LIB = "java/dataplane/gradle.lockfile:org.example:lib@1.0"


class BaselineGateSelfTest(unittest.TestCase):

    def run_gate(self, accepted: list[dict], trivy: dict | None = None, semgrep: dict | None = None) -> tuple[bool, str]:
        findings = (gate.trivy_findings(trivy) if trivy else []) + (gate.semgrep_findings(semgrep) if semgrep else [])
        lines, failed = gate.evaluate(POLICY, accepted, findings, TODAY)
        return failed, "\n".join(lines)

    def test_blocking_severities_fail_and_lower_ones_are_reported(self) -> None:
        self.assertTrue(self.run_gate([], trivy=_trivy(("CVE-1", "HIGH")))[0])
        self.assertTrue(self.run_gate([], trivy=_trivy(("CVE-1", "CRITICAL")))[0])
        self.assertTrue(self.run_gate([], trivy=_trivy(misconfig="HIGH"))[0])
        self.assertTrue(self.run_gate([], semgrep=_semgrep("ERROR"))[0])
        self.assertTrue(self.run_gate([], semgrep=_semgrep("WARNING"))[0])
        failed, out = self.run_gate([], trivy=_trivy(("CVE-1", "MEDIUM"), ("CVE-2", "LOW")), semgrep=_semgrep("INFO"))
        self.assertFalse(failed)
        self.assertEqual(3, out.count("REPORTED"))

    def test_unknown_and_unrated_severities_fail_closed(self) -> None:
        """PR 7 review D-01: a severity the gate does not name as non-blocking blocks."""
        self.assertTrue(self.run_gate([], trivy=_trivy(("CVE-1", "UNKNOWN")))[0])
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "UNKNOWN", "NEWSCALE"):
            with self.subTest(severity=severity):
                self.assertTrue(self.run_gate([], semgrep=_semgrep(severity))[0])

    def test_policy_floor_is_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for policy in ({**POLICY, "blocks_rollout": []}, {**POLICY, "semgrep_blocks": ["ERROR"]},
                           {k: v for k, v in POLICY.items() if k != "semgrep_blocks"}):
                with self.subTest(policy=policy), self.assertRaises(gate.ReportError):
                    path = Path(tmp, "baseline.yaml")
                    path.write_text(json.dumps({"policy": policy, "accepted": []}))
                    gate.load_baseline(path)

    def test_misconfiguration_acceptance_covers_one_resource_only(self) -> None:
        """PR 7 review D-03 (1): accepting a check for one resource leaves the same check on another resource blocking."""
        entry = _accept("trivy", "AVD-KSV-0001", "deploy/rwsafe/overlays/k3s/x.yaml:Deployment/a:3")
        failed, out = self.run_gate([entry], trivy=_trivy(misconfig="HIGH"))
        self.assertTrue(failed)
        self.assertIn("ACCEPTED", out)
        self.assertIn("BLOCKING  trivy    HIGH      AVD-KSV-0001 deploy/rwsafe/overlays/k3s/x.yaml:Deployment/b:30", out)

    def test_passing_misconfiguration_checks_are_not_findings(self) -> None:
        self.assertNotIn("AVD-KSV-0002", self.run_gate([], trivy=_trivy(misconfig="LOW"))[1])

    def test_exact_unexpired_acceptance_suppresses(self) -> None:
        failed, out = self.run_gate([_accept("trivy", "CVE-1", LOCKFILE_LIB)], trivy=_trivy(("CVE-1", "CRITICAL")))
        self.assertFalse(failed)
        self.assertIn("ACCEPTED", out)

    def test_acceptance_never_matches_fuzzily(self) -> None:
        for entry in (_accept("trivy", "CVE-2", LOCKFILE_LIB), _accept("trivy", "CVE-1", LOCKFILE_LIB + "1"),
                      _accept("semgrep", "CVE-1", LOCKFILE_LIB)):
            with self.subTest(entry=entry):
                self.assertTrue(self.run_gate([entry], trivy=_trivy(("CVE-1", "HIGH")))[0])

    def test_expired_acceptance_stops_suppressing_and_fails(self) -> None:
        failed, out = self.run_gate([_accept("trivy", "CVE-1", LOCKFILE_LIB, days=-1)], trivy=_trivy(("CVE-1", "LOW")))
        self.assertTrue(failed)
        self.assertIn("BASELINE_ENTRY_EXPIRED", out)

    def test_acceptance_beyond_the_maximum_fails(self) -> None:
        failed, out = self.run_gate([_accept("trivy", "CVE-1", LOCKFILE_LIB, days=91)], trivy=_trivy(("CVE-1", "HIGH")))
        self.assertTrue(failed)
        self.assertIn("BASELINE_ENTRY_BEYOND_MAX_DAYS", out)
        self.assertFalse(self.run_gate([_accept("trivy", "CVE-1", LOCKFILE_LIB, days=90)],
                                       trivy=_trivy(("CVE-1", "HIGH")))[0])

    def test_incomplete_acceptance_fails(self) -> None:
        for override in ({"owner": ""}, {"reason": "  "}, {"review_date": "soon"}, {"tool": "zap"},
                         {"rule": " CVE-1"}, {"location": LOCKFILE_LIB + " "}):
            with self.subTest(override=override):
                failed, out = self.run_gate([{**_accept("trivy", "CVE-1", LOCKFILE_LIB), **override}])
                self.assertTrue(failed)
                self.assertIn("BASELINE_ENTRY_INCOMPLETE", out)

    def test_stale_acceptance_is_reported(self) -> None:
        failed, out = self.run_gate([_accept("trivy", "CVE-9", LOCKFILE_LIB)], trivy=_trivy())
        self.assertFalse(failed)
        self.assertIn("BASELINE_ENTRY_STALE", out)

    def test_malformed_reports_and_scan_errors_fail_closed(self) -> None:
        empty_lockfile = _trivy()
        empty_lockfile["Results"][0]["Packages"] = []
        for bad in ({}, {"Results": []}, {"SchemaVersion": 2}, empty_lockfile, []):
            with self.subTest(report=bad), self.assertRaises(gate.ReportError):
                gate.trivy_findings(bad)
        for bad in ({}, {"results": None}, _semgrep(scanned=[]), _semgrep(scanned=["tools/a.py"]),
                    _semgrep(errors=[{"level": "error", "type": "Rule parse error"}]),
                    _semgrep(errors=[{"level": "warn", "type": "PartialParsing"}])):
            with self.subTest(report=bad), self.assertRaises(gate.ReportError):
                gate.semgrep_findings(bad)

    def test_cli_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            baseline = Path(tmp, "baseline.yaml")
            baseline.write_text(json.dumps({"policy": POLICY, "accepted": []}))
            clean, dirty = Path(tmp, "clean.json"), Path(tmp, "dirty.json")
            clean.write_text(json.dumps(_trivy()))
            dirty.write_text(json.dumps(_semgrep("ERROR")))
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(0, gate.main(["g", "--baseline", str(baseline), "--trivy", str(clean)]))
                self.assertEqual(1, gate.main(["g", "--baseline", str(baseline), "--semgrep", str(dirty)]))
                self.assertEqual(2, gate.main(["g", "--baseline", str(baseline), "--trivy", str(Path(tmp, "none"))]))
                self.assertEqual(2, gate.main(["g", "--baseline", str(baseline)]))
                self.assertEqual(2, gate.main(["g", "--baseline", str(Path(tmp, "none")), "--trivy", str(clean)]))

    def test_committed_baseline_is_valid_and_complete(self) -> None:
        policy, accepted = gate.load_baseline(REPO_ROOT / "security" / "baseline.yaml")
        self.assertFalse(gate.evaluate(policy, accepted, [], TODAY)[1])


if __name__ == "__main__":
    unittest.main(verbosity=2)
