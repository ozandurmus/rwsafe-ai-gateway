#!/usr/bin/env python3
"""Scanner findings above the accepted baseline fail CI (AGENTS.md section 10; SSDF PW.4, PW.7; SR-SC-2).

Reads Trivy and Semgrep JSON reports, normalises every finding to (tool, rule, location, severity), removes the ones an
unexpired acceptance in security/baseline.yaml names exactly (tool, rule and location; never a fuzzy match), and fails
when a blocking finding remains. Blocking is fail-closed (AGENTS.md section 7): every severity blocks except the few named
in NON_BLOCKING, so UNKNOWN, an unrated CVE or a new Semgrep severity scale blocks; the policy lists must still contain
the floor severities. Prints tool, severity, rule and location only (a file path, a package and version, a resource, or
a rule id), never a matched value. An incomplete acceptance, an acceptance for an unknown tool, one dated beyond the
policy's maximum, and an expired one fail; a stale one (its finding is gone) is reported so it can be removed. A missing,
malformed or empty report (Trivy without a parsed Gradle lockfile, Semgrep without a scanned Java file or with any error)
is a scanner error (fail closed). PR 7 review D-01..D-03.

Usage: python3 tools/security/baseline_gate.py [--baseline security/baseline.yaml] [--trivy REPORT] [--semgrep REPORT]
       exit 0 PASS, 1 FAIL, 2 scanner or report error
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from dataclasses import dataclass
from pathlib import Path

DEFAULT_BASELINE = Path(__file__).resolve().parents[2] / "security" / "baseline.yaml"
REQUIRED_FIELDS = ("tool", "rule", "location", "reason", "owner", "review_date")
TOOLS = {"trivy", "semgrep"}
NON_BLOCKING = {"trivy": {"MEDIUM", "LOW"}, "semgrep": {"INFO", "LOW"}}
POLICY_FLOOR = {"blocks_rollout": {"HIGH", "CRITICAL"}, "semgrep_blocks": {"ERROR", "WARNING", "CRITICAL", "HIGH", "MEDIUM"}}
MAX_ACCEPTANCE_DAYS = 90


class ReportError(Exception):
    pass


@dataclass(frozen=True)
class Finding:
    tool: str
    rule: str
    location: str
    severity: str

    @property
    def key(self) -> tuple[str, str, str]:
        return self.tool, self.rule, self.location


def trivy_findings(report: dict) -> list[Finding]:
    if not isinstance(report, dict) or "SchemaVersion" not in report:
        raise ReportError("not a Trivy JSON report")
    results = report.get("Results") or []
    if not any(r.get("Type") == "gradle" and r.get("Packages") for r in results):
        raise ReportError("Trivy parsed no Gradle lockfile package (run with --list-all-pkgs): the scan is empty")
    findings: list[Finding] = []
    for result in results:
        target = result.get("Target", "")
        for v in result.get("Vulnerabilities") or []:
            findings.append(Finding("trivy", v["VulnerabilityID"], f"{target}:{v['PkgName']}@{v['InstalledVersion']}",
                                    v.get("Severity", "UNKNOWN")))
        for m in result.get("Misconfigurations") or []:
            if m.get("Status", "FAIL") == "FAIL":
                cause = m.get("CauseMetadata") or {}
                location = f"{target}:{cause.get('Resource') or ''}:{cause.get('StartLine', 0)}"
                findings.append(Finding("trivy", m.get("AVDID") or m["ID"], location, m.get("Severity", "UNKNOWN")))
        for s in result.get("Secrets") or []:
            findings.append(Finding("trivy", s["RuleID"], f"{target}:{s.get('StartLine', 0)}", s.get("Severity", "UNKNOWN")))
    return findings


def semgrep_findings(report: dict) -> list[Finding]:
    if not isinstance(report, dict) or not isinstance(report.get("results"), list):
        raise ReportError("not a Semgrep JSON report")
    if report.get("errors"):
        raise ReportError("Semgrep reported errors or skipped input: the scan is incomplete")
    scanned = (report.get("paths") or {}).get("scanned") or []
    if not any(str(path).endswith(".java") for path in scanned):
        raise ReportError("Semgrep scanned no Java file: the scan is empty")
    return [Finding("semgrep", r["check_id"], f"{r['path']}:{r['start']['line']}", r["extra"].get("severity", "UNKNOWN"))
            for r in report["results"]]


def load_baseline(path: Path) -> tuple[dict, list[dict]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        policy, accepted = data["policy"], data["accepted"]
        if not isinstance(policy, dict) or not isinstance(accepted, list):
            raise ValueError
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise ReportError(f"baseline unreadable: {type(e).__name__}") from e
    for key, floor in POLICY_FLOOR.items():
        if not isinstance(policy.get(key), list) or not floor <= set(policy[key]):
            raise ReportError(f"baseline policy {key} drops below its floor")
    return policy, accepted


def evaluate(policy: dict, accepted: list[dict], findings: list[Finding], today: dt.date) -> tuple[list[str], bool]:
    """Report lines and whether the gate fails."""
    lines: list[str] = []
    failed = False
    suppress: set[tuple[str, str, str]] = set()
    max_days = min(int(policy.get("max_acceptance_days_no_fix_available", MAX_ACCEPTANCE_DAYS)), MAX_ACCEPTANCE_DAYS)
    for i, entry in enumerate(accepted, 1):
        try:
            if not all(isinstance(entry[k], str) and entry[k].strip() and entry[k] == entry[k].strip()
                       for k in REQUIRED_FIELDS) or entry["tool"] not in TOOLS:
                raise ValueError
            review = dt.date.fromisoformat(entry["review_date"])
        except (KeyError, ValueError, TypeError):
            lines.append(f"BASELINE_ENTRY_INCOMPLETE         accepted[{i}]")
            failed = True
            continue
        key = (entry["tool"], entry["rule"], entry["location"])
        if review < today:
            lines.append(f"BASELINE_ENTRY_EXPIRED            accepted[{i}] {key[0]} {key[1]} {key[2]}")
            failed = True
            continue
        if review > today + dt.timedelta(days=max_days):
            lines.append(f"BASELINE_ENTRY_BEYOND_MAX_DAYS    accepted[{i}] {key[0]} {key[1]} {key[2]}")
            failed = True
            continue
        suppress.add(key)
    blocking = {"trivy": set(policy["blocks_rollout"]), "semgrep": set(policy["semgrep_blocks"])}
    seen: set[tuple[str, str, str]] = set()
    for f in sorted(set(findings), key=lambda f: (f.tool, f.location, f.rule)):
        seen.add(f.key)
        if f.key in suppress:
            state = "ACCEPTED"
        elif f.severity in blocking.get(f.tool, set()) or f.severity not in NON_BLOCKING.get(f.tool, set()):
            state = "BLOCKING"
            failed = True
        else:
            state = "REPORTED"
        lines.append(f"{state:9} {f.tool:8} {f.severity:9} {f.rule} {f.location}")
    for key in sorted(suppress - seen):
        lines.append(f"BASELINE_ENTRY_STALE              {key[0]} {key[1]} {key[2]} (finding gone; remove the entry)")
    return lines, failed


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--trivy", type=Path, action="append", default=[])
    parser.add_argument("--semgrep", type=Path, action="append", default=[])
    args = parser.parse_args(argv[1:])
    if not args.trivy and not args.semgrep:
        print("scanner error: no report given", file=sys.stderr)
        return 2
    try:
        policy, accepted = load_baseline(args.baseline)
        findings: list[Finding] = []
        for paths, parse in ((args.trivy, trivy_findings), (args.semgrep, semgrep_findings)):
            for path in paths:
                try:
                    report = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, ValueError) as e:
                    raise ReportError(f"report unreadable: {path.name}: {type(e).__name__}") from e
                findings.extend(parse(report))
    except (ReportError, KeyError, TypeError) as e:
        print(f"scanner error: {e}", file=sys.stderr)
        return 2
    lines, failed = evaluate(policy, accepted, findings, dt.date.today())
    for line in lines:
        print(line)
    print(f"Findings:             {len(set(findings))}")
    print(f"Gate:                 {'FAIL' if failed else 'PASS'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
