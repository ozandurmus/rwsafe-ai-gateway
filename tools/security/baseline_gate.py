#!/usr/bin/env python3
"""Scanner findings above the accepted baseline fail CI (AGENTS.md section 10; SSDF PW.4, PW.7; SR-SC-2).

Reads Trivy and Semgrep JSON reports, normalises every finding to (tool, rule, location, severity), removes the ones an
unexpired acceptance in security/baseline.yaml names exactly (tool, rule and location; never a fuzzy match), and fails
when a blocking finding remains: Trivy at the baseline policy's `blocks_rollout` severities, Semgrep at its
`semgrep_blocks` severities. Prints tool, severity, rule and location only (a file path, a package and version, or a
rule id), never a matched value. An incomplete acceptance fails; an expired one stops suppressing; a stale one (its
finding is gone) is reported so it can be removed. A missing or malformed report is a scanner error (fail closed).

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
    findings: list[Finding] = []
    for result in report.get("Results") or []:
        target = result.get("Target", "")
        for v in result.get("Vulnerabilities") or []:
            findings.append(Finding("trivy", v["VulnerabilityID"], f"{target}:{v['PkgName']}@{v['InstalledVersion']}",
                                    v.get("Severity", "UNKNOWN")))
        for m in result.get("Misconfigurations") or []:
            if m.get("Status", "FAIL") == "FAIL":
                findings.append(Finding("trivy", m.get("AVDID") or m["ID"], target, m.get("Severity", "UNKNOWN")))
        for s in result.get("Secrets") or []:
            findings.append(Finding("trivy", s["RuleID"], f"{target}:{s.get('StartLine', 0)}", s.get("Severity", "UNKNOWN")))
    return findings


def semgrep_findings(report: dict) -> list[Finding]:
    if not isinstance(report, dict) or not isinstance(report.get("results"), list):
        raise ReportError("not a Semgrep JSON report")
    if any(e.get("level") == "error" for e in report.get("errors") or []):
        raise ReportError("Semgrep reported an error: the scan is incomplete")
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
    return policy, accepted


def evaluate(policy: dict, accepted: list[dict], findings: list[Finding], today: dt.date) -> tuple[list[str], bool]:
    """Report lines and whether the gate fails."""
    lines: list[str] = []
    failed = False
    suppress: set[tuple[str, str, str]] = set()
    for i, entry in enumerate(accepted, 1):
        try:
            if not all(isinstance(entry[k], str) and entry[k].strip() for k in REQUIRED_FIELDS):
                raise ValueError
            review = dt.date.fromisoformat(entry["review_date"])
        except (KeyError, ValueError, TypeError):
            lines.append(f"BASELINE_ENTRY_INCOMPLETE         accepted[{i}]")
            failed = True
            continue
        key = (entry["tool"], entry["rule"], entry["location"])
        if review < today:
            lines.append(f"BASELINE_ENTRY_EXPIRED            accepted[{i}] {key[0]} {key[1]} {key[2]}")
            continue
        suppress.add(key)
    blocking = {"trivy": set(policy.get("blocks_rollout", ["HIGH", "CRITICAL"])),
                "semgrep": set(policy.get("semgrep_blocks", ["ERROR", "WARNING"]))}
    seen: set[tuple[str, str, str]] = set()
    for f in sorted(set(findings), key=lambda f: (f.tool, f.location, f.rule)):
        seen.add(f.key)
        if f.key in suppress:
            state = "ACCEPTED"
        elif f.severity in blocking.get(f.tool, set()):
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
