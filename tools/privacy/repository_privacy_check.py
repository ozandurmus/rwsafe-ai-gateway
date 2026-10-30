#!/usr/bin/env python3
"""Local, offline repository privacy gate for rwsafe-ai-gateway (AGENTS.md 4.15; kickoff brief 4A product rule 7).

Reports only rule and file location; a matched value is never printed. Scans the repository candidate, never runtime
data, with no network access. Modelled on neXus tools/privacy/repository_privacy.py; the rwsafe additions are Turkish
identifiers (TCKN with checksum, TR IBAN, TR phone numbers), AI-platform credential shapes, prompt-body fixtures, and the
allowlist contract (owner + review date on every entry, expired entries fail) for this gate's own allowlist and for every
allowlist in `.gitleaks.toml`.

Test fixtures get no exemption: they use the RFC 5737 documentation ranges, the masker's 240.0.0.0/4 space and masked
`5xx` phone shapes like every other file (PR 4 review D-01). Every file is scanned: known text suffixes must decode as
UTF-8; any other file, extensionless ones included, is scanned unless it is binary (a NUL byte in its first 8 KiB). The
gate scans its own source too. `test_repository_privacy_check.py` plants synthetic findings and proves each rule fires.

Usage: python3 tools/privacy/repository_privacy_check.py [repo-root]    exit 0 PASS, 1 FAIL, 2 scanner error
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

ALLOWLIST_FILE = "tools/privacy/privacy_allowlist.json"
GITLEAKS_CONFIG = ".gitleaks.toml"
# A gitleaks allowlist names its owner and review date in its description, e.g. "owner: architect; review: 2027-01-31; ...".
_GITLEAKS_OWNER_RE = re.compile(r"\bowner:\s*([^;]+?)\s*(?:;|$)")
_GITLEAKS_REVIEW_RE = re.compile(r"\breview:\s*(\d{4}-\d{2}-\d{2})\b")
BINARY_SNIFF_BYTES = 8192
FORBIDDEN_ROOT_DIRS = {"data", "output", "logs", "runtime", "state", "cas", "captures", "support_bundles", "vault"}
FORBIDDEN_DIRS_ANYWHERE = {"__pycache__", ".pytest_cache", ".gradle", "node_modules", ".venv", "venv", "build", ".idea", ".cache"}
FORBIDDEN_SUFFIXES = {
    ".zip": "ARCHIVE_OR_PACKAGE", ".7z": "ARCHIVE_OR_PACKAGE", ".rar": "ARCHIVE_OR_PACKAGE",
    ".sqlite": "DATABASE_ARTIFACT", ".sqlite3": "DATABASE_ARTIFACT", ".db": "DATABASE_ARTIFACT",
    ".pcap": "PACKET_CAPTURE", ".pcapng": "PACKET_CAPTURE", ".har": "TRAFFIC_CAPTURE",
    ".pem": "PRIVATE_OR_TRUST_MATERIAL", ".p12": "PRIVATE_OR_TRUST_MATERIAL", ".pfx": "PRIVATE_OR_TRUST_MATERIAL",
    ".jks": "PRIVATE_OR_TRUST_MATERIAL", ".key": "PRIVATE_OR_TRUST_MATERIAL", ".enc": "PRIVATE_OR_TRUST_MATERIAL",
    ".bak": "BACKUP_OR_TEMPORARY", ".tmp": "BACKUP_OR_TEMPORARY", ".hprof": "HEAP_DUMP",
}
FORBIDDEN_NAMES = {".env": "LOCAL_CONFIGURATION", "known_hosts": "LOCAL_TRUST_MATERIAL", ".ds_store": "GENERATED_OR_OS_ARTIFACT",
                   "thumbs.db": "GENERATED_OR_OS_ARTIFACT"}
TEXT_SUFFIXES = {".py", ".sh", ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".html", ".css",
                 ".js", ".ts", ".tsx", ".mjs", ".java", ".kt", ".kts", ".sql", ".xml", ".csv", ".properties", ".gitignore", ".nft",
                 ".gitattributes", ".bat", ".lockfile"}

_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")
_EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_HIGH_RISK_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|api[_-]?key|access[_-]?token|secret|community|psk|bearer)\b\s*[:=]\s*[\"']([^\"']+)[\"']")
_SAFE_LITERAL_VALUES = {"", "none", "null", "redacted", "[redacted]", "synthetic-secret", "synthetic-password", "example",
                        "test", "changeme", "synthetic-value"}
_ANTHROPIC_KEY_RE = re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")
_OPENAI_KEY_RE = re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}")
_GOOGLE_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")
_GITHUB_TOKEN_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b")
_TR_IBAN_RE = re.compile(r"\bTR\d{2}(?:\s?\d{4}){5}\s?\d{2}\b")
_TR_PHONE_RE = re.compile(r"(?<!\d)(?:\+90|0090|0)?\s?5\d{2}[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}(?!\d)")
_TCKN_RE = re.compile(r"(?<!\d)[1-9]\d{10}(?!\d)")
# Cluster-internal DNS (svc.cluster.local) and the documented placeholder zone nexus.local are repository-safe shapes.
_INTERNAL_HOST_RE = re.compile(r"(?i)\b[a-z0-9][a-z0-9-]{1,62}\.(?:corp|lan|intra|internal)\b|\b[a-z0-9][a-z0-9.-]{1,62}\.local\b")
_SAFE_HOST_SUFFIXES = (".svc.cluster.local", ".cluster.local", ".nexus.local", "example.invalid", ".localhost", ".test")
_PROMPT_FIXTURE_HINT_RE = re.compile(r"(?i)\"(?:messages|prompt|contents|input)\"\s*:\s*\[")
_SYNTHETIC_MARKERS = ("synthetic", "example.invalid", "RFC 5737", "rfc5737", "192.0.2.", "198.51.100.", "203.0.113.")


def tckn_valid(digits: str) -> bool:
    """Turkish national identity number checksum (11 digits, first non-zero)."""
    if len(digits) != 11 or not digits.isdigit() or digits[0] == "0":
        return False
    d = [int(c) for c in digits]
    odd = d[0] + d[2] + d[4] + d[6] + d[8]
    even = d[1] + d[3] + d[5] + d[7]
    if (odd * 7 - even) % 10 != d[9]:
        return False
    return sum(d[:10]) % 10 == d[10]


def iban_valid(iban: str) -> bool:
    s = re.sub(r"\s", "", iban).upper()
    if len(s) != 26 or not s.startswith("TR"):
        return False
    rearranged = s[4:] + s[:4]
    numeric = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(numeric) % 97 == 1


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str


def _is_repository_safe_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return True
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
        return True
    docs = (ipaddress.ip_network("192.0.2.0/24"), ipaddress.ip_network("198.51.100.0/24"), ipaddress.ip_network("203.0.113.0/24"))
    if any(ip in n for n in docs):
        return True
    if ip in ipaddress.ip_network("240.0.0.0/4"):   # the subnet-preserving masker's synthetic space
        return True
    return not (ip.is_private or ip.is_link_local or ip.is_global)


def _load_allowlist(root: Path) -> tuple[dict[str, set[str]], list[Finding]]:
    """{rule: {path-or-value-regex}} plus findings for malformed or expired entries, here and in .gitleaks.toml."""
    findings: list[Finding] = _check_gitleaks_allowlists(root)
    allow: dict[str, set[str]] = {}
    p = root / ALLOWLIST_FILE
    if not p.exists():
        return allow, findings
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return allow, [Finding(ALLOWLIST_FILE, 0, "ALLOWLIST_MALFORMED")]
    today = dt.date.today()
    for i, e in enumerate(data.get("entries", []), 1):
        try:
            review = dt.date.fromisoformat(e["review_date"])
            if not e["owner"] or not e["reason"] or not e["rule"] or not e["path"]:
                raise KeyError("field")
        except (KeyError, ValueError, TypeError):
            findings.append(Finding(ALLOWLIST_FILE, i, "ALLOWLIST_ENTRY_INCOMPLETE"))
            continue
        if review < today:
            findings.append(Finding(ALLOWLIST_FILE, i, "ALLOWLIST_ENTRY_EXPIRED"))
            continue
        allow.setdefault(e["rule"], set()).add(e["path"])
    return allow, findings


def _check_gitleaks_allowlists(root: Path) -> list[Finding]:
    """Every gitleaks allowlist (global or per rule, old or new syntax) names an owner and an unexpired review date."""
    p = root / GITLEAKS_CONFIG
    if not p.exists():
        return []
    try:
        config = tomllib.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return [Finding(GITLEAKS_CONFIG, 0, "GITLEAKS_CONFIG_MALFORMED")]
    blocks: list[object] = []
    for holder in [config, *config.get("rules", [])]:
        if not isinstance(holder, dict):
            continue
        single = holder.get("allowlist")
        blocks.extend([single] if single is not None else [])
        blocks.extend(holder.get("allowlists", []))
    findings: list[Finding] = []
    today = dt.date.today()
    for i, block in enumerate(blocks, 1):
        description = block.get("description", "") if isinstance(block, dict) else ""
        owner = _GITLEAKS_OWNER_RE.search(description) if isinstance(description, str) else None
        review = _GITLEAKS_REVIEW_RE.search(description) if isinstance(description, str) else None
        try:
            review_date = dt.date.fromisoformat(review.group(1)) if review else None
        except ValueError:
            review_date = None
        if owner is None or review_date is None:
            findings.append(Finding(GITLEAKS_CONFIG, i, "GITLEAKS_ALLOWLIST_INCOMPLETE"))
        elif review_date < today:
            findings.append(Finding(GITLEAKS_CONFIG, i, "GITLEAKS_ALLOWLIST_EXPIRED"))
    return findings


def _read_candidate(path: Path) -> tuple[str | None, bool]:
    """(text, unreadable): text for a file to scan, None for a binary file; unreadable for text that does not decode."""
    try:
        data = path.read_bytes()
    except OSError:
        return None, True
    known_text = path.suffix.lower() in TEXT_SUFFIXES or path.name.lower() in TEXT_SUFFIXES
    if not known_text and b"\x00" in data[:BINARY_SNIFF_BYTES]:
        return None, False
    try:
        return data.decode("utf-8"), False
    except UnicodeDecodeError:
        return None, True


def scan(root: Path) -> tuple[int, list[Finding]]:
    allow, findings = _load_allowlist(root)
    scanned = 0
    for child in root.iterdir():
        if child.is_dir() and child.name.lower() in FORBIDDEN_ROOT_DIRS:
            findings.append(Finding(child.name, 0, "RUNTIME_DIRECTORY_PRESENT"))
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        parts = [p.lower() for p in rel.parts]
        if ".git" in parts or any(p in FORBIDDEN_DIRS_ANYWHERE for p in parts) or path.is_dir():
            continue
        if ".claude" in parts and "worktrees" in parts:  # agent worktrees nested by the desktop app; never repository content
            continue
        relp = rel.as_posix()
        low = path.name.lower()
        if low.startswith(".env") and low != ".env.example":
            findings.append(Finding(relp, 0, "LOCAL_CONFIGURATION"))
        elif low.startswith("known_hosts") and low != "known_hosts.example":
            findings.append(Finding(relp, 0, "LOCAL_TRUST_MATERIAL"))
        elif low in FORBIDDEN_NAMES:
            findings.append(Finding(relp, 0, FORBIDDEN_NAMES[low]))
        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            findings.append(Finding(relp, 0, FORBIDDEN_SUFFIXES[path.suffix.lower()]))
            continue
        text, unreadable = _read_candidate(path)
        if unreadable:
            findings.append(Finding(relp, 0, "UNREADABLE_TEXT_CANDIDATE"))
        if text is None:
            continue
        scanned += 1
        test_fixture = "/test/" in "/" + relp or relp.startswith("tests/") or "/tests/" in "/" + relp or "/fixtures/" in "/" + relp
        synthetic_file = any(m in text for m in _SYNTHETIC_MARKERS)

        def hit(rule: str, line_no: int) -> None:
            if relp in allow.get(rule, set()):
                return
            findings.append(Finding(relp, line_no, rule))

        if _PROMPT_FIXTURE_HINT_RE.search(text) and test_fixture and not synthetic_file:
            hit("PROMPT_FIXTURE_NOT_MARKED_SYNTHETIC", 0)
        for n, line in enumerate(text.splitlines(), 1):
            if _PRIVATE_KEY_RE.search(line):
                hit("PRIVATE_KEY_MATERIAL", n)
            if _EMAIL_RE.search(line) and "example.invalid" not in line and "noreply@anthropic.com" not in line:
                hit("EMAIL_ADDRESS", n)
            for m in _IPV4_RE.finditer(line):
                if not _is_repository_safe_ip(m.group(0)):
                    hit("NON_DOCUMENTATION_IPV4", n)
                    break
            for m in _INTERNAL_HOST_RE.finditer(line):
                # The leading dot makes a bare safe zone ("nexus.local") as safe as its subdomains.
                if not ("." + m.group(0).lower()).endswith(_SAFE_HOST_SUFFIXES) and "<" not in m.group(0):
                    hit("INTERNAL_HOST_NAME", n)
                    break
            for rx, rule in ((_ANTHROPIC_KEY_RE, "ANTHROPIC_KEY_SHAPE"), (_OPENAI_KEY_RE, "OPENAI_KEY_SHAPE"),
                             (_GOOGLE_KEY_RE, "GOOGLE_KEY_SHAPE"), (_GITHUB_TOKEN_RE, "GITHUB_TOKEN_SHAPE")):
                if rx.search(line) and "synthetic" not in line.lower():
                    hit(rule, n)
            m = _HIGH_RISK_ASSIGNMENT_RE.search(line)
            if m and m.group(2).strip().lower() not in _SAFE_LITERAL_VALUES and len(m.group(2).split()) < 4 \
                    and not m.group(2).startswith("[") and "synthetic" not in m.group(2).lower():
                hit("CREDENTIAL_LITERAL", n)
            for m in _TR_IBAN_RE.finditer(line):
                if iban_valid(m.group(0)):
                    hit("TR_IBAN", n)
            for m in _TCKN_RE.finditer(line):
                if tckn_valid(m.group(0)):
                    hit("TCKN_WITH_VALID_CHECKSUM", n)
            if _TR_PHONE_RE.search(line) and "5xx" not in line:
                hit("TR_MOBILE_NUMBER", n)
    return scanned, findings


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path.cwd()
    if not root.is_dir():
        print("scanner error: not a directory", file=sys.stderr)
        return 2
    scanned, findings = scan(root)
    for f in sorted(findings, key=lambda f: (f.path, f.line)):
        print(f"{f.rule:36} {f.path}:{f.line}")
    print(f"Files scanned:        {scanned}")
    print(f"Findings:             {len(findings)}")
    print(f"Gate:                 {'PASS' if not findings else 'FAIL'}")
    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
