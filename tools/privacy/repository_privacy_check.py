#!/usr/bin/env python3
"""Local, offline repository privacy gate for rwsafe-ai-gateway (AGENTS.md 4.15; kickoff brief 4A product rule 7).

Reports only rule and file location; a matched value is never printed. Scans the repository candidate, never runtime
data, with no network access. Modelled on neXus tools/privacy/repository_privacy.py; the rwsafe additions are Turkish
identifiers (TCKN with checksum, TR IBAN, TR phone numbers), AI-platform credential shapes, serial and account-name
literals, LDAP DNs and domain accounts, IPv6, prompt-body fixtures, and the allowlist contract (owner + review date on
every entry, expired entries fail) for this gate's own allowlist and for every allowlist in `.gitleaks.toml`.

Candidates: in a git checkout, the tracked and the untracked-but-not-ignored files (`git ls-files`); elsewhere (an
extracted commit), every file. A candidate inside a build or cache directory is a finding, never skipped. Known text
suffixes must decode as UTF-8; any other file, extensionless ones included, is scanned unless it is binary (a NUL byte in
its first 8 KiB). The gate scans its own source. Exemptions apply to the matched value, never to the whole line, and test
fixtures get none (PR 4 review D-01; PR 6 review D-01..D-04). `test_repository_privacy_check.py` proves every rule fires.

Usage: python3 tools/privacy/repository_privacy_check.py [--policy-root DIR] [repo-root]
       --policy-root: read the allowlist and .gitleaks.toml from DIR instead of repo-root (CI scans each commit of a pull
       request against the pull request's own policy, so an intermediate commit cannot allowlist itself).
       exit 0 PASS, 1 FAIL, 2 scanner error
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

ALLOWLIST_FILE = "tools/privacy/privacy_allowlist.json"
GITLEAKS_CONFIG = ".gitleaks.toml"
# A gitleaks allowlist names its owner and review date in its description, e.g. "owner: architect; review: 2027-01-31; ...".
_GITLEAKS_OWNER_RE = re.compile(r"\bowner:\s*([^;\s][^;]*?)\s*(?:;|$)")
_GITLEAKS_REVIEW_RE = re.compile(r"\breview:\s*(\d{4}-\d{2}-\d{2})\b")
_GITLEAKS_ALLOWLIST_KEYS = {"description", "regexes", "paths", "regexTarget", "targetRules", "condition"}
BINARY_SNIFF_BYTES = 8192

FORBIDDEN_ROOT_DIRS = {"data", "output", "logs", "runtime", "state", "cas", "captures", "support_bundles", "vault"}
FORBIDDEN_DIRS_ANYWHERE = {"__pycache__", ".pytest_cache", ".gradle", "node_modules", ".venv", "venv", "build", ".idea",
                           ".cache", "target", ".cifuzz-corpus"}
FORBIDDEN_SUFFIXES = {
    ".zip": "ARCHIVE_OR_PACKAGE", ".7z": "ARCHIVE_OR_PACKAGE", ".rar": "ARCHIVE_OR_PACKAGE",
    ".sqlite": "DATABASE_ARTIFACT", ".sqlite3": "DATABASE_ARTIFACT", ".db": "DATABASE_ARTIFACT",
    ".pcap": "PACKET_CAPTURE", ".pcapng": "PACKET_CAPTURE", ".har": "TRAFFIC_CAPTURE",
    ".pem": "PRIVATE_OR_TRUST_MATERIAL", ".p12": "PRIVATE_OR_TRUST_MATERIAL", ".pfx": "PRIVATE_OR_TRUST_MATERIAL",
    ".jks": "PRIVATE_OR_TRUST_MATERIAL", ".key": "PRIVATE_OR_TRUST_MATERIAL", ".enc": "PRIVATE_OR_TRUST_MATERIAL",
    ".bak": "BACKUP_OR_TEMPORARY", ".tmp": "BACKUP_OR_TEMPORARY", ".hprof": "HEAP_DUMP",
}
FORBIDDEN_NAMES = {".env": "LOCAL_CONFIGURATION", "known_hosts": "LOCAL_TRUST_MATERIAL", ".ds_store": "GENERATED_OR_OS_ARTIFACT",
                   "thumbs.db": "GENERATED_OR_OS_ARTIFACT", ".gitleaksignore": "GITLEAKS_BYPASS"}
TEXT_SUFFIXES = {".py", ".sh", ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".html", ".css",
                 ".js", ".ts", ".tsx", ".mjs", ".java", ".kt", ".kts", ".sql", ".xml", ".csv", ".properties", ".gitignore", ".nft",
                 ".gitattributes", ".bat", ".lockfile"}

_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")
_EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_SAFE_EMAILS = {"noreply@anthropic.com"}
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6_RE = re.compile(r"(?<![\w:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:])")
_SAFE_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",   # RFC 5737 documentation
    "240.0.0.0/4",                                         # the subnet-preserving masker's synthetic space
    "2001:db8::/32", "3fff::/20",                           # RFC 3849, RFC 9637 documentation
))
_KEY_WORD = r"(?<![A-Za-z0-9])({})(?![A-Za-z0-9])"
_HIGH_RISK_ASSIGNMENT_RE = re.compile(
    "(?i)" + _KEY_WORD.format(r"password|passwd|api[_-]?key|access[_-]?token|secret|community|psk|bearer")
    + r"[\"']?\s*[:=]\s*[\"']([^\"']+)[\"']")
_SAFE_LITERAL_VALUES = {"", "none", "null", "redacted", "[redacted]", "synthetic-secret", "synthetic-password", "example",
                        "test", "changeme", "synthetic-value"}
_IDENTITY_KEYS = (r"serial|serial[_-]?(?:number|no)|device[_-]?serial|samaccountname|userprincipalname|upn"
                  r"|account[_-]?name|user[_-]?name|login[_-]?name")
_IDENTITY_QUOTED_RE = re.compile("(?i)" + _KEY_WORD.format(_IDENTITY_KEYS) + r"[\"']?\s*[:=]\s*[\"']([^\"']+)[\"']")
_IDENTITY_UNQUOTED_RE = re.compile(r"(?i)^\s*-?\s*(" + _IDENTITY_KEYS + r")\s*[:=]\s*([^\s\"'#]+)\s*(?:#.*)?$")
_SAFE_IDENTITY_RE = re.compile(
    r"(?i)^(?:<[^>]*>|USR-[0-9a-f]+|FW-[A-Z]+-\d+|\$\{?[A-Za-z_][\w.]*\}?|-|\*+|\|"
    r"|.*(?:synthetic|example|masked|redacted|placeholder).*)$")
_LDAP_DN_RE = re.compile(r"(?i)(?<![A-Za-z0-9])(?:CN|OU|DC|UID)=[^,=\s]+\s*,\s*(?:CN|OU|DC|O)=[^,=\s]+")
# DOMAIN\user as the file spells it: one backslash in prose and configuration, an escaped one in source code (where a
# single backslash is an escape sequence such as a newline). Mermaid labels in Markdown use the newline escape too.
_DOMAIN_ACCOUNT_RE = re.compile(r"(?<![\w\\])([A-Z][A-Z0-9-]{1,14})\\([A-Za-z][A-Za-z0-9._-]{2,63})(?![\w\\])")
_DOMAIN_ACCOUNT_ESCAPED_RE = re.compile(r"(?<![\w\\])([A-Z][A-Z0-9-]{1,14})\\\\([A-Za-z][A-Za-z0-9._-]{2,63})(?![\w\\])")
CODE_SUFFIXES = {".java", ".kt", ".kts", ".py", ".js", ".ts", ".tsx", ".mjs", ".sh", ".json", ".toml"}
# A home directory names a local account: /Users/<name>, /home/<name>, C:\Users\<name> (PR 7: an external review's
# output carried the reviewer's absolute workspace path).
_HOME_PATH_RE = re.compile(r"(?i)(?:(?<![\w.])/(?:Users|home)/|\b[A-Z]:\\{1,2}Users\\{1,2})([A-Za-z0-9._-]+)")
_SAFE_HOME_NAMES = {"runner", "user", "username", "me", "shared", "example", "ubuntu", "root"}
_PLACEHOLDER_WORDS = ("synthetic", "example", "masked", "redacted", "placeholder", "domain", "<")
_ANTHROPIC_KEY_RE = re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")
_OPENAI_KEY_RE = re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}")
_GOOGLE_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")
_GITHUB_TOKEN_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b")
_GITLEAKS_INLINE_ALLOW_RE = re.compile("gitleaks" + r":allow")   # split so this line is not itself a bypass marker
_TR_IBAN_RE = re.compile(r"\bTR\d{2}(?:\s?\d{4}){5}\s?\d{2}\b")
_TR_PHONE_RE = re.compile(r"(?<!\d)(?:\+90|0090|0)?\s?\(?5\d{2}\)?[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}(?!\d)")
_TCKN_RE = re.compile(r"(?<!\d)[1-9]\d{10}(?!\d)")
# Cluster-internal DNS (svc.cluster.local) and the documented placeholder zone nexus.local are repository-safe shapes.
_INTERNAL_HOST_RE = re.compile(
    r"(?i)\b[a-z0-9][a-z0-9.-]{0,252}\.(?:corp|lan|intra|internal)\b|\b[a-z0-9][a-z0-9.-]{0,252}\.local\b")
_SAFE_HOST_SUFFIXES = (".svc.cluster.local", ".cluster.local", ".nexus.local", ".example.invalid", ".localhost", ".test")
_PROMPT_FIXTURE_HINT_RE = re.compile(r"(?i)\"(?:messages|prompt|contents|input)\"\s*:\s*[\[{\"]")


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
    """Only loopback, unspecified, multicast and the documentation and masker ranges are safe; everything else is not."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return True   # not an address (a version string with a leading zero, a time of day)
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
        return True
    return any(ip.version == n.version and ip in n for n in _SAFE_NETWORKS)


def _is_safe_email(address: str) -> bool:
    address = address.lower()
    domain = address.rsplit("@", 1)[1]
    return address in _SAFE_EMAILS or domain == "example.invalid" or domain.endswith(".example.invalid")


def _is_placeholder(value: str) -> bool:
    return any(word in value.lower() for word in _PLACEHOLDER_WORDS)


def _load_allowlist(policy_root: Path) -> tuple[dict[str, set[str]], list[Finding]]:
    """{rule: {path}} plus findings for malformed or expired entries, here and in .gitleaks.toml."""
    findings: list[Finding] = _check_gitleaks_config(policy_root)
    allow: dict[str, set[str]] = {}
    p = policy_root / ALLOWLIST_FILE
    if not p.exists():
        return allow, findings
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        entries = data["entries"] if isinstance(data, dict) else None
        if not isinstance(entries, list):
            raise ValueError("entries")
    except (OSError, ValueError, KeyError):
        return allow, findings + [Finding(ALLOWLIST_FILE, 0, "ALLOWLIST_MALFORMED")]
    today = dt.date.today()
    for i, e in enumerate(entries, 1):
        try:
            review = dt.date.fromisoformat(e["review_date"])
            if not all(isinstance(e[k], str) and e[k].strip() for k in ("owner", "reason", "rule", "path")):
                raise KeyError("field")
        except (KeyError, ValueError, TypeError):
            findings.append(Finding(ALLOWLIST_FILE, i, "ALLOWLIST_ENTRY_INCOMPLETE"))
            continue
        if review < today:
            findings.append(Finding(ALLOWLIST_FILE, i, "ALLOWLIST_ENTRY_EXPIRED"))
            continue
        allow.setdefault(e["rule"], set()).add(e["path"])
    return allow, findings


def _check_gitleaks_config(root: Path) -> list[Finding]:
    """No rule is disabled or replaced; every allowlist (global or per rule, old or new syntax) is exact, names an owner
    and an unexpired review date, and uses no commit or stopword exemption."""
    p = root / GITLEAKS_CONFIG
    if not p.exists():
        return []
    try:
        config = tomllib.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return [Finding(GITLEAKS_CONFIG, 0, "GITLEAKS_CONFIG_MALFORMED")]
    findings: list[Finding] = []
    extend = config.get("extend", {})
    if not isinstance(extend, dict) or set(extend) - {"useDefault"} or extend.get("useDefault") is not True:
        findings.append(Finding(GITLEAKS_CONFIG, 0, "GITLEAKS_DEFAULT_RULES_NOT_EXTENDED_EXACTLY"))
    blocks: list[object] = []
    for holder in [config, *config.get("rules", [])]:
        if not isinstance(holder, dict):
            continue
        single = holder.get("allowlist")
        blocks.extend([single] if single is not None else [])
        many = holder.get("allowlists", [])
        blocks.extend(many if isinstance(many, list) else [many])
    today = dt.date.today()
    for i, block in enumerate(blocks, 1):
        if not isinstance(block, dict):
            findings.append(Finding(GITLEAKS_CONFIG, i, "GITLEAKS_ALLOWLIST_INCOMPLETE"))
            continue
        description = block.get("description", "")
        description = description if isinstance(description, str) else ""
        owner = _GITLEAKS_OWNER_RE.search(description)
        review = _GITLEAKS_REVIEW_RE.search(description)
        try:
            review_date = dt.date.fromisoformat(review.group(1)) if review else None
        except ValueError:
            review_date = None
        if owner is None or review_date is None:
            findings.append(Finding(GITLEAKS_CONFIG, i, "GITLEAKS_ALLOWLIST_INCOMPLETE"))
        elif review_date < today:
            findings.append(Finding(GITLEAKS_CONFIG, i, "GITLEAKS_ALLOWLIST_EXPIRED"))
        patterns = [*block.get("regexes", []), *block.get("paths", [])]
        if set(block) - _GITLEAKS_ALLOWLIST_KEYS or not patterns or not all(
                isinstance(x, str) and x.startswith("^") and x.endswith("$") and ".*" not in x for x in patterns):
            findings.append(Finding(GITLEAKS_CONFIG, i, "GITLEAKS_ALLOWLIST_NOT_EXACT"))
    return findings


def _candidates(root: Path) -> list[Path]:
    """Tracked plus untracked-but-not-ignored files in a git checkout; every file elsewhere."""
    if (root / ".git").exists():
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                             capture_output=True, check=True).stdout
        return sorted({root / name for name in out.decode("utf-8").split("\0") if name})
    return sorted(p for p in root.rglob("*") if not p.is_dir())


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


def _scan_line(line: str, hit, *, code: bool = False, mermaid: bool = False) -> None:
    if _PRIVATE_KEY_RE.search(line):
        hit("PRIVATE_KEY_MATERIAL")
    if _GITLEAKS_INLINE_ALLOW_RE.search(line):
        hit("GITLEAKS_BYPASS")
    if any(not _is_safe_email(m.group(0)) for m in _EMAIL_RE.finditer(line)):
        hit("EMAIL_ADDRESS")
    if any(not _is_repository_safe_ip(m.group(0)) for m in _IPV4_RE.finditer(line)):
        hit("NON_DOCUMENTATION_IPV4")
    if any(_is_ipv6(m.group(0)) and not _is_repository_safe_ip(m.group(0)) for m in _IPV6_RE.finditer(line)):
        hit("NON_DOCUMENTATION_IPV6")
    if any(not ("." + m.group(0).lower()).endswith(_SAFE_HOST_SUFFIXES) for m in _INTERNAL_HOST_RE.finditer(line)):
        # The leading dot makes a bare safe zone ("nexus.local") as safe as its subdomains.
        hit("INTERNAL_HOST_NAME")
    for rx, rule in ((_ANTHROPIC_KEY_RE, "ANTHROPIC_KEY_SHAPE"), (_OPENAI_KEY_RE, "OPENAI_KEY_SHAPE"),
                     (_GOOGLE_KEY_RE, "GOOGLE_KEY_SHAPE"), (_GITHUB_TOKEN_RE, "GITHUB_TOKEN_SHAPE")):
        if any("synthetic" not in m.group(0).lower() for m in rx.finditer(line)):
            hit(rule)
    for m in _HIGH_RISK_ASSIGNMENT_RE.finditer(line):
        value = m.group(2).strip()
        if value.lower() not in _SAFE_LITERAL_VALUES and len(value.split()) < 4 and not value.startswith("[") \
                and "synthetic" not in value.lower():
            hit("CREDENTIAL_LITERAL")
            break
    identities = [m.group(2) for m in _IDENTITY_QUOTED_RE.finditer(line)]
    unquoted = _IDENTITY_UNQUOTED_RE.match(line)
    identities += [unquoted.group(2)] if unquoted else []
    if any(not _SAFE_IDENTITY_RE.match(v.strip()) for v in identities):
        hit("SERIAL_OR_ACCOUNT_LITERAL")
    if any(not _is_placeholder(m.group(0)) for m in _LDAP_DN_RE.finditer(line)):
        hit("LDAP_DISTINGUISHED_NAME")
    accounts = _DOMAIN_ACCOUNT_ESCAPED_RE if code else None if mermaid else _DOMAIN_ACCOUNT_RE
    if accounts is not None and any(not _is_placeholder(m.group(0)) for m in accounts.finditer(line)):
        hit("DOMAIN_ACCOUNT")
    if any(m.group(1).lower() not in _SAFE_HOME_NAMES and not _is_placeholder(m.group(1))
           for m in _HOME_PATH_RE.finditer(line)):
        hit("LOCAL_HOME_PATH")
    if any(iban_valid(m.group(0)) for m in _TR_IBAN_RE.finditer(line)):
        hit("TR_IBAN")
    if any(tckn_valid(m.group(0)) for m in _TCKN_RE.finditer(line)):
        hit("TCKN_WITH_VALID_CHECKSUM")
    if _TR_PHONE_RE.search(line):
        hit("TR_MOBILE_NUMBER")


def _is_ipv6(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).version == 6
    except ValueError:
        return False


def scan(root: Path, policy_root: Path | None = None) -> tuple[int, list[Finding]]:
    allow, findings = _load_allowlist(policy_root or root)
    scanned = 0
    reported_dirs: set[tuple[str, str]] = set()
    for path in _candidates(root):
        rel = path.relative_to(root)
        relp = rel.as_posix()
        parts = [p.lower() for p in rel.parts]
        if parts[0] == ".git":
            continue
        if not path.is_file():   # tracked but deleted in the working tree
            continue
        if len(parts) > 1 and parts[0] in FORBIDDEN_ROOT_DIRS and ("RUNTIME_DIRECTORY_PRESENT", parts[0]) not in reported_dirs:
            reported_dirs.add(("RUNTIME_DIRECTORY_PRESENT", parts[0]))
            findings.append(Finding(rel.parts[0], 0, "RUNTIME_DIRECTORY_PRESENT"))
        if any(p in FORBIDDEN_DIRS_ANYWHERE for p in parts[:-1]) or (".claude" in parts and "worktrees" in parts):
            findings.append(Finding(relp, 0, "BUILD_OR_CACHE_DIRECTORY_CONTENT"))
            continue
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

        def hit(rule: str, line_no: int) -> None:
            if relp in allow.get(rule, set()):
                return
            findings.append(Finding(relp, line_no, rule))

        if _PROMPT_FIXTURE_HINT_RE.search(text) and "synthetic" not in text.lower():
            hit("PROMPT_FIXTURE_NOT_MARKED_SYNTHETIC", 0)
        code = path.suffix.lower() in CODE_SUFFIXES
        fence = None
        for n, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("```"):
                fence = None if fence is not None else stripped[3:].strip().lower()
            _scan_line(line, lambda rule, n=n: hit(rule, n), code=code, mermaid=fence == "mermaid")
    return scanned, findings


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--policy-root", type=Path)
    parser.add_argument("root", nargs="?", type=Path, default=Path.cwd())
    args = parser.parse_args(argv[1:])
    root = args.root.resolve()
    policy_root = args.policy_root.resolve() if args.policy_root else None
    if not root.is_dir() or (policy_root is not None and not policy_root.is_dir()):
        print("scanner error: not a directory", file=sys.stderr)
        return 2
    try:
        scanned, findings = scan(root, policy_root)
    except (OSError, subprocess.CalledProcessError, UnicodeDecodeError) as e:
        print(f"scanner error: {type(e).__name__}", file=sys.stderr)
        return 2
    for f in sorted(findings, key=lambda f: (f.path, f.line, f.rule)):
        print(f"{f.rule:36} {f.path}:{f.line}")
    print(f"Files scanned:        {scanned}")
    print(f"Findings:             {len(findings)}")
    print(f"Gate:                 {'PASS' if not findings else 'FAIL'}")
    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
