#!/usr/bin/env python3
"""Validates the image build's proxy settings file before tools/pilot/build_config.sh stores it (PR 33 review D-03).

The file is the operator's env file for the uncommitted ConfigMap `<product>-build-proxy` (runtime contract, section
"build"): exactly the contract's keys (HTTP_PROXY, HTTPS_PROXY, NO_PROXY, GRADLE_OPTS), each once, `KEY=VALUE` lines,
`#` comments and blank lines allowed. Refused: a missing, unknown or repeated key; a file readable by group or others;
a proxy URL with credentials (userinfo), another scheme than http or https, no host, a path, query or fragment; a
GRADLE_OPTS word other than -Dhttp(s).proxyHost=, -Dhttp(s).proxyPort=<digits> and -Dhttp.nonProxyHosts= (so never
proxyUser or proxyPassword); an `@` anywhere; NO_PROXY without the in-cluster registry while a proxy is set. Values
are never printed: a refusal names the rule and the key only.

Usage: python3 -B tools/pilot/proxy_settings.py FILE CONTRACTS_JSON
       exit 0 valid, 1 refused (reasons on stderr), 2 usage
"""
from __future__ import annotations

import json
import os
import re
import stat
import sys
from pathlib import Path
from urllib.parse import urlsplit

REGISTRY = "registry.kube-system.svc.cluster.local"
_GRADLE_WORD = re.compile(r"^-Dhttps?\.proxyHost=[A-Za-z0-9.-]+$|^-Dhttps?\.proxyPort=[0-9]{1,5}$"
                          r"|^-Dhttps?\.nonProxyHosts=[A-Za-z0-9.*|-]+$")


def contract_keys(contracts: dict) -> list[str]:
    cms = (contracts.get("build") or {}).get("configMaps") or {}
    return list((cms.get("rwsafe-build-proxy") or {}).get("keys") or [])


def problems(text: str, keys: list[str], mode: int | None = None) -> list[str]:
    """Rule names (never values) the settings break."""
    out: list[str] = []
    if mode is not None and mode & (stat.S_IRWXG | stat.S_IRWXO):
        out.append("the file is readable or writable by group or others (chmod 0600)")
    seen: dict[str, str] = {}
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            out.append(f"line {n} is not KEY=VALUE")
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key not in keys:
            out.append(f"line {n}: key {key if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', key) else '?'} is not in the "
                       f"build contract")
            continue
        if key in seen:
            out.append(f"key {key} is repeated")
        seen[key] = value
    for key in keys:
        if key not in seen:
            out.append(f"key {key} is missing (empty is allowed on a network without a proxy)")
    for key, value in seen.items():
        if "@" in value:
            out.append(f"{key} holds an @ (credentials are never stored)")
    for key in ("HTTP_PROXY", "HTTPS_PROXY"):
        value = seen.get(key, "")
        if not value:
            continue
        try:
            u = urlsplit(value)
            port_ok = u.port is None or 0 < u.port < 65536
        except ValueError:
            out.append(f"{key} is not a URL")
            continue
        if u.scheme not in ("http", "https"):
            out.append(f"{key} is not an http or https URL")
        if u.username is not None or u.password is not None:
            out.append(f"{key} carries credentials (userinfo)")
        if not u.hostname:
            out.append(f"{key} has no host")
        if not port_ok:
            out.append(f"{key} has an invalid port")
        if u.path not in ("", "/") or u.query or u.fragment:
            out.append(f"{key} has a path, query or fragment")
    for word in seen.get("GRADLE_OPTS", "").split():
        if not _GRADLE_WORD.match(word):
            name = word.split("=", 1)[0] if word.startswith("-D") else "?"
            out.append(f"GRADLE_OPTS holds a word other than a proxy host, port or non-proxy list ({name})")
    if (seen.get("HTTP_PROXY") or seen.get("HTTPS_PROXY")) and REGISTRY not in seen.get("NO_PROXY", ""):
        out.append("NO_PROXY does not hold the in-cluster registry")
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python3 -B tools/pilot/proxy_settings.py FILE CONTRACTS_JSON", file=sys.stderr)
        return 2
    path, contracts = Path(argv[0]), Path(argv[1])
    keys = contract_keys(json.loads(contracts.read_text(encoding="utf-8")))
    if not keys:
        print("refused: the build contract names no proxy keys", file=sys.stderr)
        return 1
    try:
        st = os.stat(path)
        text = path.read_text(encoding="utf-8")
    except OSError:
        print("refused: the proxy settings file is missing or unreadable", file=sys.stderr)
        return 1
    found = problems(text, keys, st.st_mode)
    if found:
        for f in found:
            print(f"refused: {f}", file=sys.stderr)
        return 1
    print("proxy settings: valid (values not shown)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
