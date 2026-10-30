#!/usr/bin/env python3
"""Aggregate-only shapes of a ProxySG access log (ROADMAP phase 0, Q-30; AGENTS.md section 4).

Run by the Product Owner on the machine that holds the raw log. The raw log is never read by an agent and never enters the
repository. The output contains counts, buckets and vendor-published platform labels only: no host name outside the
vendor list below, no client address, no user, no URL path or query, no user-agent string. A final self-check refuses to
print if anything address- or e-mail-shaped would be emitted.

Input: one or more W3C extended log files as ProxySG writes them (a "#Fields:" header names the columns; values with
spaces are double-quoted), plain or .gz. Columns that are missing are reported as absent, never guessed.

Usage:
    python3 tools/proxysg/access_log_shapes.py /path/outside/the/repo/main_*.log.gz > shapes.md
"""
from __future__ import annotations

import argparse
import csv
import gzip
import io
import re
import sys
from collections import Counter, defaultdict
from typing import Iterable, Iterator

# Vendor-published endpoints (docs/product/PLATFORM_MATRIX.md section 2). Suffix match on the request host.
PLATFORMS: dict[str, tuple[str, ...]] = {
    "claude": ("claude.ai", "anthropic.com"),
    "copilot": ("githubcopilot.com", "copilot-proxy.githubusercontent.com", "exp-tas.com"),
    "github": ("github.com", "ghe.com"),
    "openai": ("chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com"),
    "devin": ("devin.ai",),
    "windsurf": ("windsurf.com", "codeium.com"),
    "gemini": ("gemini.google.com", "generativelanguage.googleapis.com", "cloudcode-pa.googleapis.com",
               "aiplatform.googleapis.com"),
    "google-auth": ("accounts.google.com", "oauth2.googleapis.com"),
    "microsoft-auth": ("login.microsoftonline.com", "login.microsoft.com", "login.windows.net", "login.live.com"),
    "m365-copilot": ("copilot.microsoft.com", "copilot.cloud.microsoft", "substrate.office.com"),
}

# Path shapes of LLM APIs, used only to count uncategorised hosts that look like relays (Q-30). Never printed.
LLM_PATH = re.compile(
    r"/(v1|v1beta|openai)/(chat/completions|completions|messages|responses|embeddings|models)\b"
    r"|:(generateContent|streamGenerateContent)\b|/api/(generate|chat)\b",
    re.IGNORECASE,
)
UNCATEGORISED = re.compile(r"^\s*(none|uncategori[sz]ed|unavailable|pending)\s*$", re.IGNORECASE)

UA_CLASSES = (
    ("vscode", re.compile(r"vscode|visual studio code|copilot-chat|github-copilot", re.I)),
    ("jetbrains", re.compile(r"jetbrains|intellij|pycharm|webstorm|goland", re.I)),
    ("claude-code", re.compile(r"claude-cli|claude-code|claudecode", re.I)),
    ("codex-cli", re.compile(r"codex", re.I)),
    ("node-sdk", re.compile(r"node|axios|undici|openai/js|anthropic/js", re.I)),
    ("python-sdk", re.compile(r"python|httpx|aiohttp|openai/python|anthropic/python", re.I)),
    ("electron-app", re.compile(r"electron", re.I)),
    ("browser", re.compile(r"mozilla/5\.0", re.I)),
)

SIZE_BUCKETS = ((0, "0"), (4 * 1024, "<=4KiB"), (64 * 1024, "<=64KiB"), (1024 * 1024, "<=1MiB"),
                (4 * 1024 * 1024, "<=4MiB"), (16 * 1024 * 1024, "<=16MiB"))
TIME_BUCKETS_MS = ((100, "<=100ms"), (1000, "<=1s"), (10_000, "<=10s"), (30_000, "<=30s"), (120_000, "<=120s"),
                   (300_000, "<=300s"))
SMALL_CELL = 5  # distinct-user counts below this are shown as "<5"

IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def size_bucket(value: str) -> str:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return "absent"
    if n == 0:
        return "0"
    for limit, label in SIZE_BUCKETS[1:]:
        if n <= limit:
            return label
    return ">16MiB"


def time_bucket(value: str) -> str:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return "absent"
    for limit, label in TIME_BUCKETS_MS:
        if n <= limit:
            return label
    return ">300s"


def platform_of(host: str) -> str | None:
    host = host.lower().rstrip(".")
    for name, suffixes in PLATFORMS.items():
        for suffix in suffixes:
            if host == suffix or host.endswith("." + suffix):
                return name
    return None


def ua_class(ua: str) -> str:
    if not ua or ua == "-":
        return "absent"
    for name, pattern in UA_CLASSES:
        if pattern.search(ua):
            return name
    return "other"


def open_text(path: str) -> io.TextIOBase:
    if path.endswith(".gz"):
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8", errors="replace")
    return open(path, encoding="utf-8", errors="replace")


def records(paths: Iterable[str]) -> Iterator[dict[str, str]]:
    for path in paths:
        fields: list[str] | None = None
        with open_text(path) as handle:
            for line in handle:
                if line.startswith("#Fields:"):
                    fields = line[len("#Fields:"):].split()
                    continue
                if line.startswith("#") or not line.strip() or fields is None:
                    continue
                row = next(csv.reader([line.rstrip("\n")], delimiter=" ", quotechar='"', skipinitialspace=True))
                if len(row) != len(fields):
                    yield {"__malformed__": "1"}
                    continue
                yield dict(zip(fields, row))


def get(rec: dict[str, str], *names: str) -> str:
    for name in names:
        if name in rec:
            return rec[name]
    return ""


def small(n: int) -> str:
    return f"<{SMALL_CELL}" if 0 < n < SMALL_CELL else str(n)


def analyse(paths: Iterable[str], ai_category: re.Pattern[str]) -> dict:
    seen_fields: set[str] = set()
    total = malformed = 0
    per_platform: dict[str, Counter] = defaultdict(Counter)
    users: dict[str, set[str]] = defaultdict(set)
    ai_category_labels: Counter = Counter()
    unc = Counter()
    unc_hosts: set[str] = set()
    unc_llm_hosts: set[str] = set()
    for rec in records(paths):
        total += 1
        if "__malformed__" in rec:
            malformed += 1
            continue
        seen_fields.update(rec.keys())
        host = get(rec, "cs-host", "cs(Host)", "r-dns")
        cats = get(rec, "cs-categories", "sc-filter-category")
        path = get(rec, "cs-uri-path", "cs-uri-stem")
        plat = platform_of(host) if host else None
        cat_list = [c.strip() for c in cats.split(";")] if cats else []
        is_ai_cat = any(ai_category.search(c) for c in cat_list)
        if is_ai_cat:
            for c in cat_list:
                if ai_category.search(c):
                    ai_category_labels[c] += 1
        if plat is None and is_ai_cat:
            plat = "ai-category-other"
        if plat is not None:
            c = per_platform[plat]
            c["requests"] += 1
            c["hour:" + (get(rec, "time")[:2] or "absent")] += 1
            c["method:" + (get(rec, "cs-method") or "absent").upper()] += 1
            status = get(rec, "sc-status")
            c["status:" + (status[:1] + "xx" if status[:1].isdigit() else "absent")] += 1
            if status == "101":
                c["websocket-upgrade"] += 1
            c["action:" + (get(rec, "s-action") or "absent")] += 1
            c["req-bytes:" + size_bucket(get(rec, "cs-bytes"))] += 1
            c["resp-bytes:" + size_bucket(get(rec, "sc-bytes"))] += 1
            c["time:" + time_bucket(get(rec, "time-taken"))] += 1
            c["client:" + ua_class(get(rec, "cs(User-Agent)", "cs-user-agent"))] += 1
            c["categorised-ai:" + ("yes" if is_ai_cat else "no")] += 1
            user = get(rec, "cs-username")
            if user and user != "-":
                users[plat].add(user)
        elif cat_list and all(UNCATEGORISED.match(x) for x in cat_list):
            unc["requests"] += 1
            unc["req-bytes:" + size_bucket(get(rec, "cs-bytes"))] += 1
            if host:
                unc_hosts.add(host.lower())
                if path and LLM_PATH.search(path):
                    unc_llm_hosts.add(host.lower())
                    unc["llm-shaped-requests"] += 1
    return {
        "total": total, "malformed": malformed, "fields": seen_fields, "per_platform": per_platform,
        "users": {k: len(v) for k, v in users.items()}, "ai_category_labels": ai_category_labels,
        "unc": unc, "unc_hosts": len(unc_hosts), "unc_llm_hosts": len(unc_llm_hosts),
    }


WANTED_FIELDS = ("date", "time", "time-taken", "cs-host", "cs-method", "sc-status", "s-action", "cs-bytes", "sc-bytes",
                 "cs-categories", "cs-uri-path", "cs(User-Agent)", "cs-username")


def render(result: dict) -> str:
    out = ["# ProxySG access-log shapes (aggregate only)", ""]
    out.append(f"Records: {result['total']}; malformed lines: {result['malformed']}")
    present = [f for f in WANTED_FIELDS if f in result["fields"]]
    absent = [f for f in WANTED_FIELDS if f not in result["fields"]]
    out.append(f"Fields present: {', '.join(present) or 'none'}")
    out.append(f"Fields absent: {', '.join(absent) or 'none'}")
    out.append("")
    out.append("## AI category labels seen (vendor taxonomy)")
    for label, n in result["ai_category_labels"].most_common(10):
        out.append(f"- {label}: {n}")
    if not result["ai_category_labels"]:
        out.append("- none matched; re-run with --ai-category set to the estate's category name pattern")
    out.append("")
    out.append("## Per platform")
    for plat in sorted(result["per_platform"]):
        c = result["per_platform"][plat]
        out.append(f"### {plat}")
        out.append(f"- requests: {c['requests']}; distinct users: {small(result['users'].get(plat, 0))}; "
                   f"websocket upgrades (101): {c['websocket-upgrade']}")
        for prefix in ("categorised-ai", "method", "status", "action", "req-bytes", "resp-bytes", "time", "client"):
            items = sorted((k.split(":", 1)[1], v) for k, v in c.items() if k.startswith(prefix + ":"))
            out.append(f"- {prefix}: " + ", ".join(f"{k}={v}" for k, v in items))
        hours = [c.get(f"hour:{h:02d}", 0) for h in range(24)]
        out.append("- requests by hour 00..23: " + " ".join(str(h) for h in hours))
        out.append("")
    out.append("## Uncategorised traffic (Q-30)")
    u = result["unc"]
    out.append(f"- requests: {u['requests']}; distinct hosts: {result['unc_hosts']}; "
               f"hosts with LLM-API path shapes: {result['unc_llm_hosts']} ({u['llm-shaped-requests']} requests)")
    items = sorted((k.split(":", 1)[1], v) for k, v in u.items() if k.startswith("req-bytes:"))
    out.append("- req-bytes: " + ", ".join(f"{k}={v}" for k, v in items))
    return "\n".join(out) + "\n"


def self_check(text: str) -> None:
    if IPV4.search(text) or EMAIL.search(text):
        raise SystemExit("refusing to print: an address- or e-mail-shaped value reached the output (check --ai-category)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("logs", nargs="+", help="raw access log files (outside the repository)")
    parser.add_argument("--ai-category", default=r"artificial intelligence|\bAI\b|generative|machine learning|chatbot",
                        help="regex for the estate's AI category name(s) in cs-categories")
    args = parser.parse_args(argv)
    text = render(analyse(args.logs, re.compile(args.ai_category, re.IGNORECASE)))
    self_check(text)
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
