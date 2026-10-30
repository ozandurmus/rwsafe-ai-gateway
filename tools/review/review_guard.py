#!/usr/bin/env python3
"""Content guard for external-review briefs (AGENTS.md 4.6, 4.7).

Refuses a brief that: contains a JSON field named like a prompt body (messages, prompt, contents, input, completion,
response_text), contains a repository privacy-gate finding when scanned as text, or is larger than the size cap.
Prints only rule names and line numbers, never the offending text."""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "privacy"))
import repository_privacy_check as gate  # noqa: E402

BODY_FIELD = re.compile(r'"(messages|prompt|contents|input|completion|response_text|raw_body|body)"\s*:')
MAX_BYTES = 400_000


def check(path: Path) -> list[str]:
    problems: list[str] = []
    data = path.read_bytes()
    if len(data) > MAX_BYTES:
        problems.append(f"BRIEF_TOO_LARGE ({len(data)} bytes > {MAX_BYTES})")
    text = data.decode("utf-8", errors="replace")
    for n, line in enumerate(text.splitlines(), 1):
        if BODY_FIELD.search(line):
            problems.append(f"PROMPT_BODY_FIELD line {n}")
        if gate._EMAIL_RE.search(line) and "example.invalid" not in line:
            problems.append(f"EMAIL_ADDRESS line {n}")
        for m in gate._IPV4_RE.finditer(line):
            if not gate._is_repository_safe_ip(m.group(0), test_fixture=False):
                problems.append(f"NON_DOCUMENTATION_IPV4 line {n}")
                break
        for rx, rule in ((gate._ANTHROPIC_KEY_RE, "ANTHROPIC_KEY_SHAPE"), (gate._OPENAI_KEY_RE, "OPENAI_KEY_SHAPE"),
                         (gate._GOOGLE_KEY_RE, "GOOGLE_KEY_SHAPE"), (gate._GITHUB_TOKEN_RE, "GITHUB_TOKEN_SHAPE")):
            if rx.search(line) and "synthetic" not in line.lower():
                problems.append(f"{rule} line {n}")
        for m in gate._TCKN_RE.finditer(line):
            if gate.tckn_valid(m.group(0)):
                problems.append(f"TCKN_WITH_VALID_CHECKSUM line {n}")
        for m in gate._TR_IBAN_RE.finditer(line):
            if gate.iban_valid(m.group(0)):
                problems.append(f"TR_IBAN line {n}")
    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: review_guard.py BRIEF", file=sys.stderr)
        return 2
    problems = check(Path(argv[1]))
    for p in problems:
        print("REFUSED:", p)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
