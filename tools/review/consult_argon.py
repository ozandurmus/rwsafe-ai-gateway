#!/usr/bin/env python3
"""Consult Argon (Google Antigravity CLI `agy`) as an external reviewer, read-only (AGENTS.md 11).

Usage: python3 tools/review/consult_argon.py --brief BRIEF.md --output docs/reviews/ARGON_<TOPIC>.md
       [--model gemini-4-argon-high] [--effort high]
The brief passes review_guard.py first; the output root must be docs/reviews/; the full output is written unaltered."""
from __future__ import annotations

import argparse
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--brief", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--model", default="gemini-4-argon-high")
    p.add_argument("--effort", default="high", choices=["low", "medium", "high", "xhigh", "max"])
    a = p.parse_args()
    out = (BASE_DIR / a.output).resolve() if not a.output.is_absolute() else a.output
    if not str(out).startswith(str((BASE_DIR / "docs" / "reviews").resolve())):
        print("refused: the review output must live under docs/reviews/", file=sys.stderr)
        return 2
    guard = subprocess.run([sys.executable, str(BASE_DIR / "tools/review/review_guard.py"), str(a.brief)], text=True)
    if guard.returncode != 0:
        print("refused: the brief failed the content guard", file=sys.stderr)
        return 2
    prompt = a.brief.read_text(encoding="utf-8")
    cmd = ["agy", "-p", prompt, "--model", a.model, "--effort", a.effort, "--mode", "plan", "--print-timeout", "0"]
    print(f"[*] consulting Argon ({a.model}, effort {a.effort}) via `agy -p --mode plan`...", flush=True)
    result = subprocess.run(cmd, cwd=BASE_DIR, capture_output=True, text=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(f"<!-- Argon consultation {stamp}, model {a.model}, effort {a.effort}; unaltered output -->\n\n"
                   + result.stdout + (("\n\n<!-- stderr -->\n" + result.stderr) if result.stderr.strip() else ""),
                   encoding="utf-8")
    print(f"[*] written: {out.relative_to(BASE_DIR)} (exit {result.returncode})")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
