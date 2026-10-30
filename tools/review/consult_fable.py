#!/usr/bin/env python3
"""Consult Fable (Claude, `claude -p`) as an external reviewer or council seat, read-only (AGENTS.md 11).

Usage: python3 tools/review/consult_fable.py --brief BRIEF.md --output docs/reviews/<NAME>.md
       [--model claude-fable-5-1] [--add-dir DIR ...]
The reviewer gets the Read tool only, over this repository and the named directories. The brief passes review_guard.py
first. The full output is written unaltered with a provenance header."""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--brief", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--model", default="claude-fable-5-1")
    p.add_argument("--add-dir", type=Path, action="append", default=[])
    p.add_argument("--timeout", type=int, default=2400)
    a = p.parse_args()
    out = (BASE_DIR / a.output).resolve() if not a.output.is_absolute() else a.output
    if not str(out).startswith(str((BASE_DIR / "docs" / "reviews").resolve())):
        print("refused: the review output must live under docs/reviews/", file=sys.stderr)
        return 2
    guard = subprocess.run([sys.executable, str(BASE_DIR / "tools/review/review_guard.py"), str(a.brief)], text=True)
    if guard.returncode != 0:
        print("refused: the brief failed the content guard", file=sys.stderr)
        return 2
    claude = shutil.which("claude") or str(Path.home() / ".local/bin/claude")
    # --tools restricts the toolset to Read; --allowedTools pre-approves it so the non-interactive run never prompts.
    # No permission bypass flag: the reviewer can only read (AGENTS.md 11, roles/REVIEWER.md).
    cmd = [claude, "-p", a.brief.read_text(encoding="utf-8"), "--model", a.model, "--tools", "Read",
           "--allowedTools", "Read", "--add-dir", str(BASE_DIR)]
    for d in a.add_dir:
        cmd += ["--add-dir", str(d.expanduser().resolve())]
    print(f"[*] consulting Fable ({a.model}) via `claude -p --tools Read`...", flush=True)
    try:
        proc = subprocess.run(cmd, text=True, capture_output=True, cwd=str(BASE_DIR), timeout=a.timeout)
    except subprocess.TimeoutExpired:
        print("fable: timed out", file=sys.stderr)
        return 1
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(f"<!-- Fable consultation {stamp}, model {a.model}, exit {proc.returncode}; unaltered output -->\n\n"
                   + proc.stdout + (("\n\n<!-- stderr -->\n" + proc.stderr[-2000:]) if proc.stderr.strip() else ""),
                   encoding="utf-8")
    print(f"[*] written: {out.relative_to(BASE_DIR)} (exit {proc.returncode}, {len(proc.stdout)} chars)")
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
