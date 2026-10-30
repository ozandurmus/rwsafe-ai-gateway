#!/usr/bin/env python3
"""Run one development task on Argon (Google Antigravity CLI `agy`) inside a git worktree (AGENTS.md 13).

Usage: python3 tools/review/argon_task.py --worktree ~/Codo/rwsafe-<lane> --brief BRIEF.md [--model gemini-4-argon-high]
       [--effort high] [--timeout 0] [--log FILE] [--add-dir DIR]
Guard rails: the worktree must be a linked git worktree under the prefix in .rwsafe-delivery.json, on a feature branch;
the brief passes review_guard.py; logs go under the home, never /tmp. Argon commits on the lane and never pushes."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
MANIFEST = json.loads((BASE_DIR / ".rwsafe-delivery.json").read_text(encoding="utf-8"))
WORKER_RULES = """
## Standing rules for every Argon task (rwsafe-ai-gateway)
- Work ONLY in this worktree; commit on its current branch with English messages ending with
  `Co-Authored-By: Gemini 4 Argon` (no e-mail address: the repository privacy gate forbids one).
- Never push, open a PR, deploy, ssh, reach HOST-A, a proxy, a directory or an AI platform; never print a secret.
- Read AGENTS.md first: masking law (section 4), data-plane law (5), policy-registry law (6), English artefacts (3).
- No prompt body, real host, address, account, serial or secret-shaped literal in code, tests, fixtures or messages:
  RFC 5737 addresses, invented names, synthetic prompts, runtime-built secrets.
- Run the tests the task names and `python3 tools/privacy/repository_privacy_check.py` before you finish; report exact
  counts; if something cannot pass, say so instead of weakening a test.
- Finish with a short report: what changed, test results, open issues, commit hashes.
"""


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--worktree", required=True, type=Path)
    p.add_argument("--brief", required=True, type=Path)
    p.add_argument("--model", default="gemini-4-argon-high")
    p.add_argument("--effort", default="high", choices=["low", "medium", "high", "xhigh", "max"])
    p.add_argument("--timeout", default="0")
    p.add_argument("--log", type=Path)
    p.add_argument("--add-dir", type=Path, action="append", default=[])
    a = p.parse_args()
    prefix = Path(MANIFEST["worktree_prefix"]).expanduser()
    wt = a.worktree.expanduser().resolve()
    if wt.parent != prefix.parent.resolve() or not wt.name.startswith(prefix.name):
        print(f"refused: {wt} is not a {MANIFEST['worktree_prefix']}* worktree", file=sys.stderr)
        return 2
    git_dir = subprocess.run(["git", "-C", str(wt), "rev-parse", "--git-dir"], capture_output=True, text=True)
    if git_dir.returncode != 0 or "/worktrees/" not in git_dir.stdout:
        print(f"refused: {wt} is not a linked git worktree", file=sys.stderr)
        return 2
    branch = subprocess.run(["git", "-C", str(wt), "branch", "--show-current"], capture_output=True, text=True).stdout.strip()
    if branch in ("", "main", "master"):
        print("refused: worktree must be on a feature branch", file=sys.stderr)
        return 2
    if subprocess.run([sys.executable, str(BASE_DIR / "tools/review/review_guard.py"), str(a.brief)]).returncode != 0:
        print("refused: the brief failed the content guard", file=sys.stderr)
        return 2
    prompt = a.brief.expanduser().read_text(encoding="utf-8") + "\n" + WORKER_RULES
    log_dir = Path.home() / "rwsafe-logs"
    log_dir.mkdir(exist_ok=True)
    log = a.log or log_dir / f"argon-{wt.name}-{int(time.time())}.log"
    cmd = ["agy", "-p", prompt, "--model", a.model, "--effort", a.effort, "--mode", "accept-edits", "--print-timeout", a.timeout]
    for extra in a.add_dir:
        cmd += ["--add-dir", str(extra.expanduser())]
    print(f"[argon] worktree={wt} branch={branch} model={a.model} effort={a.effort} log={log}", flush=True)
    with log.open("w", encoding="utf-8") as out:
        rc = subprocess.run(cmd, cwd=wt, stdout=out, stderr=subprocess.STDOUT).returncode
    text = log.read_text(encoding="utf-8", errors="replace")
    print(text[-4000:])
    if "no output produced" in text or "auto-denied" in text:
        print("[argon] FAILED: a permission was auto-denied; extend the Antigravity settings allowlist and rerun", file=sys.stderr)
        rc = rc or 3
    print(f"[argon] exit={rc} head={subprocess.run(['git', '-C', str(wt), 'log', '--oneline', '-1'], capture_output=True, text=True).stdout.strip()}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
