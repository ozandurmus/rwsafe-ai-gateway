#!/usr/bin/env python3
"""The pilot's uncommitted, owner-only host value files (`KEY=value` lines; PILOT_RUNBOOK.md steps 11.5 and 14.5):
reading, validating and replacing one without ever printing, logging or leaving a copy of a value.

A file is read only when it is a regular file (never a symbolic link), owned by the user who runs, and not readable or
writable by group or others. It is written only outside the repository, never through a symbolic link (the file or
its directory), atomically through a temporary file in the same directory (`.<name>.incoming`, gitignored) that is
created exclusively with mode 0600 and removed in every outcome. Every message names a line number and a rule, never
a value (AGENTS.md 4.2).
"""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "deploy"))
import manifest_check as mc  # noqa: E402


class HostFileError(Exception):
    """The file is unusable; the message lists rules and line numbers only."""


def parse(text: str, key: str, entry_problems: Callable[[list[str], str], list[str]]) -> tuple[list[str], list[str]]:
    """(values, problems) of a file's text: `#` comments and blank lines skipped, every other line `key=<value>` (a
    trailing carriage return dropped), then `entry_problems(values, "value")`."""
    values: list[str] = []
    problems: list[str] = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        k, sep, value = line.partition("=")
        if not sep or k != key:
            problems.append(f"line {n} is not {key}=<value>")
            continue
        values.append(value)
    problems += entry_problems(values, "value")
    return (values, []) if not problems else ([], problems)


def load(path: Path, key: str, entry_problems: Callable[[list[str], str], list[str]]) -> list[str] | None:
    """The values of `path`, None when it does not exist; HostFileError when it is unusable."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise HostFileError("the file is not a regular file (a symbolic link or another kind)")
    problems: list[str] = []
    if st.st_uid != os.getuid():
        problems.append("the file is not owned by the user who renders")
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        problems.append("the file is readable or writable by group or others (chmod 0600)")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, encoding="utf-8") as f:
        values, rules = parse(f.read(), key, entry_problems)
    problems += rules
    if problems:
        raise HostFileError("; ".join(problems))
    return values


def inside_repository(path: Path) -> bool:
    try:
        path.expanduser().resolve().relative_to(mc.REPO_ROOT.resolve())
        return True
    except ValueError:
        return False


def write(path: Path, header: str, key: str, values: list[str]) -> int:
    """Replaces `path` with `header` and one `key=value` line per value, mode 0600; returns the count. The caller has
    validated the values. Refused inside the repository and through a symbolic link (the file or its directory)."""
    if inside_repository(path):
        raise HostFileError("the file would be inside the repository")
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise HostFileError("the file's directory is a symbolic link or not a directory")
    if path.is_symlink():
        raise HostFileError("the file is a symbolic link")
    text = header + "".join(f"{key}={v}\n" for v in values)
    tmp = path.with_name(f".{path.name}.incoming")
    try:
        os.unlink(tmp)                  # a leftover from an interrupted run (never followed: unlink removes the link)
    except FileNotFoundError:
        pass
    replaced = False
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, text.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
        replaced = True
    finally:
        if not replaced:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
    return len(values)
