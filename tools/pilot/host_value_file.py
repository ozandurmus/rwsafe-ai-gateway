#!/usr/bin/env python3
"""The pilot's uncommitted, owner-only host value files (`KEY=value` lines; PILOT_RUNBOOK.md steps 11.5 and 14.5:
tools/pilot/icap_clients.py, tools/pilot/directory_range.py): reading, validating and replacing one without ever
printing, logging or leaving a copy of a value.

A file is read once, opened without following a symbolic link, and used only when it is a regular file of at most
64 KiB, owned by the user who runs, and not readable or writable by group or others (checked on the open file). It is
written only outside the repository; neither is used when the file or one of its directories up to ~/.config is a
symbolic link. A write goes
atomically through a temporary file in the same directory (`.<name>.incoming`, gitignored) that is created
exclusively with mode 0600 and never outlives a failure. Every message names a line number and a rule, never a value
or a path (PR 54 review D-02: a path carries the account name in $HOME; AGENTS.md 4.2).
"""
from __future__ import annotations

import errno
import os
import stat
import sys
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "deploy"))
import manifest_check as mc  # noqa: E402

MAX_BYTES = 65536


class HostFileError(Exception):
    """The file is unusable; the message lists rules and line numbers only."""


def os_reason(e: OSError) -> str:
    """An OSError's reason without its file name."""
    return os.strerror(e.errno) if e.errno else "an operating-system error"


def parse(text: str, key: str, entry_problems: Callable[[list[str], str], list[str]],
          shape: str = "<value>") -> tuple[list[str], list[str]]:
    """(values, problems) of a file's text: `#` comments and blank lines skipped, every other line `key=<value>`, then
    `entry_problems(values, "value")`."""
    values: list[str] = []
    problems: list[str] = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        k, sep, value = line.partition("=")
        if not sep or k != key:
            problems.append(f"line {n} is not {key}={shape}")
            continue
        values.append(value)
    problems += entry_problems(values, "value")
    return (values, []) if not problems else ([], problems)


def linked_part(path: Path) -> bool:
    """True when the file, its directory, the directory above, or (when it is named `.config`) the one above that is a
    symbolic link: ~/.config/<product>/pilot/<file> is checked up to ~/.config (PR 56 review D-04)."""
    parts = [path, path.parent, path.parent.parent]
    if path.parent.parent.parent.name == ".config":
        parts.append(path.parent.parent.parent)
    return any(p.is_symlink() for p in parts)


def load(path: Path, key: str, entry_problems: Callable[[list[str], str], list[str]],
         shape: str = "<value>") -> list[str] | None:
    """The values of `path`, None when it does not exist; HostFileError when it is unusable."""
    path = path.expanduser()
    if linked_part(path):
        raise HostFileError("the file or one of its directories is a symbolic link")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return None
    except OSError as e:
        if e.errno == errno.ELOOP:
            raise HostFileError("the file is not a regular file (a symbolic link or another kind)") from None
        raise HostFileError(f"the file cannot be opened: {os_reason(e)}") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise HostFileError("the file is not a regular file (a symbolic link or another kind)")
        problems: list[str] = []
        if st.st_uid != os.getuid():
            problems.append("the file is not owned by the user who renders")
        if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            problems.append("the file is readable or writable by group or others (chmod 0600)")
        if problems:
            raise HostFileError("; ".join(problems))
        data = b""
        while chunk := os.read(fd, MAX_BYTES):
            data += chunk
            if len(data) > MAX_BYTES:
                raise HostFileError("the file is larger than 64 KiB")
    except OSError as e:
        raise HostFileError(f"the file cannot be read: {os_reason(e)}") from None
    finally:
        os.close(fd)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise HostFileError("the file is not UTF-8 text") from None
    values, rules = parse(text, key, entry_problems, shape)
    if rules:
        raise HostFileError("; ".join(rules))
    return values


def inside_repository(path: Path) -> bool:
    try:
        path.resolve().relative_to(mc.REPO_ROOT.resolve())
        return True
    except ValueError:
        return False


def write(path: Path, header: str, key: str, values: list[str]) -> int:
    """Replaces `path` with `header` and one `key=value` line per value, mode 0600; returns the count. The caller has
    validated the values."""
    path = path.expanduser()
    if inside_repository(path):
        raise HostFileError("the file would be inside the repository")
    if linked_part(path):
        raise HostFileError("the file or one of its directories is a symbolic link")
    text = header + "".join(f"{key}={v}\n" for v in values)
    tmp = path.with_name(f".{path.name}.incoming")
    done = False
    try:
        if os.path.lexists(tmp):
            os.unlink(tmp)          # a leftover of an interrupted run; unlink removes a link, never follows it
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o600)
            data = text.encode("utf-8")
            while data:
                data = data[os.write(fd, data):]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
        done = True
    except OSError as e:
        raise HostFileError(f"the file cannot be written: {os_reason(e)}") from None
    finally:
        if not done:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return len(values)
