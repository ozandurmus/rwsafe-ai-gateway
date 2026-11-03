#!/usr/bin/env python3
"""The pilot's directory address ranges (docs/operations/PILOT_RUNBOOK.md step 14.5): the one uncommitted, owner-only
file that tools/pilot/render.py reads to fill the NetworkPolicy `<product>-control-to-directory`.

The file (default ~/.config/<product>/pilot/directory.env, mode 0600, owned by the user who renders, not a symbolic
link, never inside the repository) holds one `DIRECTORY_CIDR=<IPv4 CIDR or single address>` line per range, at most 8,
with `#` comments and blank lines allowed. Each value passes tools/deploy/manifest_check.directory_block_problem (IPv4
inside RFC 1918 private space, no prefix shorter than /16, nothing touching loopback, link-local, multicast, reserved
or the cluster's pod and Service ranges), and no two overlap. A range comes from the directory or network team and is
typed on the host only (tools/pilot/directory_range.sh); it is never committed, printed or passed as a command argument
(AGENTS.md 4.2, 8). Every message names a line or entry number and a rule, never a value or a path.

Usage (for tools/pilot/directory_range.sh; values travel on stdin only):
  directory_range.py --check-next                   the accepted values, then the new one, one per line on stdin;
                                                    exit 0 the new one is accepted, 1 refused
  directory_range.py --write [FILE] [--product P]   one value per line on stdin; validates them all, replaces FILE
                                                    (default: the product's file; 0600, atomically), prints the count
  directory_range.py --check [FILE] [--product P]   validates the file as render.py reads it; prints the count
"""
from __future__ import annotations

import argparse
import errno
import ipaddress
import os
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "deploy"))
import manifest_check as mc  # noqa: E402

KEY = "DIRECTORY_CIDR"
MAX_RANGES = mc.DIRECTORY_MAX_BLOCKS


class RangeFileError(Exception):
    """The file is unusable; the message lists rules and line numbers only."""


def default_path(product: str) -> Path:
    return Path.home() / ".config" / product / "pilot" / "directory.env"


def normalise(value: str) -> str:
    """The canonical CIDR of an accepted value (a single address becomes /32)."""
    return str(ipaddress.ip_network(value, strict=True))


def entry_problems(values: list[str], what: str = "entry") -> list[str]:
    """Rules the values break (never a value): each value, the count, duplicates and overlaps."""
    out: list[str] = []
    nets: list[tuple[int, ipaddress.IPv4Network]] = []
    for n, value in enumerate(values, 1):
        problem = mc.directory_block_problem(value)
        if problem:
            out.append(f"{what} {n} {problem}")
            continue
        net = ipaddress.ip_network(value, strict=True)
        for m, other in nets:
            if net.overlaps(other):
                out.append(f"{what} {n} overlaps {what} {m}")
        nets.append((n, net))
    if not values:
        out.append(f"no {KEY} value")
    if len(values) > MAX_RANGES:
        out.append(f"{len(values)} ranges, more than {MAX_RANGES}")
    return out


def next_problems(accepted: list[str], candidate: str) -> list[str]:
    """Rules a newly typed range breaks beside the ranges already accepted (never a value)."""
    if any(mc.directory_block_problem(a) for a in accepted):
        return ["cannot be checked: an earlier range is not valid"]
    problem = mc.directory_block_problem(candidate)
    if problem:
        return [problem]
    net = ipaddress.ip_network(candidate, strict=True)
    if any(net.overlaps(ipaddress.ip_network(a, strict=True)) for a in accepted):
        return ["overlaps a range typed earlier"]
    if len(accepted) >= MAX_RANGES:
        return [f"is one more than {MAX_RANGES}"]
    return []


def parse(text: str) -> tuple[list[str], list[str]]:
    """(values, problems) of the file's text."""
    values: list[str] = []
    problems: list[str] = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or key != KEY:
            problems.append(f"line {n} is not {KEY}=<range>")
            continue
        values.append(value)
    problems += entry_problems(values, "value")
    if problems:
        return [], problems
    return [normalise(v) for v in values], []


def _os_reason(e: OSError) -> str:
    """An OSError's reason without its file name (PR 54 review D-02: the name carries the account's home)."""
    return os.strerror(e.errno) if e.errno else "an operating-system error"


def load(path: Path) -> list[str] | None:
    """The normalised ranges of `path`, None when it does not exist; RangeFileError when it is unusable. Opened once
    without following a symbolic link; owner and mode are checked on the open file before anything is read."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return None
    except OSError as e:
        if e.errno == errno.ELOOP:
            raise RangeFileError("the file is not a regular file (a symbolic link or another kind)") from None
        raise RangeFileError(f"the file cannot be opened: {_os_reason(e)}") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise RangeFileError("the file is not a regular file (a symbolic link or another kind)")
        problems: list[str] = []
        if st.st_uid != os.getuid():
            problems.append("the file is not owned by the user who renders")
        if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            problems.append("the file is readable or writable by group or others (chmod 0600)")
        if problems:
            raise RangeFileError("; ".join(problems))
        data = b""
        while chunk := os.read(fd, 65536):
            data += chunk
            if len(data) > 65536:
                raise RangeFileError("the file is larger than 64 KiB")
    except OSError as e:
        raise RangeFileError(f"the file cannot be read: {_os_reason(e)}") from None
    finally:
        os.close(fd)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise RangeFileError("the file is not UTF-8 text") from None
    values, rules = parse(text)
    if rules:
        raise RangeFileError("; ".join(rules))
    return values


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def write(path: Path, values: list[str]) -> int:
    """Validates `values` and replaces `path` atomically with mode 0600; returns the count. Refused inside the
    repository and when the file or one of its two nearest directories is a symbolic link; the temporary file never
    outlives a failure."""
    problems = entry_problems(values)
    if problems:
        raise RangeFileError("; ".join(problems))
    path = path.expanduser()
    if _inside(path, mc.REPO_ROOT):
        raise RangeFileError("the file would be inside the repository")
    for p in (path, path.parent, path.parent.parent):
        if p.is_symlink():
            raise RangeFileError("the file or one of its directories is a symbolic link")
    text = "# directory ranges for NetworkPolicy <product>-control-to-directory (PILOT_RUNBOOK.md step 14.5)\n" + "".join(
        f"{KEY}={normalise(v)}\n" for v in values)
    tmp = path.with_name(f".{path.name}.incoming")
    done = False
    try:
        if os.path.lexists(tmp):
            os.unlink(tmp)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, text.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
        done = True
    except OSError as e:
        raise RangeFileError(f"the file cannot be written: {_os_reason(e)}") from None
    finally:
        if not done:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return len(values)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check-next", action="store_true")
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    ap.add_argument("file", nargs="?", type=Path)
    ap.add_argument("--product", help="default: the PRODUCT= line of deploy/rwsafe/product.env")
    args = ap.parse_args(argv)
    try:
        if args.check_next:
            values = [line.rstrip("\r\n") for line in sys.stdin.readlines()]
            problems = next_problems(values[:-1], values[-1]) if values else ["no value"]
            if problems:
                print("refused: the range " + "; ".join(problems), file=sys.stderr)
                return 1
            return 0
        product = args.product or mc.default_product()
        if mc.validate_product(product):
            print("refused: the product name is not valid", file=sys.stderr)
            return 2
        path = args.file or default_path(product)
        if args.write:
            values = [line.rstrip("\r\n") for line in sys.stdin.readlines() if line.strip()]
            count = write(path, values)
            print(f"directory ranges: {count} range(s) written (mode 0600); no value was printed")
            return 0
        values = load(path)
        if values is None:
            print("directory ranges: no file", file=sys.stderr)
            return 1
        print(f"directory ranges: {len(values)} range(s) valid; no value was printed")
        return 0
    except RangeFileError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
