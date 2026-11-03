#!/usr/bin/env python3
"""The pilot's ICAP clients (docs/operations/PILOT_RUNBOOK.md step 11.5): the one uncommitted, owner-only file that
tools/pilot/render.py reads to fill the NetworkPolicy `<product>-icap-from-proxies` (the ProxySG addresses that may
open TCP 1344 on the ICAP pods).

The file (default ~/.config/<product>/pilot/icap-clients.env, mode 0600, owned by the user who renders, not a symbolic
link) holds one `PROXY_ADDR=<IPv4 address>` line per proxy, at most 8, with `#` comments and blank lines allowed. Each
value is one address (no prefix) that tools/deploy/manifest_check.icap_client_problem accepts: IPv4, private (RFC
1918), outside loopback, link-local, multicast, reserved, broadcast, "this network" and the cluster's pod and Service
ranges; no duplicate. The addresses are the ones the host firewall step admits (step 11); they are typed on the host
only (tools/pilot/icap_clients.sh), never committed, printed or passed as a command argument (AGENTS.md 4.2, 8). Every
message names a line or entry number and a rule, never a value. File handling: tools/pilot/host_value_file.py.

Usage (for tools/pilot/icap_clients.sh; values travel on stdin only):
  python3 -B tools/pilot/icap_clients.py --check-next    the accepted values, then the new one, one per line on stdin;
                                                         exit 0 the new one is accepted, 1 refused
  python3 -B tools/pilot/icap_clients.py --write FILE    one value per line on stdin; validates them all, writes FILE
                                                         (0600, atomically), prints the count; exit 0, 1 refused
  python3 -B tools/pilot/icap_clients.py --check FILE    validates FILE as render.py reads it; prints the count
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import host_value_file as hvf  # noqa: E402

mc = hvf.mc
KEY = "PROXY_ADDR"
MAX_ADDRESSES = mc.ICAP_CLIENTS_MAX
HEADER = "# ProxySG addresses for NetworkPolicy <product>-icap-from-proxies (PILOT_RUNBOOK.md step 11.5)\n"
Error = hvf.HostFileError


def default_path(product: str) -> Path:
    return Path.home() / ".config" / product / "pilot" / "icap-clients.env"


def entry_problems(values: list[str], what: str = "entry") -> list[str]:
    """Rules the values break (never a value): each value, the count, duplicates."""
    out: list[str] = []
    seen: dict[str, int] = {}
    for n, value in enumerate(values, 1):
        problem = mc.icap_client_problem(value)
        if problem:
            out.append(f"{what} {n} {problem}")
            continue
        if value in seen:
            out.append(f"{what} {n} repeats {what} {seen[value]}")
        seen.setdefault(value, n)
    if not values:
        out.append(f"no {KEY} value")
    if len(values) > MAX_ADDRESSES:
        out.append(f"{len(values)} addresses, more than {MAX_ADDRESSES}")
    return out


def next_problems(accepted: list[str], candidate: str) -> list[str]:
    """Rules a newly typed address breaks beside the ones already accepted (never a value)."""
    problem = mc.icap_client_problem(candidate)
    if problem:
        return [problem]
    if candidate in accepted:
        return ["repeats an address typed earlier"]
    if len(accepted) >= MAX_ADDRESSES:
        return [f"is one more than {MAX_ADDRESSES}"]
    return []


def load(path: Path) -> list[str] | None:
    """The addresses of `path`, None when it does not exist; HostFileError when it is unusable."""
    return hvf.load(path, KEY, entry_problems)


def write(path: Path, values: list[str]) -> int:
    problems = entry_problems(values)
    if problems:
        raise Error("; ".join(problems))
    return hvf.write(path, HEADER, KEY, values)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    try:
        if argv == ["--check-next"]:
            values = [line.rstrip("\r\n") for line in sys.stdin.readlines()]
            problems = next_problems(values[:-1], values[-1]) if values else ["no value"]
            if problems:
                print("refused: the address " + "; ".join(problems), file=sys.stderr)
                return 1
            return 0
        if len(argv) == 2 and argv[0] == "--write":
            values = [line.rstrip("\r\n") for line in sys.stdin.readlines() if line.strip()]
            count = write(Path(argv[1]), values)
            print(f"ICAP clients: {count} address(es) written (mode 0600); no value was printed")
            return 0
        if len(argv) == 2 and argv[0] == "--check":
            values = load(Path(argv[1]))
            if values is None:
                print("ICAP clients: no file", file=sys.stderr)
                return 1
            print(f"ICAP clients: {len(values)} address(es) valid; no value was printed")
            return 0
    except (Error, OSError) as e:
        print(f"refused: {e if isinstance(e, Error) else type(e).__name__}", file=sys.stderr)
        return 1
    print(__doc__.split("Usage", 1)[1], file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
