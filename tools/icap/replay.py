#!/usr/bin/env python3
"""Replays synthetic sample traffic against a running rwsafe ICAP engine and prints one line per scenario.

Every prompt is synthetic. Identifiers with valid checksums and secret-shaped values are generated at runtime and never
written to disk (AGENTS.md 4.5). Fixtures: java/dataplane/src/test/resources/fixtures/icap/.

Usage:
    ./java/gradlew -p java :dataplane:runIcap          # terminal 1
    python3 tools/icap/replay.py [--host 127.0.0.1] [--port 1344] [--rounds 1]
"""
from __future__ import annotations

import argparse
import random
import socket
import sys
from pathlib import Path

FIXTURES = Path(__file__).resolve().parents[2] / "java/dataplane/src/test/resources/fixtures/icap"


def tckn(rng: random.Random) -> str:
    d = [rng.randint(1, 9)] + [rng.randint(0, 9) for _ in range(8)]
    d.append(((d[0] + d[2] + d[4] + d[6] + d[8]) * 7 - (d[1] + d[3] + d[5] + d[7])) % 10)
    d.append(sum(d) % 10)
    return "".join(map(str, d))


def iban(rng: random.Random) -> str:
    bban = "".join(str(rng.randint(0, 9)) for _ in range(22))
    check = 98 - int(bban + "292700") % 97
    return "T" + "R" + f"{check:02d}" + bban


def aws_key() -> str:
    return "AK" + "IA" + "SYNTHETIC" + "0000000"


SCENARIOS = [
    ("openai/web/chat.http", "clean chat", lambda r: "synthetic: write a haiku about release notes", -1),
    ("claude/api/messages.http", "customer TCKN", lambda r: f"synthetic: customer {tckn(r)} asks about card fees", -1),
    ("copilot/ide/chat.http", "IBAN in code", lambda r: f"synthetic: refactor transfer to {iban(r)} into a constant", -1),
    ("gemini/api/generate.http", "cloud key", lambda r: f"synthetic: why does {aws_key()} fail to deploy", -1),
    ("openai/web/chat.http", "key after preview", lambda r: "synthetic filler " * 300 + aws_key(), 4096),
    ("claude/api/messages.http", "clean in preview", lambda r: "synthetic: hello", 4096),
]


def build_http(fixture: str, prompt: str) -> tuple[bytes, bytes]:
    text = (FIXTURES / fixture).read_text(encoding="utf-8")
    head, body = text.split("\n\n", 1)
    escaped = prompt.replace("\\", "\\\\").replace('"', '\\"')
    body_bytes = body.rstrip().replace("{{PROMPT}}", escaped).encode("utf-8")
    head = head.replace("{{LEN}}", str(len(body_bytes)))
    return (head.replace("\n", "\r\n") + "\r\n\r\n").encode("latin-1"), body_bytes


def chunk(data: bytes) -> bytes:
    return f"{len(data):x}\r\n".encode() + data + b"\r\n" if data else b""


def reqmod_frame(head: bytes, body: bytes, preview: int) -> tuple[bytes, bytes]:
    icap = (f"REQMOD icap://icap.example.invalid/reqmod-ai ICAP/1.0\r\nHost: icap.example.invalid\r\n"
            f"Encapsulated: req-hdr=0, req-body={len(head)}\r\nAllow: 204\r\nX-Client-IP: 192.0.2.10\r\n"
            f"X-Authenticated-User: U1lOVEhFVElDXGRlbW8=\r\n")
    if preview < 0:
        return (icap + "\r\n").encode() + head + chunk(body) + b"0\r\n\r\n", b""
    icap += f"Preview: {preview}\r\n\r\n"
    first = body[:preview]
    if len(body) <= preview:
        return icap.encode() + head + chunk(first) + b"0; ieof\r\n\r\n", b""
    return icap.encode() + head + chunk(first) + b"0\r\n\r\n", chunk(body[preview:]) + b"0\r\n\r\n"


class Reader:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = b""

    def _fill(self) -> None:
        data = self.sock.recv(65536)
        if not data:
            raise ConnectionError("engine closed the connection")
        self.buf += data

    def until(self, marker: bytes) -> bytes:
        while marker not in self.buf:
            self._fill()
        i = self.buf.index(marker) + len(marker)
        out, self.buf = self.buf[:i], self.buf[i:]
        return out

    def exactly(self, n: int) -> bytes:
        while len(self.buf) < n:
            self._fill()
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def response(self) -> tuple[int, str, bytes]:
        head = self.until(b"\r\n\r\n").decode("latin-1")
        status = int(head[9:12])
        enc = next((l.split(":", 1)[1].strip() for l in head.split("\r\n") if l.lower().startswith("encapsulated:")), "")
        if status == 100 or not enc or enc.startswith("null-body"):
            return status, "", b""
        last = enc.split(",")[-1].strip()
        http = self.exactly(int(last.split("=")[1])).decode("latin-1")
        body = b""
        if not last.startswith("null-body"):
            while True:
                size = int(self.until(b"\r\n")[:-2].split(b";")[0], 16)
                if size == 0:
                    self.until(b"\r\n")
                    break
                body += self.exactly(size)
                self.until(b"\r\n")
        return status, http, body


def run(host: str, port: int, rounds: int) -> int:
    rng = random.Random(2026)
    print(f"{'scenario':<20} {'icap':>4}  {'http':<8} {'reason':<14} outcome")
    for _ in range(rounds):
        for fixture, name, prompt_of, preview in SCENARIOS:
            head, body = build_http(fixture, prompt_of(rng))
            first, rest = reqmod_frame(head, body, preview)
            with socket.create_connection((host, port), timeout=10) as s:
                r = Reader(s)
                s.sendall(first)
                status, http, out = r.response()
                if status == 100:
                    s.sendall(rest)
                    status, http, out = r.response()
            http_status = http.split(" ")[1] if http.startswith("HTTP/") else "-"
            reason = next((l.split(":", 1)[1].strip() for l in http.split("\r\n")
                           if l.lower().startswith("x-rwsafe-reason:")), "-")
            if status == 204:
                outcome = "allowed unchanged"
            elif http_status == "403":
                outcome = "blocked"
            elif b"[REDACTED:" in out:
                outcome = "redacted: " + ", ".join(sorted({t.decode() for t in __import__("re").findall(rb"\[REDACTED:[A-Z]+\]", out)}))
            else:
                outcome = "modified"
            print(f"{fixture.split('/')[0] + ' ' + name:<20} {status:>4}  {http_status:<8} {reason:<14} {outcome}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=1344)
    ap.add_argument("--rounds", type=int, default=1)
    a = ap.parse_args()
    return run(a.host, a.port, a.rounds)


if __name__ == "__main__":
    sys.exit(main())
