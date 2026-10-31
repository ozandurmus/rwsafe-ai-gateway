#!/usr/bin/env python3
"""A fake AI provider for the local trial: answers an OpenAI-shaped chat completion with what it received.

It listens on 127.0.0.1 only and contacts nothing. The reply's message is "Sağlayıcıya ulaşan metin: <the user message
exactly as it arrived>", so the trial page shows what a real provider would have read after the ICAP engine decided.

Routes:
    POST /v1/chat/completions   the chat API (OpenAI chat completions request and response shape)
    GET  /healthz               200 "ok"
    GET  /received              the last bodies received, newest last (the tests read it; loopback only)

Usage:
    python3 tools/trial/mock_ai.py [--port 0] [--port-file PATH]
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

LOOPBACK = "127.0.0.1"
REPLY_PREFIX = "Sağlayıcıya ulaşan metin: "
MAX_BODY = 1 << 20
KEEP = 50


def user_text(request: dict) -> str:
    """The last user message of a chat completion request, its text parts joined."""
    for message in reversed(request.get("messages") or []):
        if isinstance(message, dict) and message.get("role") == "user":
            content = message.get("content")
            if isinstance(content, str):
                return content
            if isinstance(content, list):
                return "".join(p.get("text", "") for p in content if isinstance(p, dict))
    return ""


class MockAi(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port: int = 0):
        super().__init__((LOOPBACK, port), Handler)
        self.received: deque[str] = deque(maxlen=KEEP)
        self.lock = threading.Lock()
        self.count = 0

    @property
    def port(self) -> int:
        return self.server_address[1]


class Handler(BaseHTTPRequestHandler):
    server: MockAi
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        # Method, path and status only; a body never reaches the log.
        sys.stderr.write("mock_ai: %s\n" % (fmt % args))

    def _send(self, status: int, body: bytes, content_type: str = "application/json; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, value) -> None:
        self._send(status, json.dumps(value, ensure_ascii=False).encode("utf-8"))

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._send(200, b"ok", "text/plain; charset=utf-8")
        elif self.path == "/received":
            with self.server.lock:
                self._json(200, list(self.server.received))
        else:
            self._json(404, {"error": {"message": "not found"}})

    def do_POST(self) -> None:
        if self.path != "/v1/chat/completions":
            self._json(404, {"error": {"message": "not found"}})
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length < 0 or length > MAX_BODY:
            self._json(413, {"error": {"message": "body too large"}})
            return
        raw = self.rfile.read(length).decode("utf-8", "replace")
        with self.server.lock:
            self.server.received.append(raw)
            self.server.count += 1
            n = self.server.count
        try:
            request = json.loads(raw)
        except ValueError:
            self._json(400, {"error": {"message": "the body is not JSON"}})
            return
        text = user_text(request) if isinstance(request, dict) else ""
        self._json(200, {
            "id": f"chatcmpl-trial-{n}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": request.get("model", "unknown") if isinstance(request, dict) else "unknown",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": REPLY_PREFIX + text},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        })


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, default=0, help="0 lets the system pick a free port")
    ap.add_argument("--port-file", type=Path, help="writes the chosen port here once listening")
    a = ap.parse_args()
    server = MockAi(a.port)
    if a.port_file:
        a.port_file.write_text(str(server.port), encoding="ascii")
    sys.stderr.write(f"mock_ai: listening on {LOOPBACK}:{server.port}\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
