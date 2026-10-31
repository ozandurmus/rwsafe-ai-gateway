"""Tests of the local trial (standard library only).

    python3 -m unittest discover -s tools/trial -p 'test_*.py'

RealEngineTest starts the real ICAP engine (built-in development snapshot, free loopback ports) from the classpath the
trial's Gradle init script writes, then drives trial_proxy and mock_ai in this process: the allow, redact and block paths.
It is skipped when Gradle cannot produce the classpath (TRIAL_GRADLE_OFFLINE=0 lets Gradle download). The other tests
need nothing but Python: the loopback-only guard and the fail-closed answers to an engine error or an unreachable engine.
Every identifier-shaped value is generated at runtime.
"""
from __future__ import annotations

import json
import os
import random
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

import mock_ai  # noqa: E402
import trial_proxy  # noqa: E402
from trial_proxy import LoopbackOnly, Trial, TrialServer, require_loopback  # noqa: E402

RNG = random.Random(4242)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def serve(server) -> threading.Thread:
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return t


def post(port: int, payload, headers: dict | None = None) -> tuple[int, dict]:
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/send", data=json.dumps(payload).encode("utf-8"),
                                 headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


class Stack:
    """mock_ai and trial_proxy in this process, pointed at an ICAP port."""

    def __init__(self, icap_port: int):
        self.mock = mock_ai.MockAi(0)
        serve(self.mock)
        trial = Trial("127.0.0.1", icap_port, "127.0.0.1", self.mock.port, "SYNTHETIC\\unit-test")
        self.proxy = TrialServer(0, trial, trial_proxy.examples(RNG))
        serve(self.proxy)

    def received(self) -> list[str]:
        with self.mock.lock:
            return list(self.mock.received)

    def close(self) -> None:
        for s in (self.proxy, self.mock):
            s.shutdown()
            s.server_close()


class LoopbackGuardTest(unittest.TestCase):

    def test_only_the_literal_loopback_address_passes(self):
        self.assertEqual("127.0.0.1", require_loopback("127.0.0.1"))
        for host in ("192.0.2.10", "localhost", "0.0.0.0", "::1", "127.0.0.2", "api.openai.com", ""):
            with self.assertRaises(LoopbackOnly, msg=host):
                require_loopback(host)

    def test_trial_refuses_a_non_loopback_engine_or_provider(self):
        with self.assertRaises(LoopbackOnly):
            Trial("192.0.2.10", 1344, "127.0.0.1", 9, "SYNTHETIC\\unit-test")
        with self.assertRaises(LoopbackOnly):
            Trial("127.0.0.1", 1344, "198.51.100.7", 9, "SYNTHETIC\\unit-test")

    def test_forwarding_rechecks_the_provider_address(self):
        trial = Trial("127.0.0.1", 1344, "127.0.0.1", 9, "SYNTHETIC\\unit-test")
        trial.mock_host = "203.0.113.5"
        with self.assertRaises(LoopbackOnly):
            trial.forward(b"{}")
        with self.assertRaises(LoopbackOnly):
            trial_proxy.reqmod("203.0.113.5", 1344, "SYNTHETIC\\unit-test", b"", b"")

    def test_the_api_answers_only_its_own_page(self):
        stack = Stack(free_port())
        try:
            port = stack.proxy.port
            status, _ = post(port, {"prompt": "merhaba"}, {"Origin": "http://evil.example"})
            self.assertEqual(403, status)
            status, _ = post(port, {"prompt": "merhaba"}, {"Host": "rebound.example:" + str(port)})
            self.assertEqual(403, status)
            self.assertEqual([], stack.received())
        finally:
            stack.close()


class FakeEngine:
    """An ICAP listener that answers every request with one fixed response."""

    def __init__(self, answer: bytes):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.port = self.sock.getsockname()[1]
        self.answer = answer
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                data = b""
                while not data.endswith(b"0\r\n\r\n"):
                    part = conn.recv(65536)
                    if not part:
                        break
                    data += part
                conn.sendall(self.answer)

    def close(self) -> None:
        self.sock.close()


class FailClosedTest(unittest.TestCase):

    def test_an_engine_error_forwards_nothing(self):
        engine = FakeEngine(b"ICAP/1.0 500 Server Error\r\nISTag: \"t\"\r\nEncapsulated: null-body=0\r\n\r\n")
        stack = Stack(engine.port)
        try:
            status, r = post(stack.proxy.port, {"prompt": "merhaba"})
            self.assertEqual(200, status)
            self.assertEqual("error", r["decision"]["kind"])
            self.assertFalse(r["provider"]["reached"])
            self.assertEqual([], stack.received())
        finally:
            stack.close()
            engine.close()

    def test_an_unreachable_engine_forwards_nothing(self):
        stack = Stack(free_port())
        try:
            _, r = post(stack.proxy.port, {"prompt": "merhaba"})
            self.assertEqual("error", r["decision"]["kind"])
            self.assertEqual([], stack.received())
        finally:
            stack.close()


class RealEngineTest(unittest.TestCase):
    engine: subprocess.Popen | None = None

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="rwsafe-trial-test-")
        out = Path(cls.tmp.name)
        offline = [] if os.environ.get("TRIAL_GRADLE_OFFLINE") == "0" else ["--offline"]
        build = subprocess.run(
            [str(ROOT / "java/gradlew"), "-p", str(ROOT / "java"), *offline, "-q",
             "-I", str(HERE / "classpath.init.gradle"), f"-PtrialOut={out}", ":dataplane:trialClasspath"],
            capture_output=True, text=True, timeout=280)
        if build.returncode != 0 or not (out / "dataplane.classpath").is_file():
            cls.tmp.cleanup()
            raise unittest.SkipTest("the engine classpath could not be built: " + build.stderr[-400:])
        icap, metrics = free_port(), free_port()
        env = dict(os.environ, RWSAFE_ICAP_BIND="127.0.0.1", RWSAFE_ICAP_PORT=str(icap),
                   RWSAFE_METRICS_PORT=str(metrics))
        for name in ("RWSAFE_SNAPSHOT_URL", "RWSAFE_CONTROL_EVENTS_URL", "RWSAFE_SPOOL_DIR", "RWSAFE_CAPTURE_MODE"):
            env.pop(name, None)
        cls.log = open(out / "engine.log", "wb")
        cls.engine = subprocess.Popen(
            [(out / "dataplane.java").read_text().strip(), "-cp", (out / "dataplane.classpath").read_text().strip(),
             "io.rwsafe.dataplane.boot.DataPlaneApplication"],
            cwd=ROOT / "java/dataplane", env=env, stdout=cls.log, stderr=subprocess.STDOUT)
        deadline = time.time() + 90
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{metrics}/ready", timeout=2) as r:
                    if r.status == 200:
                        break
            except OSError:
                pass
            if cls.engine.poll() is not None:
                break
            time.sleep(0.5)
        else:
            cls.tearDownClass()
            raise AssertionError("the engine was not ready within 90 s")
        if cls.engine.poll() is not None:
            cls.tearDownClass()
            raise AssertionError("the engine exited at start")
        cls.stack = Stack(icap)

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "stack", None):
            cls.stack.close()
        if cls.engine and cls.engine.poll() is None:
            cls.engine.terminate()
            try:
                cls.engine.wait(45)
            except subprocess.TimeoutExpired:
                cls.engine.kill()
                cls.engine.wait()
        cls.log.close()
        cls.tmp.cleanup()

    def send(self, prompt: str, browser: bool = False) -> tuple[dict, list[str]]:
        before = len(self.stack.received())
        status, r = post(self.stack.proxy.port, {"prompt": prompt, "browser": browser})
        self.assertEqual(200, status)
        return r, self.stack.received()[before:]

    def test_a_plain_question_is_allowed_unchanged(self):
        prompt = "Merhaba, bana bahar üzerine kısa bir şiir yazar mısın?"
        r, reached = self.send(prompt)
        self.assertEqual("allow", r["decision"]["kind"])
        self.assertEqual(204, r["decision"]["icapStatus"])
        self.assertEqual([r["request"]["body"]], reached)
        self.assertEqual(mock_ai.REPLY_PREFIX + prompt, r["provider"]["reply"])

    def test_an_identity_number_is_masked_before_the_provider(self):
        value = trial_proxy.synthetic_tckn(RNG)
        r, reached = self.send(f"Müşterimiz {value} kimlik numarasıyla kart ücretlerini soruyor.")
        self.assertEqual("masked", r["decision"]["kind"])
        self.assertIn("TCKN", r["decision"]["classes"])
        self.assertEqual(1, len(reached))
        self.assertNotIn(value, reached[0])
        self.assertIn("[REDACTED:TCKN]", reached[0])
        self.assertEqual(mock_ai.REPLY_PREFIX + "Müşterimiz [REDACTED:TCKN] kimlik numarasıyla kart ücretlerini soruyor.",
                         r["provider"]["reply"])

    def test_a_secret_shaped_key_is_blocked_and_nothing_reaches_the_provider(self):
        key = trial_proxy.synthetic_cloud_key(RNG)
        for browser, content_type in ((False, "application/json"), (True, "text/html")):
            r, reached = self.send(f"Bu erişim anahtarıyla dağıtım neden başarısız oluyor: {key}", browser)
            self.assertEqual("blocked", r["decision"]["kind"])
            self.assertEqual("secret", r["decision"]["reason"])
            self.assertTrue(r["decision"]["ref"])
            self.assertEqual([], reached)
            self.assertFalse(r["provider"]["reached"])
            self.assertEqual(403, r["blockPage"]["httpStatus"])
            self.assertTrue(r["blockPage"]["contentType"].startswith(content_type))
            self.assertNotIn(key, r["blockPage"]["body"])


if __name__ == "__main__":
    unittest.main()
