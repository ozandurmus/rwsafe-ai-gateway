#!/usr/bin/env python3
"""Self-test of the repository privacy gate (SR-PRIV-13 "gate self-test in CI"; PR 4 review D-01, D-02).

Plants synthetic findings in a temporary repository and proves that every rule fires, that the safe shapes pass, and that
the gate never prints a matched value. Every identifier-shaped value is built at runtime (AGENTS.md 4.5), so this file
itself passes the gate and gitleaks. Standard library only.

Usage: python3 tools/privacy/test_repository_privacy_check.py    (exit 0 when every case passes)
"""
from __future__ import annotations

import contextlib
import datetime as dt
import io
import json
import random
import string
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import repository_privacy_check as gate  # noqa: E402

_RNG = random.Random(20261030)


def _alnum(n: int) -> str:
    return "".join(_RNG.choice(string.ascii_letters + string.digits) for _ in range(n))


def _ip(*octets: int) -> str:
    return ".".join(str(o) for o in octets)


def _tckn() -> str:
    """A random 11-digit value with a valid TCKN checksum."""
    d = [_RNG.randint(1, 9)] + [_RNG.randint(0, 9) for _ in range(8)]
    d.append(((d[0] + d[2] + d[4] + d[6] + d[8]) * 7 - (d[1] + d[3] + d[5] + d[7])) % 10)
    d.append(sum(d) % 10)
    value = "".join(map(str, d))
    assert gate.tckn_valid(value)
    return value


def _tr_iban() -> str:
    """A random 26-character TR IBAN with valid ISO 7064 check digits."""
    bban = "".join(str(_RNG.randint(0, 9)) for _ in range(5)) + "0" + "".join(str(_RNG.randint(0, 9)) for _ in range(16))
    numeric = "".join(str(int(ch, 36)) for ch in bban + "TR00")
    value = "TR" + f"{98 - int(numeric) % 97:02d}" + bban
    assert gate.iban_valid(value)
    return value


def _tr_mobile() -> str:
    return "0" + "5" + "32" + " " + "418" + " " + "27" + " " + "93"


def _date(days: int) -> str:
    return (dt.date.today() + dt.timedelta(days=days)).isoformat()


class GateSelfTest(unittest.TestCase):

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write(self, rel: str, content: str | bytes) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")

    def rules(self) -> set[tuple[str, str]]:
        return {(f.rule, f.path) for f in gate.scan(self.root)[1]}

    def assert_finding(self, rule: str, path: str) -> None:
        self.assertIn((rule, path), self.rules(), f"{rule} did not fire on {path}")

    def assert_clean(self) -> None:
        self.assertEqual(set(), self.rules())

    # Content rules: each planted value fires its rule.

    def test_content_rules_fire(self) -> None:
        planted = {
            "PRIVATE_KEY_MATERIAL": "-----BEGIN " + "PRIVATE KEY-----",
            "EMAIL_ADDRESS": "operator" + "@" + "bank-mail" + ".com.tr",
            "INTERNAL_HOST_NAME": "fw01" + ".corp",
            "ANTHROPIC_KEY_SHAPE": "sk-" + "ant-" + _alnum(32),
            "OPENAI_KEY_SHAPE": "sk-" + "proj-" + _alnum(32),
            "GOOGLE_KEY_SHAPE": "AI" + "za" + _alnum(35),
            "GITHUB_TOKEN_SHAPE": "gh" + "p_" + _alnum(36),
            "CREDENTIAL_LITERAL": "password" + ' = "' + _alnum(12) + '"',
            "TR_IBAN": _tr_iban(),
            "TCKN_WITH_VALID_CHECKSUM": _tckn(),
            "TR_MOBILE_NUMBER": _tr_mobile(),
        }
        for rule, value in planted.items():
            with self.subTest(rule=rule):
                self.write("docs/planted.md", f"line one\nvalue {value} here\n")
                self.assert_finding(rule, "docs/planted.md")

    def test_private_public_and_link_local_addresses_fire(self) -> None:
        for address in (_ip(10, 20, 30, 40), _ip(172, 16, 9, 9), _ip(192, 168, 1, 1), _ip(169, 254, 3, 3),
                        _ip(8, 8, 4, 4)):
            with self.subTest(address=address):
                self.write("docs/planted.md", f"upstream {address}\n")
                self.assert_finding("NON_DOCUMENTATION_IPV4", "docs/planted.md")

    def test_test_fixtures_get_no_exemption(self) -> None:
        """D-01: a fixture path neither hides a private address nor a phone number."""
        for rel in ("java/dataplane/src/test/java/Fixture.java", "tests/fixtures/sample.json", "fixtures/sample.yaml"):
            with self.subTest(path=rel):
                self.write(rel, f"addr {_ip(10, 1, 2, 3)}\n")
                self.assert_finding("NON_DOCUMENTATION_IPV4", rel)
                self.write(rel, f"phone {_tr_mobile()}\n")
                self.assert_finding("TR_MOBILE_NUMBER", rel)

    def test_unmarked_prompt_fixture_fires(self) -> None:
        self.write("java/x/src/test/resources/fixtures/req.json", '{"messages' + '": [{"role": "user"}]}\n')
        self.assert_finding("PROMPT_FIXTURE_NOT_MARKED_SYNTHETIC", "java/x/src/test/resources/fixtures/req.json")

    # Safe shapes pass.

    def test_safe_shapes_pass(self) -> None:
        self.write("docs/safe.md", "\n".join([
            f"documentation {_ip(192, 0, 2, 10)} {_ip(198, 51, 100, 7)} {_ip(203, 0, 113, 9)}",
            f"masked {_ip(240, 1, 2, 3)} loopback {_ip(127, 0, 0, 1)} unspecified {_ip(0, 0, 0, 0)}",
            "phone 05xx xxx xx xx",
            "mail someone" + "@" + "example.invalid",
            "service api.rwsafe.svc.cluster.local and the placeholder zone nexus.local",
            "key sk-" + "ant-synthetic-" + "0" * 24,
            "password" + ' = "' + "synthetic-password" + '"',
            "host <masked-host>.corp",
        ]) + "\n")
        self.write("java/x/src/test/resources/fixtures/req.json", '{"messages' + '": [], "note": "synthetic"}\n')
        self.assert_clean()

    # File coverage: extensionless files, dotfiles, binaries, the gate's own source, forbidden artifacts.

    def test_extensionless_and_dot_files_are_scanned(self) -> None:
        for rel in ("java/gradlew", ".githooks/pre-commit", "Containerfile", ".gitattributes", "java/x/gradle.lockfile"):
            with self.subTest(path=rel):
                self.write(rel, f"# {_ip(10, 9, 8, 7)}\n")
                self.assert_finding("NON_DOCUMENTATION_IPV4", rel)
                (self.root / rel).unlink()

    def test_binary_files_are_skipped_and_undecodable_text_fails(self) -> None:
        self.write("java/gradle/wrapper/blob", b"\x00\x01" + _ip(10, 9, 8, 7).encode())
        self.assert_clean()
        self.write("docs/latin1.md", "café".encode("latin-1"))
        self.assert_finding("UNREADABLE_TEXT_CANDIDATE", "docs/latin1.md")

    def test_the_gate_scans_its_own_source(self) -> None:
        self.write("tools/privacy/repository_privacy_check.py", f"# {_ip(10, 9, 8, 7)}\n")
        self.assert_finding("NON_DOCUMENTATION_IPV4", "tools/privacy/repository_privacy_check.py")

    def test_forbidden_files_and_directories_fire(self) -> None:
        self.write(".env", "X=1\n")
        self.write("certs/server.pem", "x\n")
        self.write("logs/today.txt", "x\n")
        found = self.rules()
        self.assertIn(("LOCAL_CONFIGURATION", ".env"), found)
        self.assertIn(("PRIVATE_OR_TRUST_MATERIAL", "certs/server.pem"), found)
        self.assertIn(("RUNTIME_DIRECTORY_PRESENT", "logs"), found)

    # The gate's own allowlist.

    def _allowlist(self, **entry: str) -> None:
        base = {"rule": "NON_DOCUMENTATION_IPV4", "path": "docs/planted.md", "reason": "self-test",
                "owner": "self-test", "review_date": _date(30)}
        base.update(entry)
        self.write(gate.ALLOWLIST_FILE, json.dumps({"entries": [base]}))

    def test_allowlist_suppresses_only_while_complete_and_current(self) -> None:
        self.write("docs/planted.md", f"addr {_ip(10, 1, 1, 1)}\n")
        self._allowlist()
        self.assert_clean()
        self._allowlist(review_date=_date(-1))
        self.assertEqual({("ALLOWLIST_ENTRY_EXPIRED", gate.ALLOWLIST_FILE),
                          ("NON_DOCUMENTATION_IPV4", "docs/planted.md")}, self.rules())
        self._allowlist(owner="")
        self.assertIn(("ALLOWLIST_ENTRY_INCOMPLETE", gate.ALLOWLIST_FILE), self.rules())
        self.write(gate.ALLOWLIST_FILE, "{not json")
        self.assertIn(("ALLOWLIST_MALFORMED", gate.ALLOWLIST_FILE), self.rules())

    # .gitleaks.toml allowlists (D-02 (1)).

    def _gitleaks(self, body: str) -> None:
        self.write(gate.GITLEAKS_CONFIG, "[extend]\nuseDefault = true\n\n" + body)

    def test_gitleaks_allowlists_need_owner_and_current_review_date(self) -> None:
        cases = {
            f'[[allowlists]]\ndescription = "owner: architect; review: {_date(30)}; fixtures"\n': None,
            '[[allowlists]]\ndescription = "fixtures without an owner"\n': "GITLEAKS_ALLOWLIST_INCOMPLETE",
            '[[allowlists]]\ndescription = "owner: architect; fixtures"\n': "GITLEAKS_ALLOWLIST_INCOMPLETE",
            '[[allowlists]]\nregexes = ["^x$"]\n': "GITLEAKS_ALLOWLIST_INCOMPLETE",
            f'[[allowlists]]\ndescription = "owner: architect; review: {_date(-1)}"\n': "GITLEAKS_ALLOWLIST_EXPIRED",
            '[allowlist]\ndescription = "old single-table syntax"\n': "GITLEAKS_ALLOWLIST_INCOMPLETE",
            '[[rules]]\nid = "r"\nregex = "x"\n[[rules.allowlists]]\ndescription = "per rule"\n':
                "GITLEAKS_ALLOWLIST_INCOMPLETE",
            '[[rules]]\nid = "r"\nregex = "x"\n[rules.allowlist]\ndescription = "per rule, old syntax"\n':
                "GITLEAKS_ALLOWLIST_INCOMPLETE",
            "[[allowlists]\nbroken": "GITLEAKS_CONFIG_MALFORMED",
        }
        for body, rule in cases.items():
            with self.subTest(body=body):
                self._gitleaks(body)
                found = {r for r, p in self.rules() if p == gate.GITLEAKS_CONFIG}
                self.assertEqual(set() if rule is None else {rule}, found)

    # Output discipline.

    def test_gate_prints_rule_and_location_never_the_value(self) -> None:
        value = _tckn()
        self.write("docs/planted.md", f"id {value}\n")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = gate.main(["gate", str(self.root)])
        self.assertEqual(1, code)
        self.assertIn("TCKN_WITH_VALID_CHECKSUM", out.getvalue())
        self.assertIn("docs/planted.md:1", out.getvalue())
        self.assertNotIn(value, out.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
