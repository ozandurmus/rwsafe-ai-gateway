#!/usr/bin/env python3
"""Self-test of the repository privacy gate (SR-PRIV-13 "gate self-test in CI"; PR 4 review D-01, D-02; PR 6 review).

Plants synthetic findings in temporary repositories and proves that every rule fires, that exemptions apply to the matched
value and never to its line, that the safe shapes pass, that the allowlists are exact and expire, and that the gate never
prints a matched value. Every identifier-shaped value is built at runtime (AGENTS.md 4.5), so this file itself passes the
gate and gitleaks. Standard library and the git CLI only.

Usage: python3 -B tools/privacy/test_repository_privacy_check.py    (exit 0 when every case passes)
"""
from __future__ import annotations

import contextlib
import datetime as dt
import io
import json
import random
import re
import string
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import repository_privacy_check as gate  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
_RNG = random.Random(20261030)
BS = "\\"   # one backslash


def _alnum(n: int) -> str:
    return "".join(_RNG.choice(string.ascii_letters + string.digits) for _ in range(n))


def _ip(*octets: int) -> str:
    return ".".join(str(o) for o in octets)


def _ip6(*groups: str) -> str:
    return ":".join(groups)


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


def _broken_checksum(value: str) -> str:
    return value[:-1] + str((int(value[-1]) + 1) % 10)


def _tr_mobile(spaced: bool = True) -> str:
    groups = ["0" + "5" + "32", "418", "27", "93"]
    return " ".join(groups) if spaced else "".join(groups)


def _date(days: int) -> str:
    return (dt.date.today() + dt.timedelta(days=days)).isoformat()


class GateTestCase(unittest.TestCase):

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write(self, rel: str, content: str | bytes, root: Path | None = None) -> None:
        path = (root or self.root) / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")

    def rules(self, policy_root: Path | None = None) -> set[tuple[str, str]]:
        return {(f.rule, f.path) for f in gate.scan(self.root, policy_root)[1]}

    def assert_finding(self, rule: str, path: str) -> None:
        self.assertIn((rule, path), self.rules(), f"{rule} did not fire on {path}")

    def assert_line_fires(self, rule: str, line: str, path: str = "docs/planted.md") -> None:
        self.write(path, f"first line\n{line}\n")
        self.assertIn((rule, path), self.rules(), f"{rule} did not fire")
        (self.root / path).unlink()

    def assert_line_clean(self, line: str, path: str = "docs/safe.md") -> None:
        self.write(path, f"first line\n{line}\n")
        self.assertEqual(set(), self.rules(), "a safe shape fired")
        (self.root / path).unlink()


class ContentRules(GateTestCase):

    def test_each_content_rule_fires(self) -> None:
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
            "GITLEAKS_BYPASS": "x = 1  # " + "gitleaks" + ":allow",
            "SERIAL_OR_ACCOUNT_LITERAL": "serial_number" + ' = "' + "FGT" + _alnum(10) + '"',
            "LDAP_DISTINGUISHED_NAME": "CN=" + "jdoe" + ",OU=" + "Staff" + ",DC=" + "bankco" + ",DC=" + "tr",
            "DOMAIN_ACCOUNT": "log on as " + "BANKCO" + BS + "jdoe01",
        }
        for rule, value in planted.items():
            with self.subTest(rule=rule):
                self.assert_line_fires(rule, f"value {value} here")

    def test_rule_variants_fire(self) -> None:
        cases = [
            ("GITHUB_TOKEN_SHAPE", "github" + "_pat_" + _alnum(64)),
            ("INTERNAL_HOST_NAME", "fw01" + ".dc1" + ".corp"),
            ("INTERNAL_HOST_NAME", "printer01" + ".local"),
            ("TR_MOBILE_NUMBER", "0 (532) " + "418 27 93"),
            ("TR_MOBILE_NUMBER", _tr_mobile(spaced=False)),
            ("CREDENTIAL_LITERAL", "icap" + "_secret" + ' = "' + _alnum(20) + '"'),
            ("CREDENTIAL_LITERAL", '{"' + "api_key" + '": "' + _alnum(20) + '"}'),
            ("SERIAL_OR_ACCOUNT_LITERAL", "  " + "sAMAccountName" + ": " + "jdoe01"),
            ("SERIAL_OR_ACCOUNT_LITERAL", "- " + "serial" + ": " + "ABC" + _alnum(8)),
            ("SERIAL_OR_ACCOUNT_LITERAL", '"' + "userPrincipalName" + '": "' + "jdoe01" + '"'),
            ("LOCAL_HOME_PATH", "see file://" + "/Users/" + "jdoe01" + "/Codo/x/AGENTS.md"),
            ("LOCAL_HOME_PATH", "cd " + "/home/" + "jdoe01" + "/src"),
            ("LOCAL_HOME_PATH", "C:" + BS + "Users" + BS + "jdoe01" + BS + "x"),
        ]
        for rule, line in cases:
            with self.subTest(rule=rule, line=line[:12]):
                self.assert_line_fires(rule, line)

    def test_escaped_domain_account_in_source_code_fires(self) -> None:
        self.assert_line_fires("DOMAIN_ACCOUNT", 'String user = "' + "BANKCO" + BS + BS + "jdoe01" + '";',
                               path="java/x/src/main/java/A.java")

    def test_exemptions_apply_to_the_match_not_the_line(self) -> None:
        """PR 6 review D-02: a safe token elsewhere on the line hides nothing."""
        cases = [
            ("ANTHROPIC_KEY_SHAPE", "synthetic fixture next to sk-" + "ant-" + _alnum(32)),
            ("EMAIL_ADDRESS", "a" + "@" + "example.invalid and " + "b" + "@" + "bank-mail.com.tr"),
            ("EMAIL_ADDRESS", "x" + "@" + "example.invalid.bank-mail.com.tr"),
            ("CREDENTIAL_LITERAL", "password" + ' = "' + "test" + '", ' + "secret" + ' = "' + _alnum(16) + '"'),
            ("TR_MOBILE_NUMBER", "masked 05xx xxx xx xx, real " + _tr_mobile()),
            ("NON_DOCUMENTATION_IPV4", f"{_ip(192, 0, 2, 1)} then {_ip(10, 0, 0, 7)}"),
            ("INTERNAL_HOST_NAME", "api.rwsafe.svc.cluster.local and " + "db01" + ".corp"),
        ]
        for rule, line in cases:
            with self.subTest(rule=rule):
                self.assert_line_fires(rule, line)

    def test_addresses_outside_the_safe_ranges_fire(self) -> None:
        for address in (_ip(10, 20, 30, 40), _ip(172, 16, 9, 9), _ip(192, 168, 1, 1), _ip(169, 254, 3, 3),
                        _ip(8, 8, 4, 4), _ip(100, 64, 1, 1)):
            with self.subTest(address=address):
                self.assert_line_fires("NON_DOCUMENTATION_IPV4", f"upstream {address}")
        for address in (_ip6("2a0b", "7c40", "1", "0", "0", "0", "0", "9"), _ip6("fe80", "", "1"),
                        _ip6("fd12", "3456", "", "1")):
            with self.subTest(address=address):
                self.assert_line_fires("NON_DOCUMENTATION_IPV6", f"upstream {address} here")

    def test_test_fixtures_get_no_exemption(self) -> None:
        """PR 4 review D-01: a fixture path neither hides a private address nor a phone number."""
        for rel in ("java/dataplane/src/test/java/Fixture.java", "tests/fixtures/sample.json", "fixtures/sample.yaml"):
            with self.subTest(path=rel):
                self.assert_line_fires("NON_DOCUMENTATION_IPV4", f"addr {_ip(10, 1, 2, 3)}", path=rel)
                self.assert_line_fires("TR_MOBILE_NUMBER", f"phone {_tr_mobile()}", path=rel)

    def test_prompt_bodies_need_an_explicit_synthetic_marker_anywhere(self) -> None:
        for rel, body in (("java/x/src/test/resources/fixtures/req.json", '{"messages' + '": [{"role": "user"}]}'),
                          ("docs/api.md", '{"prompt' + '": "summarise the attached file"}'),
                          ("tools/sample.json", '{"input' + '": {"text": "hello"}}'),
                          ("docs/doc-range.md", f'{{"prompt' + f'": "hi"}} from {_ip(192, 0, 2, 5)}')):
            with self.subTest(path=rel):
                self.write(rel, body + "\n")
                self.assert_finding("PROMPT_FIXTURE_NOT_MARKED_SYNTHETIC", rel)
                (self.root / rel).unlink()

    def test_digit_runs_inside_a_digest_are_not_identifiers(self) -> None:
        tckn = _tckn()
        digest = ("ab" + tckn + "cd" + "0" * 64)[:64]
        self.assert_line_clean(f'<sha256 value="{digest}" origin="Generated by Gradle"/>')
        # The same number outside a digest, or inside a run too short to be one, still fires.
        self.assert_line_fires("TCKN_WITH_VALID_CHECKSUM", f'<sha256 value="{digest}"/> customer {tckn}')
        self.assert_line_fires("TCKN_WITH_VALID_CHECKSUM", f"id ab{tckn}cd")

    def test_safe_shapes_pass(self) -> None:
        self.assert_line_clean("\n".join([
            f"documentation {_ip(192, 0, 2, 10)} {_ip(198, 51, 100, 7)} {_ip(203, 0, 113, 9)}",
            f"masked {_ip(240, 1, 2, 3)} loopback {_ip(127, 0, 0, 1)} unspecified {_ip(0, 0, 0, 0)}",
            f"v6 {_ip6('2001', 'db8', '', '1')} {_ip6('3fff', '', '7')} {_ip6('', '', '1')} {_ip6('ff02', '', '1')} ::",
            "not addresses 12:30:45 aa:bb:cc:dd:ee:ff Foo::bar 1.2.3",
            "phone 05xx xxx xx xx",
            "mail someone" + "@" + "example.invalid and noreply" + "@" + "anthropic.com",
            "service api.rwsafe.svc.cluster.local, the placeholder zone nexus.local, <masked-host>.corp",
            "key sk-" + "ant-synthetic-" + "0" * 24,
            "password" + ' = "' + "synthetic-password" + '"',
            "serial" + ' = "' + "<masked-serial>" + '", ' + "account_name" + ' = "' + "USR-1a2b" + '"',
            "  " + "serial" + ": " + "FW-EDGE-01",
            "  " + "username" + ": " + "${RWSAFE_USER}",
            "String serialNumber = device.serial();",
            "paths /home/" + "runner/work, /Users/" + "<masked-user>/x, <workspace-root>/AGENTS.md, api/users/list",
            "CN=" + "<masked>" + ",OU=" + "<masked>" + " and DOMAIN" + BS + "user",
            f"invalid checksums {_broken_checksum(_tckn())} {_broken_checksum(_tr_iban())}",
        ]))
        self.assert_line_clean('String line = "' + "END" + BS + "nfoo" + '";', path="java/x/src/main/java/A.java")
        self.assert_line_clean("```mermaid\nA[store PVC" + BS + "nencrypted chunks]\n```")
        self.write("java/x/src/test/resources/fixtures/req.json", '{"messages' + '": [], "note": "synthetic"}\n')
        self.assertEqual(set(), self.rules())


class FileCoverage(GateTestCase):

    def test_extensionless_and_dot_files_are_scanned(self) -> None:
        for rel in ("java/gradlew", ".githooks/pre-commit", "Containerfile", ".gitattributes", "java/x/gradle.lockfile"):
            with self.subTest(path=rel):
                self.assert_line_fires("NON_DOCUMENTATION_IPV4", f"# {_ip(10, 9, 8, 7)}", path=rel)

    def test_binary_files_are_skipped_and_undecodable_text_fails(self) -> None:
        self.write("java/gradle/wrapper/blob", b"\x00\x01" + _ip(10, 9, 8, 7).encode())
        self.assertEqual(set(), self.rules())
        self.write("docs/latin1.md", "café".encode("latin-1"))
        self.assert_finding("UNREADABLE_TEXT_CANDIDATE", "docs/latin1.md")

    def test_the_gate_scans_its_own_source(self) -> None:
        self.assert_line_fires("NON_DOCUMENTATION_IPV4", f"# {_ip(10, 9, 8, 7)}",
                               path="tools/privacy/repository_privacy_check.py")

    def test_forbidden_names_and_suffixes_fire(self) -> None:
        expected = {
            ".env": "LOCAL_CONFIGURATION", "config/.env.prod": "LOCAL_CONFIGURATION",
            "known_hosts": "LOCAL_TRUST_MATERIAL", "docs/.DS_Store": "GENERATED_OR_OS_ARTIFACT",
            "img/Thumbs.db": "GENERATED_OR_OS_ARTIFACT", ".gitleaksignore": "GITLEAKS_BYPASS",
        }
        expected.update({f"artifacts/file{suffix}": rule for suffix, rule in gate.FORBIDDEN_SUFFIXES.items()})
        for rel in expected:
            self.write(rel, "x\n")
        self.write(".env.example", "X=\n")
        self.write("known_hosts.example", "x\n")
        found = self.rules()
        for rel, rule in expected.items():
            with self.subTest(path=rel):
                self.assertIn((rule, rel), found)
        self.assertFalse(any(p in (".env.example", "known_hosts.example") for _, p in found))

    def test_runtime_and_build_directories_fire_instead_of_being_skipped(self) -> None:
        """PR 6 review D-01 (1): content under a build or cache directory is reported, not silently skipped."""
        self.write("logs/today.txt", "x\n")
        for rel in ("java/build/report.txt", "node_modules/a.js", "java/target/x.txt", ".gradle/cache.txt",
                    "tools/__pycache__/m.txt", ".claude/worktrees/lane/a.md"):
            self.write(rel, "x\n")
        found = self.rules()
        self.assertIn(("RUNTIME_DIRECTORY_PRESENT", "logs"), found)
        for rel in ("java/build/report.txt", "node_modules/a.js", "java/target/x.txt", ".gradle/cache.txt",
                    "tools/__pycache__/m.txt", ".claude/worktrees/lane/a.md"):
            with self.subTest(path=rel):
                self.assertIn(("BUILD_OR_CACHE_DIRECTORY_CONTENT", rel), found)

    def test_git_checkout_scans_tracked_and_unignored_files_only(self) -> None:
        """PR 6 review D-01 (2): ignored local files do not fail the hook; a tracked file in an ignored directory does."""
        def git(*args: str) -> None:
            subprocess.run(["git", "-C", str(self.root), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                            *args], check=True, capture_output=True)
        git("init", "-q")
        self.write(".gitignore", "build/\nlocal.txt\n")
        self.write("local.txt", f"{_ip(10, 1, 1, 1)}\n")
        self.write("README.md", "clean\n")
        git("add", ".gitignore", "README.md")
        git("commit", "-q", "-m", "init")
        self.assertEqual(set(), self.rules())
        self.write("new.md", f"{_ip(10, 1, 1, 2)}\n")
        self.assertIn(("NON_DOCUMENTATION_IPV4", "new.md"), self.rules())
        (self.root / "new.md").unlink()
        self.write("build/forced.txt", "x\n")
        git("add", "-f", "build/forced.txt")
        self.assertIn(("BUILD_OR_CACHE_DIRECTORY_CONTENT", "build/forced.txt"), self.rules())


class Allowlists(GateTestCase):

    def _allowlist(self, root: Path | None = None, raw: str | None = None, **entry: str) -> None:
        base = {"rule": "NON_DOCUMENTATION_IPV4", "path": "docs/planted.md", "reason": "self-test",
                "owner": "self-test", "review_date": _date(30)}
        base.update(entry)
        self.write(gate.ALLOWLIST_FILE, raw if raw is not None else json.dumps({"entries": [base]}), root)

    def test_allowlist_suppresses_only_while_complete_and_current(self) -> None:
        self.write("docs/planted.md", f"addr {_ip(10, 1, 1, 1)}\n")
        self._allowlist()
        self.assertEqual(set(), self.rules())
        self._allowlist(review_date=_date(-1))
        self.assertEqual({("ALLOWLIST_ENTRY_EXPIRED", gate.ALLOWLIST_FILE),
                          ("NON_DOCUMENTATION_IPV4", "docs/planted.md")}, self.rules())
        for broken in ({"owner": ""}, {"owner": "   "}, {"reason": ""}):
            with self.subTest(entry=broken):
                self._allowlist(**broken)
                self.assertIn(("ALLOWLIST_ENTRY_INCOMPLETE", gate.ALLOWLIST_FILE), self.rules())
        for raw in ("{not json", "[]", '{"entries": {}}', '{"other": []}'):
            with self.subTest(raw=raw):
                self._allowlist(raw=raw)
                self.assertIn(("ALLOWLIST_MALFORMED", gate.ALLOWLIST_FILE), self.rules())

    def test_malformed_allowlist_keeps_the_gitleaks_findings(self) -> None:
        self._allowlist(raw="{not json")
        self.write(gate.GITLEAKS_CONFIG, "[extend]\nuseDefault = true\n[[allowlists]]\nregexes = ['^x$']\n")
        found = self.rules()
        self.assertIn(("ALLOWLIST_MALFORMED", gate.ALLOWLIST_FILE), found)
        self.assertIn(("GITLEAKS_ALLOWLIST_INCOMPLETE", gate.GITLEAKS_CONFIG), found)

    def test_policy_root_governs_instead_of_the_scanned_tree(self) -> None:
        """PR 6 review D-05 (1): an intermediate commit cannot allowlist its own identifier."""
        self.write("docs/planted.md", f"addr {_ip(10, 1, 1, 1)}\n")
        self._allowlist()
        with tempfile.TemporaryDirectory() as policy:
            self.assertIn(("NON_DOCUMENTATION_IPV4", "docs/planted.md"), self.rules(Path(policy)))

    def _gitleaks(self, body: str, extend: str = "[extend]\nuseDefault = true\n\n") -> set[str]:
        self.write(gate.GITLEAKS_CONFIG, extend + body)
        return {r for r, p in self.rules() if p == gate.GITLEAKS_CONFIG}

    def test_gitleaks_allowlists_are_owned_dated_and_exact(self) -> None:
        ok = f'description = "owner: architect; review: {_date(30)}; fixtures"\nregexes = ["^x$"]\n'
        cases = {
            "[[allowlists]]\n" + ok: set(),
            '[[allowlists]]\ndescription = "fixtures without an owner"\nregexes = ["^x$"]\n':
                {"GITLEAKS_ALLOWLIST_INCOMPLETE"},
            f'[[allowlists]]\ndescription = "owner:   ; review: {_date(30)}"\nregexes = ["^x$"]\n':
                {"GITLEAKS_ALLOWLIST_INCOMPLETE"},
            '[[allowlists]]\ndescription = "owner: architect; fixtures"\nregexes = ["^x$"]\n':
                {"GITLEAKS_ALLOWLIST_INCOMPLETE"},
            f'[[allowlists]]\ndescription = "owner: architect; review: {_date(-1)}"\nregexes = ["^x$"]\n':
                {"GITLEAKS_ALLOWLIST_EXPIRED"},
            '[allowlist]\ndescription = "old single-table syntax"\nregexes = ["^x$"]\n': {"GITLEAKS_ALLOWLIST_INCOMPLETE"},
            '[[rules]]\nid = "r"\nregex = "x"\n[[rules.allowlists]]\ndescription = "per rule"\nregexes = ["^x$"]\n':
                {"GITLEAKS_ALLOWLIST_INCOMPLETE"},
            '[[rules]]\nid = "r"\nregex = "x"\n[rules.allowlist]\ndescription = "per rule, old"\nregexes = ["^x$"]\n':
                {"GITLEAKS_ALLOWLIST_INCOMPLETE"},
            f'[[allowlists]]\ndescription = "owner: a; review: {_date(30)}"\nregexes = ["^sk-.*$"]\n':
                {"GITLEAKS_ALLOWLIST_NOT_EXACT"},
            f'[[allowlists]]\ndescription = "owner: a; review: {_date(30)}"\npaths = ["docs/"]\n':
                {"GITLEAKS_ALLOWLIST_NOT_EXACT"},
            f'[[allowlists]]\ndescription = "owner: a; review: {_date(30)}"\nstopwords = ["x"]\n':
                {"GITLEAKS_ALLOWLIST_NOT_EXACT"},
            f'[[allowlists]]\n{ok}commits = ["abc"]\n': {"GITLEAKS_ALLOWLIST_NOT_EXACT"},
            "[[allowlists]\nbroken": {"GITLEAKS_CONFIG_MALFORMED"},
        }
        for body, expected in cases.items():
            with self.subTest(body=body):
                self.assertEqual(expected, self._gitleaks(body))

    def test_gitleaks_rules_cannot_be_disabled_or_replaced(self) -> None:
        for extend in ("[extend]\nuseDefault = true\ndisabledRules = ['generic-api-key']\n",
                       "[extend]\nuseDefault = true\npath = 'other.toml'\n",
                       "[extend]\nuseDefault = false\n", ""):
            with self.subTest(extend=extend):
                self.assertEqual({"GITLEAKS_DEFAULT_RULES_NOT_EXTENDED_EXACTLY"}, self._gitleaks("", extend=extend))

    def test_repository_gitleaks_custom_rules_detect_runtime_canaries(self) -> None:
        """The rwsafe rules exist in the committed .gitleaks.toml and match a runtime-built canary each (the CI gitleaks
        self-test proves gitleaks itself reports them)."""
        config = tomllib.loads((REPO_ROOT / gate.GITLEAKS_CONFIG).read_text(encoding="utf-8"))
        rules = {r["id"]: r["regex"] for r in config["rules"]}
        canaries = [
            ("rwsafe-anthropic-api-key", "sk-" + "ant-" + _alnum(40)),
            ("rwsafe-openai-api-key", "sk-" + "proj-" + _alnum(40)),
            ("rwsafe-google-api-key", "AI" + "za" + _alnum(35)),
            ("rwsafe-github-token", "gh" + "p_" + _alnum(36)),
            ("rwsafe-icap-shared-secret", "icap" + "_secret" + ' = "' + _alnum(24) + '"'),
        ]
        for rule_id, canary in canaries:
            with self.subTest(rule=rule_id):
                self.assertIn(rule_id, rules)
                self.assertIsNotNone(re.search(rules[rule_id], canary))


class OutputDiscipline(GateTestCase):

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

    def test_policy_root_option_and_scanner_errors(self) -> None:
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(0, gate.main(["gate", "--policy-root", str(self.root), str(self.root)]))
            self.assertEqual(2, gate.main(["gate", str(self.root / "missing")]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
