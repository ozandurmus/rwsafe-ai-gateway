"""Tests for access_log_shapes.py with a synthetic log built at runtime (documentation addresses, reserved names)."""
import gzip
import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import access_log_shapes as shapes  # noqa: E402

FIELDS = ("#Fields: date time time-taken c-ip cs-username cs-auth-group s-action sc-status cs-method cs-host "
          "cs-uri-path cs-uri-query cs-bytes sc-bytes cs-categories cs(User-Agent)")


def line(host, path, cats, user="USR-a1", status="200", ua='"Mozilla/5.0 (X11)"', req="512", resp="2048"):
    client = ".".join(["192", "0", "2", "10"])  # RFC 5737 documentation address, built at runtime
    return (f'2026-10-30 09:15:01 840 {client} {user} - TCP_NC_MISS {status} POST {host} {path} - {req} {resp} '
            f'"{cats}" {ua}')


class ShapesTest(unittest.TestCase):
    def run_on(self, lines, gz=False):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "main.log" + (".gz" if gz else ""))
            data = "\n".join(["#Software: synthetic", FIELDS, *lines]) + "\n"
            if gz:
                with gzip.open(path, "wt", encoding="utf-8") as f:
                    f.write(data)
            else:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(data)
            res = shapes.analyse([path], re.compile("artificial intelligence", re.I))
            return res, shapes.render(res)

    def test_platforms_and_buckets(self):
        res, text = self.run_on([
            line("chatgpt.com", "/backend-api/conversation", "Artificial Intelligence/ML Applications"),
            line("api.anthropic.com", "/v1/messages", "Artificial Intelligence/ML Applications",
                 ua='"claude-cli/2.0 (external, cli)"', req="70000"),
            line("relay.example.invalid", "/v1/chat/completions", "none"),
            line("other.example.invalid", "/index.html", "none"),
        ], gz=True)
        self.assertEqual(res["per_platform"]["openai"]["requests"], 1)
        self.assertEqual(res["per_platform"]["claude"]["client:claude-code"], 1)
        self.assertEqual(res["per_platform"]["claude"]["req-bytes:<=1MiB"], 1)
        self.assertEqual(res["unc_hosts"], 2)
        self.assertEqual(res["unc_llm_hosts"], 1)
        self.assertIn("distinct users: <5", text)

    def test_output_has_no_identifiers(self):
        _, text = self.run_on([line("relay.example.invalid", "/v1/chat/completions?key=abc", "none", user="USR-zz")])
        for forbidden in ("example.invalid", "USR-zz", "192.0.2", "/v1/chat", "key=abc", "Mozilla"):
            self.assertNotIn(forbidden, text)
        shapes.self_check(text)

    def test_self_check_refuses_addresses(self):
        with self.assertRaises(SystemExit):
            shapes.self_check("value " + ".".join(["198", "51", "100", "7"]))

    def test_missing_fields_reported(self):
        _, text = self.run_on([line("chatgpt.com", "/", "Artificial Intelligence/ML Applications")])
        self.assertIn("Fields absent: none", text)


if __name__ == "__main__":
    unittest.main()
