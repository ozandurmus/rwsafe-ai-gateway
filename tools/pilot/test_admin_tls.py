#!/usr/bin/env python3
"""Self-test of tools/pilot/admin_tls.sh against a stand-in kubectl (nothing reaches a cluster): the CA is made once with
its key 0600 under ~/.config/<product>/admin-ca/ and never handed to kubectl; the leaf is for `ui.<product>.local` only
(SAN DNS only, 825 days, serverAuth, EC P-256) and verifies against the name-constrained CA; the Secret is created from
the leaf files; a second run changes nothing; --renew replaces the Secret from the same CA; no key, certificate body or
home path is printed; the temporary files are gone. Runs under both product names.

Usage: python3 -B tools/pilot/test_admin_tls.py
"""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "admin_tls.sh"

# The stand-in kubectl: `get namespace` succeeds; `get secret` succeeds once a Secret was stored; the labelled pipeline
# (`create secret tls ... --dry-run=client -o json`, `label --local`, `create|apply -f -`) copies the files it was given
# into the state directory and records the stored object; every call is logged.
FAKE_KUBECTL = r"""#!/usr/bin/env bash
set -euo pipefail
state="${FAKE_STATE:?}"
printf '%s\n' "$*" >> "${state}/calls.log"
args=("$@")
if [ "${args[0]}" = "-n" ]; then args=("${args[@]:2}"); fi
case "${args[0]} ${args[1]:-}" in
  "get namespace") exit 0 ;;
  "get secret") [ -f "${state}/stored.json" ] && exit 0 || exit 1 ;;
  "create secret")
    for a in "${args[@]}"; do
      case "${a}" in
        --dry-run=client) dry=1 ;;
        --cert=*) cp "${a#--cert=}" "${state}/tls.crt" ;;
        --key=*) cp "${a#--key=}" "${state}/tls.key" ;;
      esac
    done
    [ "${dry:-0}" = 1 ] || exit 3
    printf '{"apiVersion":"v1","kind":"Secret","type":"kubernetes.io/tls","metadata":{"name":"%s"}}\n' "${args[3]}" ;;
  "label --local") cat ;;
  "create -f"|"apply -f") cat > "${state}/stored.json"; echo "${args[0]}" >> "${state}/modes.log" ;;
  *) echo "unexpected: $*" >&2; exit 4 ;;
esac
"""


def openssl(*args: str) -> str:
    return subprocess.run(["openssl", *args], capture_output=True, text=True, check=True).stdout


class AdminTls(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.home = self.tmp / "home"
        self.state = self.tmp / "state"
        self.bin = self.tmp / "bin"
        self.scratch = self.tmp / "scratch"
        for d in (self.home, self.state, self.bin, self.scratch):
            d.mkdir()
        kubectl = self.bin / "kubectl"
        kubectl.write_text(FAKE_KUBECTL)
        kubectl.chmod(0o755)
        if not shutil.which("shred"):
            shred = self.bin / "shred"
            shred.write_text('#!/bin/sh\n[ "$1" = "-u" ] && shift\nrm -f "$@"\n')
            shred.chmod(0o755)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_script(self, product: str, *args: str) -> tuple[int, str]:
        env = {"PATH": f"{self.bin}:/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin",
               "HOME": str(self.home), "TMPDIR": str(self.scratch), "PRODUCT": product,
               "KUBECTL": str(self.bin / "kubectl"), "FAKE_STATE": str(self.state)}
        out = subprocess.run(["bash", str(SCRIPT), *args], capture_output=True, text=True, timeout=120, env=env)
        return out.returncode, out.stdout + out.stderr

    def assert_nothing_secret_printed(self, out: str):
        self.assertNotIn("PRIVATE KEY", out)
        self.assertNotIn("BEGIN", out)
        self.assertNotIn(str(self.home), out)
        self.assertIsNone(re.search(r"[A-Za-z0-9+/=]{40,}", out), out)

    def test_bash_n_and_usage(self):
        self.assertEqual(subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True).returncode, 0)
        rc, out = self.run_script("rwsafe", "--bogus")
        self.assertEqual(rc, 2, out)
        self.assertIn("usage", out)

    def test_create_skip_and_renew(self):
        for product in ("rwsafe", "acme"):
            with self.subTest(product):
                self.tearDown()
                self.setUp()
                self.check_product(product)

    def check_product(self, product: str):
        host = f"ui.{product}.local"
        rc, out = self.run_script(product)
        self.assertEqual(rc, 0, out)
        self.assert_nothing_secret_printed(out)
        self.assertIn(f"created secret {product}-admin-tls", out)
        self.assertIn(f"~/.config/{product}/admin-ca/ca.crt", out)
        fp = re.search(r"CA SHA-256 fingerprint: ((?:[0-9A-F]{2}:){31}[0-9A-F]{2})$", out, re.M)
        self.assertIsNotNone(fp, out)

        ca_dir = self.home / ".config" / product / "admin-ca"
        self.assertEqual(stat.S_IMODE(ca_dir.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((ca_dir / "ca.key").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((ca_dir / "ca.crt").stat().st_mode), 0o644)
        ca_cert, leaf = str(ca_dir / "ca.crt"), str(self.state / "tls.crt")
        self.assertEqual(fp.group(1), openssl("x509", "-in", ca_cert, "-noout", "-fingerprint", "-sha256")
                         .strip().split("=", 1)[1])

        # The CA key never reaches kubectl, and the Secret is made from the leaf's files only.
        calls = (self.state / "calls.log").read_text()
        self.assertNotIn("ca.key", calls)
        self.assertNotIn(str(self.home), calls)
        self.assertIn(f"-n {product} create secret tls {product}-admin-tls --cert=", calls)
        stored = json.loads((self.state / "stored.json").read_text())
        self.assertEqual(stored["metadata"]["name"], f"{product}-admin-tls")
        self.assertEqual((self.state / "modes.log").read_text().split(), ["create"])
        self.assertNotEqual((self.state / "tls.key").read_bytes(), (ca_dir / "ca.key").read_bytes())

        # The CA: 10 years, a CA for one path length, constrained to the admin host.
        ca_text = openssl("x509", "-in", ca_cert, "-noout", "-text")
        self.assertRegex(ca_text, r"CA:TRUE, pathlen:0")
        self.assertIn(f"DNS:{host}", ca_text.split("Name Constraints", 1)[1])
        self.assertEqual(self.days(ca_cert), 3650)
        # The leaf: this host only, serverAuth, EC P-256, 825 days, issued by the CA and verifying against it.
        leaf_text = openssl("x509", "-in", leaf, "-noout", "-text")
        san = leaf_text.split("Subject Alternative Name:", 1)[1].strip().splitlines()[0].strip()
        self.assertEqual(san, f"DNS:{host}")
        self.assertIn("TLS Web Server Authentication", leaf_text)
        self.assertNotIn("TLS Web Client Authentication", leaf_text)
        self.assertRegex(leaf_text, r"CA:FALSE")
        # Named curve only: explicit curve parameters (LibreSSL's genpkey default) are refused by Go's crypto/x509
        # (Traefik) and by browsers.
        for text in (ca_text, leaf_text):
            self.assertIn("ASN1 OID: prime256v1", text)
            self.assertNotIn("Field Type", text)
        self.assertEqual(self.days(leaf), 825)
        self.assertIn("OK", openssl("verify", "-CAfile", ca_cert, leaf))
        # Nothing left in the temporary directory.
        self.assertEqual(list(self.scratch.iterdir()), [])

        # Again: the Secret exists, nothing changes.
        rc, out = self.run_script(product)
        self.assertEqual(rc, 0, out)
        self.assertIn(f"exists, left as it is: secret {product}-admin-tls", out)
        self.assertIn(fp.group(1), out)
        self.assertEqual((self.state / "modes.log").read_text().split(), ["create"])

        # --renew: a new leaf from the same CA replaces the Secret.
        old_leaf = Path(leaf).read_bytes()
        rc, out = self.run_script(product, "--renew")
        self.assertEqual(rc, 0, out)
        self.assert_nothing_secret_printed(out)
        self.assertIn("CA exists, reused", out)
        self.assertIn(f"renewed secret {product}-admin-tls", out)
        self.assertIn(fp.group(1), out)
        self.assertEqual((self.state / "modes.log").read_text().split(), ["create", "apply"])
        self.assertNotEqual(Path(leaf).read_bytes(), old_leaf)
        self.assertIn("OK", openssl("verify", "-CAfile", ca_cert, leaf))
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_half_a_ca_and_a_lost_ca_are_refused(self):
        rc, out = self.run_script("rwsafe")
        self.assertEqual(rc, 0, out)
        ca_dir = self.home / ".config" / "rwsafe" / "admin-ca"
        (ca_dir / "ca.key").unlink()
        rc, out = self.run_script("rwsafe", "--renew")
        self.assertEqual(rc, 1, out)
        self.assertIn("only one of", out)
        (ca_dir / "ca.crt").unlink()
        rc, out = self.run_script("rwsafe")
        self.assertEqual(rc, 1, out)
        self.assertIn("CA files under ~/.config/rwsafe/admin-ca/ are missing", out)

    @staticmethod
    def days(cert: str) -> int:
        from datetime import datetime
        dates = dict(line.split("=", 1) for line in openssl("x509", "-in", cert, "-noout", "-startdate",
                                                            "-enddate").splitlines())
        fmt = "%b %d %H:%M:%S %Y %Z"
        start = datetime.strptime(re.sub(r"\s+", " ", dates["notBefore"]), fmt)
        end = datetime.strptime(re.sub(r"\s+", " ", dates["notAfter"]), fmt)
        return round((end - start).total_seconds() / 86400)


if __name__ == "__main__":
    os.umask(0o022)
    unittest.main(verbosity=1)
