import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


class CredentialTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(os.environ, {
            "UPSTREAM_SQUID_HOST": "proxy.example.com",
            "UPSTREAM_SQUID_PORT": "3128",
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def load_bridge(self, payload):
        with patch.object(Path, "read_bytes", return_value=payload):
            return runpy.run_path(str(ROOT / "bridge.py"))

    def test_secret_authenticates_without_environment_credentials(self):
        with patch.dict(os.environ, {
            "UPSTREAM_SQUID_HOST": "proxy.example.com",
            "UPSTREAM_SQUID_PORT": "3128",
        }, clear=True):
            bridge = self.load_bridge(b"Mufasa\0Circle Of Life")
            self.assertNotIn("PROXY_DIGEST_USER", os.environ)
            self.assertNotIn("PROXY_DIGEST_PASS", os.environ)
        bridge["parse_auth_challenge"](
            'Digest realm="testrealm@host.com", '
            'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", qop="auth"'
        )
        with patch("secrets.token_hex", return_value="0a4f113b"):
            header = bridge["build_auth_header"]("GET", "/dir/index.html")
        self.assertIn('response="6629fae49393a05397450978507c4ef1"', header)

    def test_secret_preserves_whitespace(self):
        bridge = self.load_bridge(b" user \0 password\r\n ")
        self.assertEqual(bridge["USERNAME"], " user ")
        self.assertEqual(bridge["PASSWORD"], " password\r\n ")

    def test_invalid_and_missing_secrets_fail(self):
        for payload in (b"", b"missing-separator", b"\0password", b"user\0", b"user\0\xff"):
            with self.subTest(payload=payload), self.assertRaises(SystemExit):
                self.load_bridge(payload)
        with patch.object(Path, "read_bytes", side_effect=FileNotFoundError):
            with self.assertRaises(SystemExit):
                runpy.run_path(str(ROOT / "bridge.py"))

    def test_startup_sends_secret_only_through_stdin(self):
        with tempfile.TemporaryDirectory() as directory:
            startup = Path(directory) / "startup.sh"
            shutil.copy2(ROOT / "startup.sh", startup)
            (Path(directory) / ".env").write_text(
                "UPSTREAM_SQUID_HOST=upstream.example.com\n"
                "UPSTREAM_SQUID_PORT=4567\n"
                "PROXY_DIGEST_USER=ignored-user\n"
                "PROXY_DIGEST_PASS=ignored-password\n"
            )
            fake = Path(directory) / "podman"
            fake.write_text(
                f"#!{sys.executable}\n"
                "import json, os, pathlib, sys\n"
                "assert 'PROXY_DIGEST_USER' not in os.environ\n"
                "assert 'PROXY_DIGEST_PASS' not in os.environ\n"
                "root = pathlib.Path(os.environ['TEST_CAPTURE_DIR'])\n"
                "if sys.argv[1:3] == ['secret', 'create']:\n"
                "    (root / 'secret').write_bytes(sys.stdin.buffer.read())\n"
                "elif sys.argv[1] == 'run':\n"
                "    (root / 'args').write_text(json.dumps(sys.argv[1:]))\n"
                "else:\n"
                "    sys.exit(2)\n"
            )
            fake.chmod(0o700)
            username, password = "test user", "test password $ \\\n"
            env = dict(
                os.environ,
                PATH=directory + os.pathsep + os.environ["PATH"],
                TEST_CAPTURE_DIR=directory,
                PROXY_DIGEST_USER=username,
                PROXY_DIGEST_PASS=password,
            )
            env.pop("UPSTREAM_SQUID_HOST", None)
            env.pop("UPSTREAM_SQUID_PORT", None)
            subprocess.run([str(startup)], env=env, check=True)
            self.assertEqual(
                (Path(directory) / "secret").read_bytes(),
                (username + "\0" + password).encode(),
            )
            args = json.loads((Path(directory) / "args").read_text())
            self.assertIn("UPSTREAM_SQUID_HOST=upstream.example.com", args)
            self.assertIn("UPSTREAM_SQUID_PORT=4567", args)
            self.assertNotIn(username, " ".join(args))
            self.assertNotIn(password, " ".join(args))
            self.assertIn(
                "source=squid-digest-bridge-credentials,type=mount,"
                "target=proxy_digest_credentials,mode=0400", args
            )
            env.update(UPSTREAM_SQUID_HOST="override.example.com", UPSTREAM_SQUID_PORT="5678")
            subprocess.run([str(startup)], env=env, check=True)
            args = json.loads((Path(directory) / "args").read_text())
            self.assertIn("UPSTREAM_SQUID_HOST=override.example.com", args)
            self.assertIn("UPSTREAM_SQUID_PORT=5678", args)

            (Path(directory) / ".env").unlink()
            env.pop("UPSTREAM_SQUID_HOST")
            env.pop("UPSTREAM_SQUID_PORT")
            result = subprocess.run([str(startup)], env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Set UPSTREAM_SQUID_HOST", result.stderr)

    def test_invalid_upstream_configuration_fails(self):
        for host, port in (("", "3128"), ("proxy.example.com", ""),
                           ("proxy.example.com", "invalid"), ("proxy.example.com", "0"),
                           ("proxy.example.com", "65536")):
            with self.subTest(host=host, port=port), patch.dict(os.environ, {
                "UPSTREAM_SQUID_HOST": host, "UPSTREAM_SQUID_PORT": port,
            }), self.assertRaises(SystemExit):
                self.load_bridge(b"user\0password")


if __name__ == "__main__":
    unittest.main()
