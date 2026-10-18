import os
from pathlib import Path
import runpy
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
