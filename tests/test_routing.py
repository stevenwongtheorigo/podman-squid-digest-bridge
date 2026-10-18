import asyncio
import os
from pathlib import Path
import runpy
import unittest
from unittest.mock import AsyncMock, patch


ROOT = Path(__file__).resolve().parents[1]


def load_bridge(rules=None, **environment):
    settings = {"UPSTREAM_SQUID_HOST": "squid.example", "UPSTREAM_SQUID_PORT": "3128"}
    settings.update(environment)
    if rules is not None:
        settings["PROXY_DOMAINS_FILE"] = "/app/proxy-domains.txt"
    with patch.dict(os.environ, settings, clear=True), \
            patch.object(Path, "read_text", return_value=rules), \
            patch.object(Path, "read_bytes", return_value=b"user\0password"):
        loaded = runpy.run_path(str(ROOT / "bridge.py"))
    return loaded["handle_client"].__globals__


class DomainTests(unittest.TestCase):
    def setUp(self):
        self.bridge = load_bridge()

    def test_squid_exact_and_suffix_matching(self):
        rules = self.bridge["parse_domain_rules"]("# comment\r\nEXACT.Example. # exact\n\n.Example.NET\n.example.net.\n")
        self.assertEqual(rules, {"exact.example", ".example.net"})
        for host, expected in (("exact.example", True), ("EXACT.EXAMPLE.", True),
                               ("sub.exact.example", False), ("example.net", True),
                               ("a.b.example.net", True), ("notexample.net", False),
                               ("example.net.evil", False), ("unlisted.example", False),
                               ("127.0.0.1", False), ("::1", False)):
            with self.subTest(host=host):
                self.assertEqual(self.bridge["should_proxy"](host, rules), expected)

    def test_unconfigured_and_empty_lists_have_distinct_defaults(self):
        for host in ("example.com", "127.0.0.1", "::1"):
            self.assertTrue(self.bridge["should_proxy"](host, None))
            self.assertFalse(self.bridge["should_proxy"](host, frozenset()))

    def test_invalid_rules_report_line_number(self):
        invalid = ("*.example.com", "https://example.com", "example.com:443", "example.com/path",
                   "acl proxy dstdomain .example.com", "example.com other.com", "!example.com",
                   ".", "..example.com", "example..com", "example.com..", "bad_name.example",
                   "-bad.example", "bad-.example", "127.0.0.1", ".127.0.0.1", "[::1]",
                   "éxample.com", "a" * 64 + ".example", "a." * 127 + "com")
        for entry in invalid:
            with self.subTest(entry=entry), self.assertRaisesRegex(ValueError, "line 3"):
                self.bridge["parse_domain_rules"]("# header\n\n" + entry)

    def test_dns_names_and_ip_connect_targets(self):
        for target, expected in (("EXAMPLE.com.:443", ("example.com", 443)),
                                 ("xn--bcher-kva.example:8443", ("xn--bcher-kva.example", 8443)),
                                 ("127.0.0.1:80", ("127.0.0.1", 80)),
                                 ("[2001:0db8::1]:443", ("2001:db8::1", 443))):
            with self.subTest(target=target):
                self.assertEqual(self.bridge["parse_connect_target"](target), expected)
        for target in ("example.com", "example.com:0", "example.com:65536", "example.com:-1",
                       "example.com:abc", "example.com:443/path", "user@example.com:443",
                       "example.com:443:80", "https://example.com:443", "[::1]", "::1:443",
                       "[not-ipv6]:443", "[fe80::1%eth0]:443", "bad name:443", ":443"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.bridge["parse_connect_target"](target)

    def test_direct_only_does_not_require_upstream_settings_or_read_secrets(self):
        with patch.object(Path, "read_bytes", side_effect=AssertionError("Secret accessed")):
            # run_path needs no secret patch in this test: only an empty policy.
            with patch.dict(os.environ, {"PROXY_DOMAINS_FILE": "domains.txt"}, clear=True), \
                    patch.object(Path, "read_text", return_value="# all direct\n"):
                bridge = runpy.run_path(str(ROOT / "bridge.py"))
        self.assertFalse(bridge["NEEDS_UPSTREAM"])
        self.assertIsNone(bridge["USERNAME"])
        self.assertIsNone(bridge["PASSWORD"])

    def test_invalid_or_missing_files_fail_before_credentials(self):
        for error in (FileNotFoundError(), PermissionError(), UnicodeError("invalid encoding")):
            with self.subTest(error=error), patch.dict(os.environ, {"PROXY_DOMAINS_FILE": "bad"}, clear=True), \
                    patch.object(Path, "read_text", side_effect=error), self.assertRaisesRegex(SystemExit, "Unable to load proxy domains"):
                runpy.run_path(str(ROOT / "bridge.py"))
        with self.assertRaisesRegex(SystemExit, "Invalid domain rule"):
            load_bridge("*.example.com")

    def test_nonempty_file_requires_upstream_configuration(self):
        with self.assertRaisesRegex(SystemExit, "must be set"):
            load_bridge(".example.com", UPSTREAM_SQUID_HOST="")


class Writer:
    def __init__(self):
        self.data = bytearray()
        self.closed = False
        self.eof = False
        self.drain = AsyncMock()
        self.wait_closed = AsyncMock()

    def write(self, data):
        self.data.extend(data)

    def close(self):
        self.closed = True

    def can_write_eof(self):
        return True

    def write_eof(self):
        self.eof = True


def reader(data):
    stream = asyncio.StreamReader()
    stream.feed_data(data)
    stream.feed_eof()
    return stream


class RoutingTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.bridge = load_bridge(".proxied.example\n")
        self.client = Writer()

    async def request(self, target, payload=b"", method="CONNECT"):
        stream = reader(f"{method} {target} HTTP/1.1\r\nHost: ignored.example\r\nProxy-Authorization: client-secret\r\n\r\n".encode() + payload)
        await self.bridge["handle_client"](stream, self.client)
        self.assertTrue(self.client.closed)
        return bytes(self.client.data)

    async def test_unmatched_host_connects_direct_and_relays_only_tunnel_bytes(self):
        destination = Writer()
        with patch("asyncio.open_connection", new_callable=AsyncMock,
                   return_value=(reader(b"destination bytes"), destination)) as connect:
            response = await self.request("DIRECT.EXAMPLE.:8443", b"TLS client bytes")
        connect.assert_awaited_once_with("direct.example", 8443)
        self.assertEqual(response, b"HTTP/1.1 200 Connection established\r\n\r\ndestination bytes")
        self.assertEqual(destination.data, b"TLS client bytes")
        self.assertTrue(destination.closed)

    async def test_configured_policy_sends_ipv4_and_ipv6_direct(self):
        for target, host in (("127.0.0.1:443", "127.0.0.1"), ("[::1]:443", "::1")):
            with self.subTest(target=target):
                self.client = Writer()
                with patch("asyncio.open_connection", new_callable=AsyncMock,
                           return_value=(reader(b""), Writer())) as connect:
                    await self.request(target)
                connect.assert_awaited_once_with(host, 443)

    async def test_matching_host_uses_digest_and_never_connects_to_destination(self):
        challenge = (b'HTTP/1.1 407 Proxy Authentication Required\r\n'
                     b'Proxy-Authenticate: Digest realm="realm", nonce="nonce", qop="auth"\r\n\r\n')
        first, authenticated = Writer(), Writer()
        with patch("asyncio.open_connection", new_callable=AsyncMock, side_effect=[
            (reader(challenge), first),
            (reader(b"HTTP/1.1 200 Connection established\r\n\r\nupstream tunnel"), authenticated),
        ]) as connect:
            response = await self.request("sub.proxied.example:443", b"client tunnel")
        self.assertEqual(connect.await_count, 2)
        self.assertTrue(all(call.args == ("squid.example", 3128) for call in connect.await_args_list))
        self.assertNotIn(b"Proxy-Authorization:", first.data)
        self.assertIn(b'Proxy-Authorization: Digest username="user"', authenticated.data)
        self.assertNotIn(b"client-secret", first.data + authenticated.data)
        self.assertTrue(authenticated.data.endswith(b"\r\n\r\nclient tunnel"))
        self.assertTrue(response.endswith(b"upstream tunnel"))
        self.assertTrue(first.closed)
        self.assertTrue(authenticated.closed)

    async def test_route_failure_returns_gateway_error_without_fallback(self):
        for target, expected_host in (("direct.example:443", "direct.example"),
                                      ("proxied.example:443", "squid.example")):
            for error, status in ((OSError("unreachable"), b"502 Bad Gateway"),
                                   (asyncio.TimeoutError(), b"504 Gateway Timeout")):
                with self.subTest(target=target, error=error):
                    self.client = Writer()
                    with patch("asyncio.open_connection", new_callable=AsyncMock, side_effect=error) as connect:
                        response = await self.request(target)
                    self.assertIn(status, response)
                    self.assertNotIn(b"200 Connection", response)
                    connect.assert_awaited_once_with(expected_host, 3128 if expected_host == "squid.example" else 443)

    async def test_upstream_header_timeout_closes_connection_without_fallback(self):
        upstream = Writer()
        stalled = asyncio.StreamReader()
        with patch.dict(self.bridge, CONNECT_TIMEOUT=0.01), \
                patch("asyncio.open_connection", new_callable=AsyncMock, return_value=(stalled, upstream)) as connect:
            response = await self.request("proxied.example:443")
        self.assertIn(b"504 Gateway Timeout", response)
        self.assertTrue(upstream.closed)
        connect.assert_awaited_once_with("squid.example", 3128)

    async def test_upstream_rejection_is_forwarded_without_fallback(self):
        upstream = Writer()
        response = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
        with patch("asyncio.open_connection", new_callable=AsyncMock, return_value=(reader(response), upstream)) as connect:
            self.assertEqual(await self.request("proxied.example:443"), response)
        connect.assert_awaited_once()
        self.assertTrue(upstream.closed)

    async def test_truncated_upstream_response_is_gateway_failure(self):
        upstream = Writer()
        with patch("asyncio.open_connection", new_callable=AsyncMock,
                   return_value=(reader(b"HTTP/1.1 200 Connection established\r\n"), upstream)) as connect:
            response = await self.request("proxied.example:443")
        self.assertIn(b"502 Bad Gateway", response)
        connect.assert_awaited_once()
        self.assertTrue(upstream.closed)

    async def test_invalid_target_is_bad_request_without_opening_connections(self):
        for target in ("example.com", "example.com:0", "[::1]", "user@example.com:443"):
            with self.subTest(target=target):
                self.client = Writer()
                with patch("asyncio.open_connection", new_callable=AsyncMock) as connect:
                    response = await self.request(target)
                self.assertIn(b"400 Bad Request", response)
                connect.assert_not_awaited()

    async def test_plain_http_remains_unsupported(self):
        with patch("asyncio.open_connection", new_callable=AsyncMock) as connect:
            response = await self.request("http://example.com/", method="GET")
        self.assertIn(b"501 Not Implemented", response)
        connect.assert_not_awaited()

    async def test_tunnel_eof_keeps_reverse_direction_open_for_response(self):
        destination = Writer()
        await self.bridge["pipe"](reader(b"request bytes"), destination)
        self.assertEqual(destination.data, b"request bytes")
        self.assertTrue(destination.eof)
        self.assertFalse(destination.closed)

    async def test_malformed_digest_challenge_is_gateway_failure(self):
        upstream = Writer()
        malformed = b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Digest realm="realm"\r\n\r\n'
        with patch("asyncio.open_connection", new_callable=AsyncMock,
                   return_value=(reader(malformed), upstream)) as connect:
            response = await self.request("proxied.example:443")
        self.assertIn(b"502 Bad Gateway", response)
        connect.assert_awaited_once()
        self.assertTrue(upstream.closed)


if __name__ == "__main__":
    unittest.main()
