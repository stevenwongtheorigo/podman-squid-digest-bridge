import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from test_routing import CLIENT_AUTH_HEADER, CLIENT_TOKEN, Writer, load_bridge, reader


class SecurityTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.bridge = load_bridge(".proxied.example\n")

    async def test_large_client_header_block_is_rejected_without_a_connection(self):
        request = b"CONNECT direct.example:443 HTTP/1.1\r\n" + b"X-Audit: " + b"x" * 40000 + b"\r\n\r\n"
        client = Writer()
        with patch("asyncio.open_connection", new_callable=AsyncMock) as connect:
            await self.bridge["handle_client"](reader(request), client)
        self.assertIn(b"431 Request Header Fields Too Large", client.data)
        self.assertTrue(client.closed)
        connect.assert_not_awaited()

    async def test_many_short_headers_are_subject_to_the_same_total_limit(self):
        request = b"CONNECT direct.example:443 HTTP/1.1\r\n" + b"X-Audit: value\r\n" * 3000 + b"\r\n"
        client = Writer()
        with patch("asyncio.open_connection", new_callable=AsyncMock) as connect:
            await self.bridge["handle_client"](reader(request), client)
        self.assertIn(b"431 Request Header Fields Too Large", client.data)
        connect.assert_not_awaited()

    async def test_large_upstream_headers_fail_closed_and_close_the_socket(self):
        upstream = Writer()
        response = b"HTTP/1.1 200 Connection established\r\n" + b"X-Audit: value\r\n" * 3000 + b"\r\n"
        client = Writer()
        request = reader(b"CONNECT proxied.example:443 HTTP/1.1\r\n" + CLIENT_AUTH_HEADER + b"\r\n")
        with patch("asyncio.open_connection", new_callable=AsyncMock,
                   return_value=(reader(response), upstream)) as connect:
            await self.bridge["handle_client"](request, client)
        self.assertIn(b"502 Bad Gateway", client.data)
        self.assertNotIn(b"200 Connection", client.data)
        self.assertTrue(upstream.closed)
        connect.assert_awaited_once()

    async def test_client_limit_rejects_excess_and_releases_slots(self):
        stalled = asyncio.StreamReader()
        first, excess = Writer(), Writer()
        with patch.dict(self.bridge, MAX_CLIENTS=1):
            active = asyncio.create_task(self.bridge["handle_client"](stalled, first))
            try:
                # Let the first handler reserve its slot and wait for headers.
                await asyncio.sleep(0)
                self.assertEqual(self.bridge["active_clients"], 1)
                await asyncio.wait_for(self.bridge["handle_client"](
                    reader(b"CONNECT direct.example:443 HTTP/1.1\r\n\r\n"), excess), 0.2)
                self.assertTrue(excess.closed)
                self.assertEqual(self.bridge["active_clients"], 1)
            finally:
                active.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await active
            self.assertTrue(first.closed)
            self.assertEqual(self.bridge["active_clients"], 0)
            next_client = Writer()
            await self.bridge["handle_client"](reader(b"GET / HTTP/1.1\r\n" + CLIENT_AUTH_HEADER + b"\r\n"), next_client)
            self.assertIn(b"501", next_client.data)
            self.assertEqual(self.bridge["active_clients"], 0)

    async def test_unsupported_digest_is_rejected_before_sending_credentials(self):
        for options in ('algorithm=SHA-256, qop="auth"', 'algorithm=MD5-sess, qop="auth"',
                        'algorithm=MD5, qop="auth-int"', 'algorithm=MD5',
                        'algorithm=SHA-256, qop="auth-int"',
                        'algorithm=MD5, algorithm=SHA-256, qop="auth"'):
            with self.subTest(options=options):
                self.bridge = load_bridge(".proxied.example\n")
                response = ('HTTP/1.1 407 Proxy Authentication Required\r\n'
                            'Proxy-Authenticate: Digest realm="audit", nonce="nonce", '
                            + options + '\r\n\r\n').encode()
                upstream, client = Writer(), Writer()
                with patch("asyncio.open_connection", new_callable=AsyncMock,
                           return_value=(reader(response), upstream)) as connect:
                    await self.bridge["handle_client"](
                        reader(b"CONNECT proxied.example:443 HTTP/1.1\r\n" + CLIENT_AUTH_HEADER + b"\r\n"), client)
                self.assertIn(b"502 Bad Gateway", client.data)
                self.assertNotIn(b"Proxy-Authorization", upstream.data)
                self.assertTrue(upstream.closed)
                connect.assert_awaited_once()

    async def test_digest_quotes_values_and_rejects_header_control_characters(self):
        self.bridge["parse_auth_challenge"]('Digest realm="audit", nonce="nonce", qop="auth, auth-int"')
        self.bridge["USERNAME"] = 'DOMAIN\\user"name'
        header = self.bridge["build_auth_header"]("CONNECT", "proxied.example:443")
        self.assertIn('username="DOMAIN\\\\user\\"name"', header)
        self.assertIn("algorithm=MD5", header)
        self.assertIn("qop=auth", header)
        self.assertIn("cnonce=", header)
        with self.assertRaises(ValueError):
            self.bridge["parse_auth_challenge"]('Digest realm="audit", nonce="nonce", qop="auth", opaque="bad\nX-Injected: yes"')

    async def test_unauthenticated_and_wrong_tokens_never_open_outbound_connections(self):
        for header in (b"", b"Proxy-Authorization: Basic YnJpZGdlOndyb25n\r\n",
                       b"Proxy-Authorization: Basic !!!\r\n", CLIENT_AUTH_HEADER + CLIENT_AUTH_HEADER):
            with self.subTest(header=header):
                client = Writer()
                with patch("asyncio.open_connection", new_callable=AsyncMock) as connect:
                    await self.bridge["handle_client"](
                        reader(b"CONNECT proxied.example:443 HTTP/1.1\r\n" + header + b"\r\n"), client)
                self.assertIn(b"407 Proxy Authentication Required", client.data)
                self.assertNotIn(CLIENT_TOKEN, client.data)
                connect.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
