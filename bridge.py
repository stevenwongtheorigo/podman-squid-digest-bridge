import asyncio
import hashlib
import logging
import os
from pathlib import Path
import re
import secrets

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Consume configuration once, before starting the server. Credentials are read
# from secret files, never injected into the container environment.
UPSTREAM_HOST = os.environ.pop("UPSTREAM_SQUID_HOST", "")
upstream_port = os.environ.pop("UPSTREAM_SQUID_PORT", "")
if not UPSTREAM_HOST or not upstream_port:
    raise SystemExit("UPSTREAM_SQUID_HOST and UPSTREAM_SQUID_PORT must be set")
try:
    UPSTREAM_PORT = int(upstream_port)
    if not 1 <= UPSTREAM_PORT <= 65535:
        raise ValueError
except ValueError:
    raise SystemExit("UPSTREAM_SQUID_PORT must be an integer from 1 to 65535") from None
del upstream_port
try:
    USERNAME, PASSWORD = (
        Path("/run/secrets/proxy_digest_credentials")
        .read_bytes().decode("utf-8").split("\0", 1)
    )
except (OSError, UnicodeError, ValueError):
    raise SystemExit("Unable to read credential secrets; start with ./startup.sh") from None
if not USERNAME or not PASSWORD:
    raise SystemExit("Credential secrets must be non-empty")

state = {
    "realm": None,
    "nonce": None,
    "qop": None,
    "opaque": None,
    "nc": 0,
}

def md5(data: str) -> str:
    return hashlib.md5(data.encode("utf-8")).hexdigest()

def parse_auth_challenge(header_val: str):
    matches = re.findall(r'(\w+)=(?:"([^"]+)"|([^\s,]+))', header_val)
    params = {k.lower(): v or v2 for k, v, v2 in matches}
    state["realm"] = params.get("realm")
    state["nonce"] = params.get("nonce")
    state["qop"] = params.get("qop")
    state["opaque"] = params.get("opaque")
    state["nc"] = 0

def build_auth_header(method: str, uri: str) -> str:
    if not (state["realm"] and state["nonce"]):
        return ""
    state["nc"] += 1
    nc_str = f"{state['nc']:08x}"
    cnonce = secrets.token_hex(8)

    ha1 = md5(f"{USERNAME}:{state['realm']}:{PASSWORD}")
    ha2 = md5(f"{method}:{uri}")

    if state["qop"] and "auth" in state["qop"].split(","):
        resp = md5(f"{ha1}:{state['nonce']}:{nc_str}:{cnonce}:auth:{ha2}")
        hdr = (
            f'Digest username="{USERNAME}", realm="{state["realm"]}", '
            f'nonce="{state["nonce"]}", uri="{uri}", qop=auth, '
            f'nc={nc_str}, cnonce="{cnonce}", response="{resp}"'
        )
    else:
        resp = md5(f"{ha1}:{state['nonce']}:{ha2}")
        hdr = (
            f'Digest username="{USERNAME}", realm="{state["realm"]}", '
            f'nonce="{state["nonce"]}", uri="{uri}", response="{resp}"'
        )
    if state["opaque"]:
        hdr += f', opaque="{state["opaque"]}"'
    return hdr

async def read_headers(reader: asyncio.StreamReader):
    raw = b""
    while not raw.endswith(b"\r\n\r\n"):
        line = await reader.readline()
        if not line:
            break
        raw += line
    return raw

async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()

async def handle_client(c_reader: asyncio.StreamReader, c_writer: asyncio.StreamWriter):
    req_header = await read_headers(c_reader)
    if not req_header:
        c_writer.close()
        return

    first_line = req_header.split(b"\r\n")[0].decode("latin-1")
    parts = first_line.split(" ")
    if len(parts) < 3:
        c_writer.close()
        return

    method, uri, proto = parts[0], parts[1], parts[2]

    # Handle HTTPS CONNECT Tunnels
    if method.upper() == "CONNECT":
        u_reader, u_writer = await asyncio.open_connection(UPSTREAM_HOST, UPSTREAM_PORT)

        # Step 1: Send CONNECT (with cached nonce if available)
        auth = build_auth_header("CONNECT", uri)
        req = f"CONNECT {uri} HTTP/1.1\r\nHost: {uri}\r\n"
        if auth:
            req += f"Proxy-Authorization: {auth}\r\n"
        req += "\r\n"
        u_writer.write(req.encode("latin-1"))
        await u_writer.drain()

        resp = await read_headers(u_reader)
        status_line = resp.split(b"\r\n")[0].decode("latin-1")

        # Step 2: Handle 407 Challenge
        if "407" in status_line:
            for line in resp.decode("latin-1").split("\r\n"):
                if line.lower().startswith("proxy-authenticate:"):
                    parse_auth_challenge(line.split(":", 1)[1].strip())
                    break

            # Re-open connection if Squid closed it
            u_writer.close()
            await u_writer.wait_closed()
            u_reader, u_writer = await asyncio.open_connection(UPSTREAM_HOST, UPSTREAM_PORT)

            auth = build_auth_header("CONNECT", uri)
            req = f"CONNECT {uri} HTTP/1.1\r\nHost: {uri}\r\nProxy-Authorization: {auth}\r\n\r\n"
            u_writer.write(req.encode("latin-1"))
            await u_writer.drain()

            resp = await read_headers(u_reader)
            status_line = resp.split(b"\r\n")[0].decode("latin-1")

        # Forward the final result to the client (200 Connection established)
        c_writer.write(resp)
        await c_writer.drain()

        if "200" in status_line:
            # Full duplex raw pipe for the TLS handshake and data
            await asyncio.gather(
                pipe(c_reader, u_writer),
                pipe(u_reader, c_writer)
            )
        else:
            u_writer.close()
            c_writer.close()
    else:
        # Plain HTTP Fallback
        c_writer.write(b"HTTP/1.1 501 Not Implemented\r\n\r\n")
        c_writer.close()

async def main():
    server = await asyncio.start_server(handle_client, "0.0.0.0", 8080)
    logging.info(f"Digest Bridge listening on :8080 (Upstream: {UPSTREAM_HOST}:{UPSTREAM_PORT})")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
