import asyncio
import base64
import binascii
import hashlib
import hmac
import ipaddress
import logging
import os
from pathlib import Path
import re
import secrets
import sys

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

CONNECT_TIMEOUT = 10
MAX_HEADER_BYTES = 32 * 1024
MAX_CLIENTS = 100
active_clients = 0
DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
DIGEST_PARAM = re.compile(
    r'''[ \t]*([!#$%&'*+\-.^_`|~0-9A-Za-z]+)[ \t]*=[ \t]*'''
    r'''(?:"((?:[^"\\\x00-\x1f\x7f]|\\[\x20-\x7e])*)"|([!#$%&'*+\-.^_`|~0-9A-Za-z]+))[ \t]*(?:,|$)'''
)


def normalize_hostname(host):
    host = host.lower().removesuffix(".")
    if not host or len(host) > 253 or not all(DOMAIN_LABEL.fullmatch(label) for label in host.split(".")):
        raise ValueError("Invalid hostname")
    return host


def parse_domain_rules(text):
    rules = set()
    for number, line in enumerate(text.splitlines(), 1):
        entry = line.partition("#")[0].strip()
        if not entry:
            continue
        suffix = entry.startswith(".")
        try:
            domain = normalize_hostname(entry[1:] if suffix else entry)
            try:
                ipaddress.ip_address(domain)
            except ValueError:
                pass
            else:
                raise ValueError("Use hostnames, not IP addresses")
        except ValueError:
            raise ValueError(f"Invalid domain rule on line {number}") from None
        rules.add(("." if suffix else "") + domain)
    return frozenset(rules)


def load_domain_rules(filename):
    if not filename:
        return None  # No configured list preserves proxy-everything behavior.
    try:
        return parse_domain_rules(Path(filename).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as error:
        raise SystemExit(f"Unable to load proxy domains: {error}") from None


def should_proxy(host, rules):
    if rules is None:
        return True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        host = normalize_hostname(host)
        return any(host == rule or (rule.startswith(".") and
                   (host == rule[1:] or host.endswith(rule))) for rule in rules)
    return False


def parse_connect_target(target):
    if target.startswith("["):
        match = re.fullmatch(r"\[([^]\s%]+)\]:([0-9]+)", target)
        if not match:
            raise ValueError("Invalid CONNECT target")
        host, port = match.groups()
        host = str(ipaddress.IPv6Address(host))
    else:
        match = re.fullmatch(r"([^:\s]+):([0-9]+)", target)
        if not match:
            raise ValueError("Invalid CONNECT target")
        host, port = match.groups()
        try:
            host = str(ipaddress.IPv4Address(host))
        except ValueError:
            host = normalize_hostname(host)
    port = int(port)
    if not 1 <= port <= 65535:
        raise ValueError("Invalid CONNECT port")
    return host, port


def load_client_token():
    try:
        token = Path("/run/secrets/bridge_client_token").read_bytes().strip()
    except OSError:
        raise SystemExit("Unable to read local client token; start with ./startup.sh") from None
    if re.fullmatch(rb"[A-Za-z0-9_-]{32,128}", token) is None:
        raise SystemExit("Invalid local client token; start with ./startup.sh")
    return token


if __name__ == "__main__" and sys.argv[1:] == ["--check-client-token"]:
    load_client_token()
    raise SystemExit(0)


# Consume routing and upstream settings once, before starting the server.
DOMAIN_RULES = load_domain_rules(os.environ.pop("PROXY_DOMAINS_FILE", ""))
NEEDS_UPSTREAM = DOMAIN_RULES is None or bool(DOMAIN_RULES)
UPSTREAM_HOST = os.environ.pop("UPSTREAM_SQUID_HOST", "")
upstream_port = os.environ.pop("UPSTREAM_SQUID_PORT", "")
UPSTREAM_PORT = None
if NEEDS_UPSTREAM:
    if not UPSTREAM_HOST or not upstream_port:
        raise SystemExit("UPSTREAM_SQUID_HOST and UPSTREAM_SQUID_PORT must be set")
    try:
        UPSTREAM_PORT = int(upstream_port)
        if not 1 <= UPSTREAM_PORT <= 65535:
            raise ValueError
    except ValueError:
        raise SystemExit("UPSTREAM_SQUID_PORT must be an integer from 1 to 65535") from None
del upstream_port
# Startup uses the same parser inside the image to validate configuration before
# prompting or replacing a working container. No host Python dependency is needed.
if __name__ == "__main__" and sys.argv[1:] == ["--check-config"]:
    print("proxy" if NEEDS_UPSTREAM else "direct")
    raise SystemExit(0)

USERNAME = PASSWORD = None
CLIENT_TOKEN = load_client_token()
if NEEDS_UPSTREAM:
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
    state.update(realm=None, nonce=None, qop=None, opaque=None, nc=0)
    scheme, separator, fields = header_val.partition(" ")
    if not separator or scheme.lower() != "digest":
        raise ValueError("Unsupported authentication scheme")
    params = {}
    position = 0
    while position < len(fields):
        match = DIGEST_PARAM.match(fields, position)
        if match is None:
            raise ValueError("Invalid Digest challenge")
        name = match[1].lower()
        if name in params:
            raise ValueError("Duplicate Digest parameter")
        params[name] = re.sub(r"\\(.)", r"\1", match[2]) if match[2] is not None else match[3]
        position = match.end()
    if params.get("algorithm", "MD5").upper() != "MD5":
        raise ValueError("Unsupported Digest algorithm; only MD5 is supported")
    if "auth" not in {value.strip().lower() for value in params.get("qop", "").split(",")}:
        raise ValueError("Digest challenge must offer qop=auth")
    if params.get("realm") is None or not params.get("nonce"):
        raise ValueError("Invalid Digest challenge")
    state.update(realm=params["realm"], nonce=params["nonce"], qop="auth", opaque=params.get("opaque"))


def quote_auth_value(value):
    if re.search(r"[\x00-\x1f\x7f]", value):
        raise ValueError("Invalid Digest field")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'

def build_auth_header(method: str, uri: str) -> str:
    if state["realm"] is None or state["nonce"] is None:
        return ""
    state["nc"] += 1
    nc_str = f"{state['nc']:08x}"
    cnonce = secrets.token_hex(8)

    ha1 = md5(f"{USERNAME}:{state['realm']}:{PASSWORD}")
    ha2 = md5(f"{method}:{uri}")

    resp = md5(f"{ha1}:{state['nonce']}:{nc_str}:{cnonce}:auth:{ha2}")
    hdr = (
        f'Digest username={quote_auth_value(USERNAME)}, realm={quote_auth_value(state["realm"])}, '
        f'nonce={quote_auth_value(state["nonce"])}, uri={quote_auth_value(uri)}, '
        f'algorithm=MD5, qop=auth, nc={nc_str}, cnonce="{cnonce}", response="{resp}"'
    )
    if state["opaque"] is not None:
        hdr += f', opaque={quote_auth_value(state["opaque"])}'
    return hdr


class HeaderTooLarge(ValueError):
    pass


async def read_headers(reader: asyncio.StreamReader):
    try:
        raw = await reader.readuntil(b"\r\n\r\n")
    except asyncio.LimitOverrunError:
        raise HeaderTooLarge("Headers exceed size limit") from None
    except asyncio.IncompleteReadError as error:
        raw = error.partial
    if len(raw) > MAX_HEADER_BYTES:
        raise HeaderTooLarge("Headers exceed size limit")
    return raw

async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
        # Preserve TCP half-close: a peer may finish sending before the response
        # has arrived. The handler closes both sockets after both pumps finish.
        if writer.can_write_eof():
            writer.write_eof()
            await writer.drain()
        else:
            writer.close()
    except OSError:
        writer.close()
    except asyncio.CancelledError:
        writer.close()
        raise

async def connect_upstream(target):
    writer = None
    try:
        reader, writer = await asyncio.open_connection(UPSTREAM_HOST, UPSTREAM_PORT, limit=MAX_HEADER_BYTES)
        for attempt in range(2):
            auth = build_auth_header("CONNECT", target)
            request = f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
            if auth:
                request += f"Proxy-Authorization: {auth}\r\n"
            writer.write((request + "\r\n").encode("latin-1"))
            await writer.drain()
            response = await read_headers(reader)
            # A truncated or malformed upstream response is a gateway failure.
            status = response.split(b"\r\n", 1)[0].split()
            if (not response.endswith(b"\r\n\r\n") or len(status) < 2 or
                    status[0] not in (b"HTTP/1.0", b"HTTP/1.1") or
                    len(status[1]) != 3 or not status[1].isdigit() or
                    not 100 <= int(status[1]) <= 599):
                raise ConnectionError("Invalid upstream proxy response")
            if status[1] != b"407" or attempt:
                return reader, writer, response, status[1] == b"200"
            challenge = next((line.split(b":", 1)[1].strip().decode("latin-1")
                              for line in response.split(b"\r\n")
                              if line.lower().startswith(b"proxy-authenticate:") and
                              line.split(b":", 1)[1].strip().lower().startswith(b"digest ")), None)
            if challenge is None:
                return reader, writer, response, False
            parse_auth_challenge(challenge)
            writer.close()
            await writer.wait_closed()
            reader, writer = await asyncio.open_connection(UPSTREAM_HOST, UPSTREAM_PORT, limit=MAX_HEADER_BYTES)
    except BaseException:
        if writer is not None:
            writer.close()
        raise


async def send_error(writer, status):
    writer.write(f"HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode("ascii"))
    await writer.drain()


def client_authenticated(request):
    values = []
    for line in request.split(b"\r\n")[1:]:
        name, separator, value = line.partition(b":")
        if separator and name.lower() == b"proxy-authorization":
            values.append(value.strip())
    if len(values) != 1:
        return False
    scheme, separator, encoded = values[0].partition(b" ")
    if not separator or scheme.lower() != b"basic":
        return False
    try:
        supplied = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        return False
    return hmac.compare_digest(supplied, b"bridge:" + CLIENT_TOKEN)


async def handle_client(c_reader: asyncio.StreamReader, c_writer: asyncio.StreamWriter):
    global active_clients
    if active_clients >= MAX_CLIENTS:
        c_writer.close()
        return
    # No await between admission and reservation; pending headers and established
    # tunnels both count toward the limit. Excess clients are closed immediately.
    active_clients += 1
    u_writer = None
    try:
        try:
            request = await asyncio.wait_for(read_headers(c_reader), CONNECT_TIMEOUT)
            if not request:
                return
            parts = request.split(b"\r\n", 1)[0].decode("latin-1").split(" ")
            if len(parts) != 3 or parts[2] not in ("HTTP/1.0", "HTTP/1.1") or not request.endswith(b"\r\n\r\n"):
                raise ValueError("Invalid request")
            if not client_authenticated(request):
                c_writer.write(b'HTTP/1.1 407 Proxy Authentication Required\r\n'
                               b'Proxy-Authenticate: Basic realm="Squid Digest Bridge"\r\n'
                               b'Content-Length: 0\r\nConnection: close\r\n\r\n')
                await c_writer.drain()
                return
            method, target, _ = parts
            if method.upper() != "CONNECT":
                await send_error(c_writer, "501 Not Implemented")
                return
            host, port = parse_connect_target(target)
        except HeaderTooLarge:
            await send_error(c_writer, "431 Request Header Fields Too Large")
            return
        except (ValueError, asyncio.TimeoutError):
            await send_error(c_writer, "400 Bad Request")
            return

        try:
            if should_proxy(host, DOMAIN_RULES):
                u_reader, u_writer, response, established = await asyncio.wait_for(
                    connect_upstream(target), CONNECT_TIMEOUT)
            else:
                u_reader, u_writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), CONNECT_TIMEOUT)
                response = b"HTTP/1.1 200 Connection established\r\n\r\n"
                established = True
        except asyncio.TimeoutError:
            await send_error(c_writer, "504 Gateway Timeout")
            return
        except (OSError, ValueError):
            await send_error(c_writer, "502 Bad Gateway")
            return

        c_writer.write(response)
        await c_writer.drain()
        if established:
            await asyncio.gather(pipe(c_reader, u_writer), pipe(u_reader, c_writer))
    except (OSError, ValueError):
        # The client may disconnect while its request is being handled.
        pass
    finally:
        active_clients -= 1
        if u_writer is not None:
            u_writer.close()
        c_writer.close()


async def main():
    server = await asyncio.start_server(handle_client, "0.0.0.0", 8080, limit=MAX_HEADER_BYTES)
    mode = "all via Squid" if DOMAIN_RULES is None else f"{len(DOMAIN_RULES)} proxy domain rules"
    logging.info("Digest Bridge listening on :8080 (%s)", mode)
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
