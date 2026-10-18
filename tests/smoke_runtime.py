"""Opt-in live test: python3 tests/smoke_runtime.py podman|docker|orbstack.

Uses dummy credentials, an in-container Digest proxy, a temporary repository
copy, a unique container name, and a spare localhost port. No external proxy
or HTTPS service is contacted.
"""
import json
import base64
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import uuid


ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = r'''
import hashlib
import re
import socketserver
import threading

class SmokeProxy(socketserver.StreamRequestHandler):
    def handle(self):
        request = self.rfile.readline().decode("ascii")
        headers = {}
        while True:
            line = self.rfile.readline()
            if line in (b"\r\n", b""):
                break
            key, value = line.decode("ascii").split(":", 1)
            headers[key.lower()] = value.strip()
        auth = headers.get("proxy-authorization", "")
        if not auth:
            self.wfile.write(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Digest realm="smoke", nonce="smoke-nonce", qop="auth"\r\nContent-Length: 0\r\n\r\n')
            return
        fields = {key: quoted or plain for key, quoted, plain in
                  re.findall(r'(\w+)=(?:"([^"]*)"|([^,\s]+))', auth)}
        md5 = lambda value: hashlib.md5(value.encode()).hexdigest()
        ha1 = md5("smoke-user:smoke:smoke-password")
        ha2 = md5("CONNECT:" + request.split()[1])
        expected = md5(ha1 + ":smoke-nonce:" + fields["nc"] + ":" + fields["cnonce"] + ":auth:" + ha2)
        if (fields.get("username") != "smoke-user" or fields.get("response") != expected
                or request.split()[1] != "smoke.example:443"):
            self.wfile.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            return
        self.wfile.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        self.wfile.flush()
        while True:
            payload = self.connection.recv(4096)
            if not payload:
                break
            self.connection.sendall(payload)

class DirectEcho(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            payload = self.request.recv(4096)
            if not payload:
                break
            self.request.sendall(b"direct:" + payload)

class AfterEOF(socketserver.BaseRequestHandler):
    def handle(self):
        payload = b""
        while True:
            piece = self.request.recv(4096)
            if not piece:
                break
            payload += piece
        self.request.sendall(b"after-eof:" + payload)

class SmokeServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

smoke_server = SmokeServer(("127.0.0.1", 3128), SmokeProxy)
threading.Thread(target=smoke_server.serve_forever, daemon=True).start()
direct_server = SmokeServer(("127.0.0.1", 3130), DirectEcho)
threading.Thread(target=direct_server.serve_forever, daemon=True).start()
after_eof_server = SmokeServer(("127.0.0.1", 3131), AfterEOF)
threading.Thread(target=after_eof_server.serve_forever, daemon=True).start()
'''


def main(kind):
    if kind not in ("podman", "docker", "orbstack"):
        raise SystemExit("Expected podman, docker, or orbstack")
    name = "squid-digest-bridge-smoke-" + uuid.uuid4().hex[:12]
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix="bridge-smoke-") as directory:
        root = Path(directory)
        for filename in ("startup.sh", "shutdown.sh", "runtime.sh"):
            source = (ROOT / filename).read_text().replace("squid-digest-bridge", name)
            source = source.replace("127.0.0.1:8080:8080", f"127.0.0.1:{port}:8080")
            (root / filename).write_text(source)
        (root / "bridge.py").write_text(UPSTREAM + (ROOT / "bridge.py").read_text())
        (root / "domains.txt").write_text("smoke.example\n")
        env = dict(os.environ, CONTAINER_RUNTIME=kind,
                   UPSTREAM_SQUID_HOST="127.0.0.1", UPSTREAM_SQUID_PORT="3128",
                   PROXY_DOMAINS_FILE=str(root / "domains.txt"),
                   PROXY_DIGEST_USER="smoke-user", PROXY_DIGEST_PASS="smoke-password")

        def script(filename):
            result = subprocess.run(["/bin/bash", filename], cwd=root, env=env,
                                    capture_output=True, text=True)
            if result.returncode:
                print(result.stderr, file=sys.stderr)
                result.check_returncode()
            return result.stdout

        def runtime(*args, check=True):
            clean_env = {key: value for key, value in env.items() if not key.startswith("PROXY_DIGEST_")}
            result = subprocess.run(
                ["/bin/bash", "-c", 'set -euo pipefail; source ./runtime.sh; '
                 'if [ -f "$state_file" ]; then load_runtime_state; else select_runtime; fi; runtime "$@"',
                 "smoke", *args], cwd=root, env=clean_env, capture_output=True, text=True,
            )
            if check and result.returncode:
                print(result.stderr, file=sys.stderr)
                result.check_returncode()
            return result.stdout

        def probe(target="smoke.example:443", expected=b"smoke tunnel payload", status=b"200", half_close=False, authenticated=True):
            deadline = time.monotonic() + 20
            while True:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
                        auth = b""
                        if authenticated:
                            token = (root / ".bridge-client-token").read_bytes().strip()
                            auth = b"Proxy-Authorization: Basic " + base64.b64encode(b"bridge:" + token) + b"\r\n"
                        connection.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n".encode() + auth + b"\r\n")
                        headers = b""
                        while not headers.endswith(b"\r\n\r\n"):
                            piece = connection.recv(1)
                            if not piece:
                                raise ConnectionError("Bridge closed connection")
                            headers += piece
                        assert headers.startswith(b"HTTP/1.1 " + status), headers
                        if status != b"200":
                            return
                        connection.sendall(b"smoke tunnel payload")
                        if half_close:
                            connection.shutdown(socket.SHUT_WR)
                        received = b""
                        while len(received) < len(expected):
                            piece = connection.recv(4096)
                            if not piece:
                                raise ConnectionError("Tunnel closed early")
                            received += piece
                        assert received == expected
                    return
                except (OSError, ConnectionError):
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.2)

        try:
            script("startup.sh")
            probe()
            probe(status=b"407", authenticated=False)
            inspected = json.loads(runtime("inspect", name))[0]
            bridge_ip = inspected["NetworkSettings"]["Networks"][name + "-network"]["IPAddress"]
            runtime("network", "create", name + "-peer-network")
            # Positive control on the bridge's own network, followed by probes
            # from an unrelated network and the engine's default network.
            network_probe = r'''
import socket, sys
try:
    connection = socket.create_connection((sys.argv[1], 8080), timeout=2)
except OSError:
    if sys.argv[2] == "allowed":
        raise
else:
    if sys.argv[2] == "blocked":
        connection.sendall(b"CONNECT smoke.example:443 HTTP/1.1\r\n\r\n")
        response = connection.recv(4096)
        if not response.startswith(b"HTTP/1.1 407 "):
            raise SystemExit("Unrelated container can use the bridge without its client token")
    connection.close()
'''
            for network, expected in ((name + "-network", "allowed"),
                                      (name + "-peer-network", "blocked"),
                                      ("podman" if kind == "podman" else "bridge", "blocked")):
                runtime("run", "--rm", "--name", name + "-peer", "--network", network,
                        "docker.io/library/python:3.12-alpine", "python", "-c", network_probe, bridge_ip, expected)
            probe("127.0.0.1:3130", b"direct:smoke tunnel payload")
            probe("127.0.0.1:3131", b"after-eof:smoke tunnel payload", half_close=True)
            probe("smoke.example:3130", status=b"403")
            probe("127.0.0.1:1", status=b"502")
            inspected = runtime("inspect", name)
            assert "smoke-password" not in inspected and "smoke-user" not in inspected
            environment = runtime("exec", name, "env")
            assert "PROXY_DIGEST_" not in environment
            runtime("restart", name)
            probe()
            probe("127.0.0.1:3130", b"direct:smoke tunnel payload")
            script("startup.sh")
            probe()
            # Recreate in direct-only mode with no upstream configuration/credentials.
            (root / "domains.txt").write_text("# all direct\n")
            for key in ("UPSTREAM_SQUID_HOST", "UPSTREAM_SQUID_PORT", "PROXY_DIGEST_USER", "PROXY_DIGEST_PASS"):
                env.pop(key, None)
            script("startup.sh")
            probe("127.0.0.1:3130", b"direct:smoke tunnel payload")
            probe("127.0.0.1:3131", b"after-eof:smoke tunnel payload", half_close=True)
            inspected = json.loads(runtime("inspect", name))[0]
            assert not any("credentials" in mount["Destination"] or mount["Destination"] == "/run/secrets"
                           for mount in inspected["Mounts"])
            script("shutdown.sh")
            assert json.loads(runtime("inspect", name))[0]["State"]["Running"] is False
            print(f"PASS {kind}: local and peer-container authentication, Digest and direct tunnels, strict routing failures, restart, replacement, direct-only startup without corporate credentials, shutdown")
        finally:
            runtime("rm", "--force", name + "-peer", check=False)
            runtime("rm", "--force", name, check=False)
            if kind == "podman":
                runtime("secret", "rm", name + "-credentials", check=False)
            else:
                volumes = runtime("volume", "ls", "--filter", f"label=io.{name}.managed=true", "--format", "{{.Name}}", check=False)
                for volume in volumes.splitlines():
                    runtime("volume", "rm", volume, check=False)
            runtime("network", "rm", name + "-peer-network", check=False)
            runtime("network", "rm", name + "-network", check=False)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) == 2 else "")
