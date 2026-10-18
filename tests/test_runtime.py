import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
USERNAME = " test user "
PASSWORD = "test password $ \\\n\r\n "


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name in ("startup.sh", "shutdown.sh", "runtime.sh", "bridge.py"):
            shutil.copy2(ROOT / name, self.root / name)
        # A controlled PATH makes engine detection independent of the host.
        for name in ("dirname", "cat", "mktemp", "mv", "rm", "chmod"):
            (self.bin / name).symlink_to(shutil.which(name))
        uname = self.bin / "uname"
        uname.write_text('#!/bin/bash\nprintf "%s\\n" "${TEST_OS:-Linux}"\n')
        uname.chmod(0o700)
        self.env = {
            "PATH": str(self.bin), "HOME": str(self.root),
            "TEST_CAPTURE_DIR": str(self.root),
            "UPSTREAM_SQUID_HOST": "upstream.example.com", "UPSTREAM_SQUID_PORT": "3128",
            "PROXY_DIGEST_USER": USERNAME, "PROXY_DIGEST_PASS": PASSWORD,
        }

    def install(self, engine):
        executable = self.bin / engine
        executable.write_text(f"#!{sys.executable}\n" + (ROOT / "tests/fake_runtime.py").read_text())
        executable.chmod(0o700)

    def run_script(self, name="startup.sh", success=True, **settings):
        result = subprocess.run(
            ["/bin/bash", str(self.root / name)],
            env=dict(self.env, **settings), capture_output=True, text=True,
        )
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(USERNAME, result.stdout + result.stderr)
        self.assertNotIn(PASSWORD, result.stdout + result.stderr)
        return result

    def calls(self):
        path = self.root / "calls"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def model(self):
        return json.loads((self.root / "model.json").read_text())

    def test_missing_engines_show_platform_help_before_configuration(self):
        self.env.pop("UPSTREAM_SQUID_HOST")
        self.env.pop("UPSTREAM_SQUID_PORT")
        for system, heading in (("Darwin", "macOS:"), ("MINGW64_NT", "Windows:"),
                                ("MSYS_NT", "Windows:"), ("CYGWIN_NT", "Windows:"),
                                ("Windows_NT", "Windows:"), ("Linux", "Linux:"), ("FreeBSD", None)):
            with self.subTest(system=system):
                result = self.run_script(success=False, TEST_OS=system)
                self.assertEqual(result.returncode, 127)
                self.assertIn("Podman or Docker is not installed", result.stderr)
                for platform in ("macOS:", "Windows:", "Linux:"):
                    self.assertEqual(platform in result.stderr, platform == heading)
                self.assertIn("https://podman.io/docs/installation", result.stderr)
                self.assertIn("./startup.sh again", result.stderr)
                self.assertNotIn("command not found", result.stderr)
                self.assertNotIn("Proxy username:", result.stderr)

    def test_auto_falls_back_to_podman_and_preserves_native_secret(self):
        self.install("podman")
        self.run_script()
        self.assertTrue(all(engine == "podman" for engine, _ in self.calls()))
        self.assertEqual((self.root / "secret").read_bytes(), (USERNAME + "\0" + PASSWORD).encode())
        args = self.model()["container"]["args"]
        self.assertIn("--replace", args)
        self.assertIn("source=squid-digest-bridge-credentials,type=mount,target=proxy_digest_credentials,mode=0400", args)
        self.assertIn(str(self.root / "bridge.py") + ":/app/bridge.py:ro,Z", args)

    def test_auto_falls_back_to_docker_with_protected_credentials(self):
        self.install("docker")
        self.install("podman")
        self.run_script()
        self.assertTrue(all(engine == "docker" for engine, _ in self.calls()))
        model = self.model()
        volume = model["container"]["credentials"]
        secret = self.root / volume / "proxy_digest_credentials"
        self.assertEqual(secret.read_bytes(), (USERNAME + "\0" + PASSWORD).encode())
        self.assertEqual(stat.S_IMODE(secret.stat().st_mode), 0o400)
        args = model["container"]["args"]
        self.assertIn(f"type=volume,source={volume},target=/run/secrets,readonly", args)
        self.assertIn("127.0.0.1:8080:8080", args)
        self.assertIn("unless-stopped", args)
        self.assertNotIn(USERNAME, (self.root / "calls").read_text())
        self.assertNotIn(PASSWORD, (self.root / "calls").read_text())
        self.assertNotIn(USERNAME, (self.root / ".bridge-runtime").read_text())
        self.assertEqual(stat.S_IMODE((self.root / ".bridge-runtime").stat().st_mode), 0o600)

    def test_auto_prefers_orbstack_over_docker_and_podman(self):
        self.install("docker")
        self.install("podman")
        self.run_script(TEST_ORBSTACK_CONTEXT="1", DOCKER_CONTEXT="desktop-linux", DOCKER_HOST="unix:///ignored")
        self.assertEqual(self.calls()[0], ["docker", ["context", "inspect", "orbstack"]])
        self.assertTrue(all(engine == "docker" and args[:2] == ["--context", "orbstack"]
                            for engine, args in self.calls()[1:]))

    def test_explicit_docker_bypasses_orbstack_preference(self):
        self.install("docker")
        self.run_script(CONTAINER_RUNTIME="docker", TEST_ORBSTACK_CONTEXT="1", DOCKER_CONTEXT="desktop-linux")
        self.assertFalse(any(args == ["context", "inspect", "orbstack"] for _, args in self.calls()))
        self.assertTrue(all(args[:2] == ["--context", "desktop-linux"]
                            for _, args in self.calls() if args != ["context", "show"]))

    def test_orbstack_uses_context_without_changing_global_selection(self):
        self.install("docker")
        self.install("podman")
        self.run_script(CONTAINER_RUNTIME="orbstack", DOCKER_CONTEXT="desktop-linux", DOCKER_HOST="unix:///ignored")
        self.assertTrue(all(engine == "docker" and args[:2] == ["--context", "orbstack"]
                            for engine, args in self.calls()))

    def test_settings_are_literal_allowlisted_and_exports_take_precedence(self):
        self.install("docker")
        (self.root / ".env").write_text(
            "UPSTREAM_SQUID_HOST=file.example.com\r\nUPSTREAM_SQUID_PORT=4567\r\n"
            "CONTAINER_RUNTIME=orbstack\r\nPROXY_DIGEST_USER=ignored\nPROXY_DIGEST_PASS=ignored\n"
            "UNKNOWN=$(touch unexpected)\n"
        )
        del self.env["UPSTREAM_SQUID_HOST"]
        del self.env["UPSTREAM_SQUID_PORT"]
        self.run_script()
        args = self.model()["container"]["args"]
        self.assertIn("UPSTREAM_SQUID_HOST=file.example.com", args)
        self.assertIn("UPSTREAM_SQUID_PORT=4567", args)
        self.assertFalse((self.root / "unexpected").exists())
        self.run_script("shutdown.sh")
        self.run_script(CONTAINER_RUNTIME="docker", UPSTREAM_SQUID_HOST="override.example.com", UPSTREAM_SQUID_PORT="5678")
        args = self.model()["container"]["args"]
        self.assertIn("UPSTREAM_SQUID_HOST=override.example.com", args)
        self.assertIn("UPSTREAM_SQUID_PORT=5678", args)

    def test_invalid_runtime_and_missing_explicit_engine_do_not_fall_back(self):
        self.install("podman")
        self.assertIn("CONTAINER_RUNTIME must be", self.run_script(success=False, CONTAINER_RUNTIME="unknown").stderr)
        result = self.run_script(success=False, CONTAINER_RUNTIME="docker")
        self.assertEqual(result.returncode, 127)
        self.assertEqual(self.calls(), [])

    def test_unavailable_preferred_engine_does_not_fall_back_or_prompt(self):
        self.install("podman")
        self.install("docker")
        for orbstack, preferred in (("", "docker"), ("1", "orbstack")):
            with self.subTest(preferred=preferred):
                result = self.run_script(success=False, TEST_FAIL="info", TEST_ORBSTACK_CONTEXT=orbstack,
                                         PROXY_DIGEST_USER="", PROXY_DIGEST_PASS="")
                self.assertIn(f"Cannot connect to {preferred}", result.stderr)
                self.assertNotIn("Proxy username:", result.stderr)
                self.assertTrue(all(engine == "docker" for engine, _ in self.calls()))

    def test_rotation_removes_old_volume_after_start_and_stop_retains_new_one(self):
        self.install("docker")
        self.run_script()
        old_volume = self.model()["container"]["credentials"]
        self.run_script(PROXY_DIGEST_PASS="replacement")
        model = self.model()
        volume = model["container"]["credentials"]
        self.assertNotEqual(old_volume, volume)
        self.assertEqual(model["volumes"], [volume])
        self.assertEqual((self.root / volume / "proxy_digest_credentials").read_bytes(), (USERNAME + "\0replacement").encode())
        self.run_script("shutdown.sh")
        self.assertEqual(self.model()["volumes"], [volume])
        self.assertTrue(self.model()["container"]["stopped"])
        self.assertFalse((self.root / ".bridge-runtime").exists())

    def test_failed_preparation_keeps_existing_container_and_credentials(self):
        self.install("docker")
        self.run_script()
        before = self.model()
        state = (self.root / ".bridge-runtime").read_text()
        for stage in ("pull", "list", "volume", "helper", "remove"):
            with self.subTest(stage=stage):
                self.run_script(success=False, TEST_FAIL=stage, TEST_IMAGE_MISSING="1")
                self.assertEqual(self.model(), before)
                self.assertEqual((self.root / ".bridge-runtime").read_text(), state)
                self.assertEqual(list(self.root.glob(".bridge-runtime.*")), [])

    def test_failed_run_cleans_new_container_and_volume(self):
        self.install("docker")
        self.run_script(success=False, TEST_FAIL="run")
        self.assertEqual(self.model(), {"container": None, "volumes": []})
        self.assertFalse((self.root / ".bridge-runtime").exists())

    def test_unmanaged_container_is_not_replaced(self):
        self.install("docker")
        (self.root / "model.json").write_text(json.dumps({"volumes": [], "container": {"managed": "", "credentials": ""}}))
        result = self.run_script(success=False)
        self.assertIn("refusing to replace", result.stderr)
        self.assertFalse(any("rm" in args for _, args in self.calls()))

    def test_shutdown_and_auto_restart_reuse_recorded_docker_context(self):
        self.install("docker")
        self.run_script(TEST_DOCKER_CONTEXT="original-context")
        self.install("podman")
        start = len(self.calls())
        self.run_script(DOCKER_CONTEXT="different-context")
        self.run_script("shutdown.sh", CONTAINER_RUNTIME="podman", DOCKER_CONTEXT="different-context")
        self.assertTrue(all(engine == "docker" and args[:2] == ["--context", "original-context"]
                            for engine, args in self.calls()[start:]))

    def test_docker_host_and_tls_are_recorded_for_shutdown(self):
        self.install("docker")
        self.run_script(DOCKER_HOST="tcp://localhost:2376", DOCKER_TLS_VERIFY="1", DOCKER_CERT_PATH="/tmp/cert path")
        state = (self.root / ".bridge-runtime").read_text()
        self.assertIn("runtime_tls_verify=1", state)
        self.assertIn("runtime_cert_path=/tmp/cert path", state)
        start = len(self.calls())
        self.run_script("shutdown.sh", DOCKER_HOST="unix:///different", DOCKER_CONTEXT="different-context")
        self.assertTrue(all(args[:2] == ["--host", "tcp://localhost:2376"] for _, args in self.calls()[start:]))

    def test_podman_default_connection_is_recorded_on_macos(self):
        self.install("podman")
        self.run_script(TEST_OS="Darwin", TEST_PODMAN_CONNECTION="machine-one")
        start = len(self.calls())
        self.run_script("shutdown.sh", CONTAINER_CONNECTION="machine-two", CONTAINER_HOST="unix:///different")
        self.assertTrue(all(args[:2] == ["--connection", "machine-one"] for _, args in self.calls()[start:]))

    def test_switch_requires_shutdown_first(self):
        self.install("docker")
        self.install("podman")
        self.run_script(CONTAINER_RUNTIME="docker")
        before = self.model()
        result = self.run_script(success=False, CONTAINER_RUNTIME="podman")
        self.assertIn("Run ./shutdown.sh before switching", result.stderr)
        self.assertEqual(self.model(), before)

    def test_failed_stop_retains_recorded_target(self):
        self.install("docker")
        self.run_script()
        self.run_script("shutdown.sh", success=False, TEST_FAIL="stop")
        self.assertTrue((self.root / ".bridge-runtime").exists())

    def test_state_file_is_not_executed_as_shell(self):
        self.install("docker")
        (self.root / ".bridge-runtime").write_text("$(touch unexpected)\n")
        self.run_script("shutdown.sh", success=False)
        self.assertFalse((self.root / "unexpected").exists())
        self.assertEqual(self.calls(), [])

    def test_empty_policy_skips_upstream_and_credentials_on_every_runtime(self):
        self.install("docker")
        self.install("podman")
        (self.root / "empty domains.txt").write_text("# direct only\n\n")
        (self.root / ".env").write_text("PROXY_DOMAINS_FILE=empty domains.txt\n")
        del self.env["UPSTREAM_SQUID_HOST"]
        del self.env["UPSTREAM_SQUID_PORT"]
        self.env["PROXY_DIGEST_USER"] = ""
        self.env["PROXY_DIGEST_PASS"] = ""
        for kind in ("podman", "docker", "orbstack"):
            with self.subTest(kind=kind):
                start = len(self.calls())
                self.run_script(CONTAINER_RUNTIME=kind)
                args = self.model()["container"]["args"]
                self.assertIn("PROXY_DOMAINS_FILE=/app/proxy-domains.txt", args)
                suffix = ":ro,z" if kind == "podman" else ":ro"
                self.assertIn(str(self.root / "empty domains.txt") + ":/app/proxy-domains.txt" + suffix, args)
                self.assertFalse(any("UPSTREAM_SQUID_" in value for value in args))
                self.assertNotIn("--secret", args)
                self.assertNotIn("--mount", args)
                self.assertFalse(any("secret" in values or "--interactive" in values or values[:2] == ["volume", "create"]
                                     for _, values in self.calls()[start:]))
                self.run_script("shutdown.sh")

    def test_nonempty_policy_mounts_rules_and_still_creates_credentials(self):
        self.install("docker")
        path = self.root / "domains.txt"
        path.write_text("example.com\n.example.net\n")
        self.run_script(PROXY_DOMAINS_FILE=str(path))
        args = self.model()["container"]["args"]
        self.assertIn("PROXY_DOMAINS_FILE=/app/proxy-domains.txt", args)
        self.assertIn("UPSTREAM_SQUID_HOST=upstream.example.com", args)
        self.assertTrue(self.model()["container"]["credentials"])

    def test_bad_policy_leaves_existing_container_and_credentials_untouched(self):
        self.install("docker")
        self.run_script()
        before = self.model()
        path = self.root / "domains.txt"
        for content in (None, "*.example.com", "acl domains dstdomain .example.com", "example.com:443"):
            with self.subTest(content=content):
                if content is not None:
                    path.write_text(content)
                start = len(self.calls())
                self.run_script(success=False, PROXY_DOMAINS_FILE=str(path), PROXY_DIGEST_USER="", PROXY_DIGEST_PASS="")
                self.assertEqual(self.model(), before)
                self.assertFalse(any("secret" in values or "--interactive" in values or "rm" in values
                                     for _, values in self.calls()[start:]))

    def test_empty_policy_override_takes_precedence_over_env_file(self):
        self.install("docker")
        (self.root / ".env").write_text("PROXY_DOMAINS_FILE=missing.txt\n")
        (self.root / "empty.txt").write_text("")
        self.run_script(PROXY_DOMAINS_FILE=str(self.root / "empty.txt"))
        self.assertEqual(self.model()["volumes"], [])

    def test_switching_to_direct_only_removes_old_docker_credential_volume(self):
        self.install("docker")
        self.run_script()
        old_volume = self.model()["container"]["credentials"]
        (self.root / "empty.txt").write_text("")
        self.run_script(PROXY_DOMAINS_FILE=str(self.root / "empty.txt"), PROXY_DIGEST_USER="", PROXY_DIGEST_PASS="")
        self.assertEqual(self.model()["volumes"], [])
        self.assertFalse((self.root / old_volume).exists())
        self.run_script()
        self.assertEqual(len(self.model()["volumes"]), 1)

    def test_failed_direct_only_launch_is_cleaned_up(self):
        self.install("docker")
        (self.root / "empty.txt").write_text("")
        self.run_script(success=False, TEST_FAIL="run", PROXY_DOMAINS_FILE=str(self.root / "empty.txt"))
        self.assertEqual(self.model(), {"container": None, "volumes": []})
        self.assertFalse((self.root / ".bridge-runtime").exists())

    def test_bridge_uses_a_dedicated_network_on_all_runtimes(self):
        self.install("podman")
        self.install("docker")
        for kind in ("podman", "docker", "orbstack"):
            with self.subTest(kind=kind):
                start = len(self.calls())
                self.run_script(CONTAINER_RUNTIME=kind)
                args = self.model()["container"]["args"]
                self.assertEqual(args[args.index("--network") + 1], "squid-digest-bridge-network")
                self.assertEqual(json.loads((self.root / "networks.json").read_text()),
                                 {"squid-digest-bridge-network": "true"})
                self.run_script("shutdown.sh")

    def test_unmanaged_network_is_refused_before_creating_credentials(self):
        self.install("docker")
        (self.root / "networks.json").write_text(json.dumps({"squid-digest-bridge-network": ""}))
        result = self.run_script(success=False, PROXY_DIGEST_USER="", PROXY_DIGEST_PASS="")
        self.assertIn("refusing to use", result.stderr)
        self.assertFalse(any("secret" in args or "--interactive" in args for _, args in self.calls()))

    def test_network_creation_failure_keeps_the_existing_container(self):
        self.install("docker")
        self.run_script()
        before = self.model()
        (self.root / "networks.json").unlink()
        self.run_script(success=False, TEST_FAIL="network", PROXY_DIGEST_USER="", PROXY_DIGEST_PASS="")
        self.assertEqual(self.model(), before)

    def test_client_token_is_private_persistent_and_not_in_cli_arguments(self):
        self.install("docker")
        self.run_script()
        path = self.root / ".bridge-client-token"
        token = path.read_text().strip()
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertNotIn(token, (self.root / "calls").read_text())
        self.assertIn(str(path) + ":/run/secrets/bridge_client_token:ro", self.model()["container"]["args"])
        self.run_script()
        self.assertEqual(path.read_text().strip(), token)

    def test_invalid_client_token_fails_before_replacing_the_container(self):
        self.install("docker")
        self.run_script()
        before = self.model()
        (self.root / ".bridge-client-token").write_text("invalid")
        result = self.run_script(success=False)
        self.assertIn("Invalid local client token", result.stderr)
        self.assertEqual(self.model(), before)


if __name__ == "__main__":
    unittest.main()
