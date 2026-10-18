"""Stateful CLI fixture; executed as podman/docker by test_runtime.py."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

assert "PROXY_DIGEST_USER" not in os.environ
assert "PROXY_DIGEST_PASS" not in os.environ
root = Path(os.environ["TEST_CAPTURE_DIR"])
args = sys.argv[1:]
engine = Path(sys.argv[0]).name
with (root / "calls").open("a") as log:
    log.write(json.dumps([engine, args]) + "\n")
while args and args[0].startswith("--"):
    option = args.pop(0)
    if "=" not in option:
        args.pop(0)

model_file = root / "model.json"
model = json.loads(model_file.read_text()) if model_file.exists() else {"volumes": [], "container": None}


def save():
    model_file.write_text(json.dumps(model))


def fail(stage):
    if os.environ.get("TEST_FAIL") == stage:
        sys.exit(1)


def option(name):
    return args[args.index(name) + 1]


if args[:2] == ["network", "inspect"]:
    fail("network-inspect")
    network_file = root / "networks.json"
    networks = json.loads(network_file.read_text()) if network_file.exists() else {}
    if args[-1] not in networks:
        sys.exit(1)
    if "--format" in args:
        print(networks[args[-1]])
elif args[:2] == ["network", "create"]:
    fail("network")
    network_file = root / "networks.json"
    networks = json.loads(network_file.read_text()) if network_file.exists() else {}
    if args[-1] in networks:
        sys.exit(1)
    networks[args[-1]] = option("--label").split("=", 1)[1]
    network_file.write_text(json.dumps(networks))
elif args[:3] == ["system", "connection", "list"]:
    print(os.environ.get("TEST_PODMAN_CONNECTION", "podman-machine-default"))
elif args == ["context", "show"]:
    print(os.environ.get("DOCKER_CONTEXT") or os.environ.get("TEST_DOCKER_CONTEXT", "desktop-linux"))
elif args == ["context", "inspect", "orbstack"]:
    sys.exit(0 if os.environ.get("TEST_ORBSTACK_CONTEXT") else 1)
elif args == ["info"]:
    fail("info")
elif args[:2] == ["image", "inspect"]:
    if os.environ.get("TEST_IMAGE_MISSING"):
        sys.exit(1)
elif args[0] == "pull":
    fail("pull")
elif args[:2] == ["secret", "create"]:
    assert engine == "podman"
    (root / "secret").write_bytes(sys.stdin.buffer.read())
elif args[:2] == ["container", "ls"]:
    fail("list")
    if model["container"]:
        print("squid-digest-bridge")
elif args[0] == "inspect":
    assert model["container"]
    label = "credentials" if "credentials" in option("--format") else "managed"
    print(model["container"][label])
elif args[:2] == ["volume", "create"]:
    fail("volume")
    name = args[-1]
    model["volumes"].append(name)
    (root / name).mkdir()
    save()
    print(name)
elif args[:2] == ["volume", "rm"]:
    name = args[-1]
    if model["container"] and model["container"]["credentials"] == name:
        sys.exit(1)
    model["volumes"].remove(name)
    shutil.rmtree(root / name)
    save()
elif args[0] == "run":
    if args[-1] == 'import secrets; print(secrets.token_urlsafe(32))':
        print("test-client-token-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
    elif "--check-client-token" in args:
        mounts = dict(value.rsplit(":", 2)[1::-1] for i, value in enumerate(args) if i and args[i - 1] == "--volume")
        code = Path(mounts["/app/bridge.py"]).read_text().replace("/run/secrets/bridge_client_token", mounts["/run/secrets/bridge_client_token"])
        subprocess.run([sys.executable, "-c", code, "--check-client-token"], check=True)
    elif "--check-config" in args:
        fail("config")
        settings = dict(value.split("=", 1) for i, value in enumerate(args) if i and args[i - 1] == "--env")
        mounts = dict(value.rsplit(":", 2)[1::-1] for i, value in enumerate(args) if i and args[i - 1] == "--volume")
        settings["PROXY_DOMAINS_FILE"] = mounts[settings["PROXY_DOMAINS_FILE"]]
        subprocess.run([sys.executable, mounts["/app/bridge.py"], "--check-config"],
                       env=dict(os.environ, **settings), check=True)
    elif "--interactive" in args:
        fail("helper")
        name = option("--mount").split("source=", 1)[1].split(",", 1)[0]
        # Execute the real credential-writer code with only its mount path mapped
        # into the fixture, so byte preservation and file permissions are tested.
        code = args[-1].replace("/run/secrets/", str(root / name) + "/")
        subprocess.run([sys.executable, "-c", code], input=sys.stdin.buffer.read(), check=True)
    else:
        if engine == "docker":
            assert "--replace" not in args and "--secret" not in args
            assert not any(value.endswith(":ro,Z") for value in args)
        labels = dict(value.split("=", 1) for i, value in enumerate(args) if i and args[i - 1] == "--label")
        model["container"] = {
            "managed": labels["io.squid-digest-bridge.managed"],
            "credentials": labels.get("io.squid-digest-bridge.credentials", ""),
            "args": args,
            "stopped": False,
        }
        save()
        fail("run")
        print("fake-container-id")
elif args[0] == "rm":
    if args[-1] == "squid-digest-bridge":
        fail("remove")
        model["container"] = None
        save()
elif args[0] == "stop":
    fail("stop")
    if not model["container"]:
        sys.exit(1)
    model["container"]["stopped"] = True
    save()
else:
    raise SystemExit(f"Unexpected CLI arguments: {args}")
