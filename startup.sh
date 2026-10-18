#!/bin/bash
set -euo pipefail

if ! command -v podman >/dev/null 2>&1; then
    printf '%s\n' 'Error: Podman is not installed or is not available on PATH.' >&2
    case "$(uname -s 2>/dev/null || printf unknown)" in
        Darwin)
            printf '%s\n' '
  macOS:
    Download and run the macOS installer from:
    https://podman.io/docs/installation#macos
    Then run: podman machine init
              podman machine start' >&2
            ;;
        MINGW*|MSYS*|CYGWIN*|Windows_NT)
            printf '%s\n' '
  Windows:
    Install Podman using the Windows setup guide:
    https://podman.io/docs/installation#windows
    Then run in PowerShell: podman machine init
                            podman machine start
    Run startup.sh from a Bash shell (for example, Git Bash).
    Make sure podman is available on PATH in that shell.' >&2
            ;;
        Linux)
            printf '%s\n' '
  Linux:
    Ubuntu/Debian: sudo apt-get update && sudo apt-get install podman
    Fedora:        sudo dnf install podman
    Arch Linux:    sudo pacman -S podman
    Other distributions: https://podman.io/docs/installation#installing-on-linux' >&2
            ;;
        *)
            printf '\nInstall Podman for your operating system: https://podman.io/docs/installation\n' >&2
            ;;
    esac
    printf '%s\n' '
Open a new terminal after installation and verify with: podman info
Then run ./startup.sh again.' >&2
    exit 127
fi

cd -- "$(dirname -- "$0")"
# Load only upstream settings; credentials still come from the caller or terminal.
# Exported settings take precedence over .env. Values are literal and unquoted.
if [ -f .env ]; then
    while IFS='=' read -r name value || [ -n "$name" ]; do
        value=${value%$'\r'}
        case "$name" in
            UPSTREAM_SQUID_HOST) UPSTREAM_SQUID_HOST=${UPSTREAM_SQUID_HOST-$value} ;;
            UPSTREAM_SQUID_PORT) UPSTREAM_SQUID_PORT=${UPSTREAM_SQUID_PORT-$value} ;;
        esac
    done < .env
fi
: "${UPSTREAM_SQUID_HOST:?Set UPSTREAM_SQUID_HOST in .env or export it}"
: "${UPSTREAM_SQUID_PORT:?Set UPSTREAM_SQUID_PORT in .env or export it}"

# Read credentials only from the caller or terminal, never from .env.
if [ -z "${PROXY_DIGEST_USER:-}" ]; then
    if ! read -r -p 'Proxy username: ' PROXY_DIGEST_USER </dev/tty; then
        printf '\nUnable to read username; export PROXY_DIGEST_USER for non-interactive startup.\n' >&2
        exit 1
    fi
fi
: "${PROXY_DIGEST_USER:?Username must not be empty}"
if [ -z "${PROXY_DIGEST_PASS:-}" ]; then
    if ! read -r -s -p 'Proxy password: ' PROXY_DIGEST_PASS </dev/tty; then
        printf '\nUnable to read password; export PROXY_DIGEST_PASS for non-interactive startup.\n' >&2
        exit 1
    fi
    printf '\n' >/dev/tty
fi
: "${PROXY_DIGEST_PASS:?Password must not be empty}"
proxy_username=$PROXY_DIGEST_USER
proxy_password=$PROXY_DIGEST_PASS
unset PROXY_DIGEST_USER PROXY_DIGEST_PASS

# Send credentials through stdin, without exporting them or putting them in
# command arguments. The NUL separator preserves spaces and newlines exactly.
printf '%s\0%s' "$proxy_username" "$proxy_password" |
    podman secret create --replace squid-digest-bridge-credentials - >/dev/null
unset proxy_username proxy_password

exec podman run --detach --replace \
    --name squid-digest-bridge \
    --restart unless-stopped \
    --publish 127.0.0.1:8080:8080 \
    --env "UPSTREAM_SQUID_HOST=$UPSTREAM_SQUID_HOST" \
    --env "UPSTREAM_SQUID_PORT=$UPSTREAM_SQUID_PORT" \
    --secret source=squid-digest-bridge-credentials,type=mount,target=proxy_digest_credentials,mode=0400 \
    --volume "$PWD/bridge.py:/app/bridge.py:ro,Z" \
    docker.io/library/python:3.12-alpine python /app/bridge.py
