#!/bin/bash
set -euo pipefail

# Remove credentials before any runtime command, including connection checks.
proxy_username=${PROXY_DIGEST_USER:-}
proxy_password=${PROXY_DIGEST_PASS:-}
unset PROXY_DIGEST_USER PROXY_DIGEST_PASS
cd -- "$(dirname -- "$0")"
source ./runtime.sh
load_settings
if [ -f "$state_file" ] && [ "${CONTAINER_RUNTIME:-auto}" = auto ]; then
    load_runtime_state
else
    select_runtime
fi
selected_state=$(runtime_state)
if [ -f "$state_file" ] && [ "$(cat "$state_file")" != "$selected_state" ]; then
    printf 'Error: A bridge is recorded on another runtime/connection. Run ./shutdown.sh before switching.\n' >&2
    exit 1
fi
check_runtime
: "${UPSTREAM_SQUID_HOST:?Set UPSTREAM_SQUID_HOST in .env or export it}"
: "${UPSTREAM_SQUID_PORT:?Set UPSTREAM_SQUID_PORT in .env or export it}"

# Read credentials only from the caller or terminal, never from .env.
if [ -z "${proxy_username:-}" ]; then
    if ! read -r -p 'Proxy username: ' proxy_username </dev/tty; then
        printf '\nUnable to read username; export PROXY_DIGEST_USER for non-interactive startup.\n' >&2
        exit 1
    fi
fi
: "${proxy_username:?Username must not be empty}"
if [ -z "${proxy_password:-}" ]; then
    if ! read -r -s -p 'Proxy password: ' proxy_password </dev/tty; then
        printf '\nUnable to read password; export PROXY_DIGEST_PASS for non-interactive startup.\n' >&2
        exit 1
    fi
    printf '\n' >/dev/tty
fi
: "${proxy_password:?Password must not be empty}"

# Prepare the image before touching the current container or its credentials.
if ! runtime image inspect "$image" >/dev/null 2>&1; then
    runtime pull "$image" >/dev/null
fi

credential_volume=
helper_name=
state_temp=
new_container_attempted=false
cleanup() {
    result=$?
    trap - EXIT
    if [ -n "$helper_name" ]; then
        runtime rm --force "$helper_name" >/dev/null 2>&1 || true
    fi
    if [ -n "$credential_volume" ]; then
        if [ "$new_container_attempted" = true ]; then
            runtime rm --force "$container_name" >/dev/null 2>&1 || true
        fi
        runtime volume rm "$credential_volume" >/dev/null 2>&1 || true
    fi
    [ -z "$state_temp" ] || rm -f -- "$state_temp"
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Check that state can be persisted before replacing a working container.
umask 077
state_temp=$(mktemp "$state_file.XXXXXX")
printf '%s\n' "$selected_state" > "$state_temp"

run_args=(--detach --name "$container_name" --restart unless-stopped
    --publish 127.0.0.1:8080:8080
    --label "$managed_label=true"
    --env "UPSTREAM_SQUID_HOST=$UPSTREAM_SQUID_HOST"
    --env "UPSTREAM_SQUID_PORT=$UPSTREAM_SQUID_PORT")
if [ "$runtime_kind" = podman ]; then
    printf '%s\0%s' "$proxy_username" "$proxy_password" |
        runtime secret create --replace squid-digest-bridge-credentials - >/dev/null
    unset proxy_username proxy_password
    run_args+=(--replace
        --secret source=squid-digest-bridge-credentials,type=mount,target=proxy_digest_credentials,mode=0400
        --volume "$PWD/bridge.py:/app/bridge.py:ro,Z")
    runtime run "${run_args[@]}" "$image" python /app/bridge.py
else
    # Inspect through a successful list operation: do not treat daemon/permission
    # errors as proof that the named container does not exist.
    existing=$(runtime container ls --all --filter "name=^/$container_name$" --format '{{.Names}}')
    old_volume=
    if [ -n "$existing" ]; then
        owner=$(runtime inspect --format "{{index .Config.Labels \"$managed_label\"}}" "$container_name")
        if [ "$owner" != true ]; then
            printf 'Error: Container %s is not managed by this project; refusing to replace it.\n' "$container_name" >&2
            exit 1
        fi
        old_volume=$(runtime inspect --format "{{index .Config.Labels \"$credentials_label\"}}" "$container_name")
    fi
    credential_volume="$container_name-credentials-$$-$RANDOM-$RANDOM"
    runtime volume create --label "$managed_label=true" "$credential_volume" >/dev/null
    helper_name="$container_name-credentials-$$"
    # The Python command is constant. Credential bytes only cross stdin, with no
    # host credential file, container environment, command arguments, or output.
    printf '%s\0%s' "$proxy_username" "$proxy_password" |
        runtime run --rm --interactive --name "$helper_name" --network none \
            --mount "type=volume,source=$credential_volume,target=/run/secrets" \
            "$image" python -c '
import os, sys
payload = sys.stdin.buffer.read()
username, password = payload.decode("utf-8").split("\0", 1)
if not username or not password:
    raise SystemExit("Credential secrets must be non-empty")
os.umask(0o077)
fd = os.open("/run/secrets/proxy_digest_credentials", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
with os.fdopen(fd, "wb") as secret:
    secret.write(payload)
'
    unset proxy_username proxy_password
    helper_name=
    if [ -n "$existing" ]; then
        runtime rm --force "$container_name" >/dev/null
    fi
    run_args+=(--label "$credentials_label=$credential_volume"
        --mount "type=volume,source=$credential_volume,target=/run/secrets,readonly"
        --volume "$PWD/bridge.py:/app/bridge.py:ro")
    new_container_attempted=true
    runtime run "${run_args[@]}" "$image" python /app/bridge.py
    # The new container now owns the volume, including when state persistence fails.
    credential_volume=
    if [ -n "$old_volume" ]; then
        case "$old_volume" in
            "$container_name"-credentials-*)
                runtime volume rm "$old_volume" >/dev/null ||
                    printf 'Warning: Could not remove old credential volume %s.\n' "$old_volume" >&2 ;;
        esac
    fi
fi
mv -f -- "$state_temp" "$state_file"
state_temp=
