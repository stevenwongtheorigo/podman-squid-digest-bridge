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
# Prepare the image before validation, credentials, or container replacement.
if ! runtime image inspect "$image" >/dev/null 2>&1; then
    runtime pull "$image" >/dev/null
fi

mount_options=ro
if [ "$runtime_kind" = podman ]; then
    mount_options=ro,Z
    # Validation and the bridge share these files. Shared SELinux labels avoid
    # a temporary validator taking private ownership from a running bridge.
    [ -z "${PROXY_DOMAINS_FILE:-}" ] || mount_options=ro,z
fi
config_args=(--volume "$PWD/bridge.py:/app/bridge.py:$mount_options")
needs_upstream=proxy
if [ -n "${PROXY_DOMAINS_FILE:-}" ]; then
    if [ ! -f "$PROXY_DOMAINS_FILE" ] || [ ! -r "$PROXY_DOMAINS_FILE" ]; then
        printf 'Error: PROXY_DOMAINS_FILE must name a readable regular file.\n' >&2
        exit 1
    fi
    domain_file=$(cd -- "$(dirname -- "$PROXY_DOMAINS_FILE")" && pwd)/${PROXY_DOMAINS_FILE##*/}
    config_args+=(--volume "$domain_file:/app/proxy-domains.txt:$mount_options"
        --env PROXY_DOMAINS_FILE=/app/proxy-domains.txt)
    needs_upstream=$(runtime run --rm --network none "${config_args[@]}" \
        --env "UPSTREAM_SQUID_HOST=${UPSTREAM_SQUID_HOST:-}" \
        --env "UPSTREAM_SQUID_PORT=${UPSTREAM_SQUID_PORT:-}" \
        "$image" python /app/bridge.py --check-config)
    case "$needs_upstream" in
        proxy|direct) ;;
        *) printf 'Error: Unable to validate proxy domain configuration.\n' >&2; exit 1 ;;
    esac
fi

if ! runtime network inspect "$network_name" >/dev/null 2>&1; then
    runtime network create --driver bridge --label "$managed_label=true" "$network_name" >/dev/null
fi
network_owner=$(runtime network inspect --format "{{index .Labels \"$managed_label\"}}" "$network_name")
if [ "$network_owner" != true ]; then
    printf 'Error: Network %s is not managed by this project; refusing to use it.\n' "$network_name" >&2
    exit 1
fi

if [ -L "$client_token_file" ]; then
    printf 'Error: Local client token must not be a symbolic link.\n' >&2
    exit 1
fi
if [ ! -e "$client_token_file" ]; then
    token_temp=$(mktemp "$client_token_file.XXXXXX")
    if ! runtime run --rm --network none "$image" python -c 'import secrets; print(secrets.token_urlsafe(32))' > "$token_temp"; then
        rm -f -- "$token_temp"
        exit 1
    fi
    chmod 600 "$token_temp"
    mv -f -- "$token_temp" "$client_token_file"
fi
if [ ! -f "$client_token_file" ] || [ ! -r "$client_token_file" ]; then
    printf 'Error: Local client token must be a readable regular file.\n' >&2
    exit 1
fi
chmod 600 "$client_token_file"
token_options=ro
[ "$runtime_kind" != podman ] || token_options=ro,Z
client_args=(--volume "$PWD/$client_token_file:/run/secrets/bridge_client_token:$token_options")
runtime run --rm --network none "${config_args[@]}" "${client_args[@]}" \
    "$image" python /app/bridge.py --check-client-token

if [ "$needs_upstream" = proxy ]; then
    : "${UPSTREAM_SQUID_HOST:?Set UPSTREAM_SQUID_HOST in .env or export it}"
    : "${UPSTREAM_SQUID_PORT:?Set UPSTREAM_SQUID_PORT in .env or export it}"
    # Read credentials only from the caller or terminal, never from .env.
    if [ -z "$proxy_username" ]; then
        if ! read -r -p 'Proxy username: ' proxy_username </dev/tty; then
            printf '\nUnable to read username; export PROXY_DIGEST_USER for non-interactive startup.\n' >&2
            exit 1
        fi
    fi
    : "${proxy_username:?Username must not be empty}"
    if [ -z "$proxy_password" ]; then
        if ! read -r -s -p 'Proxy password: ' proxy_password </dev/tty; then
            printf '\nUnable to read password; export PROXY_DIGEST_PASS for non-interactive startup.\n' >&2
            exit 1
        fi
        printf '\n' >/dev/tty
    fi
    : "${proxy_password:?Password must not be empty}"
else
    unset proxy_username proxy_password
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
    if [ "$new_container_attempted" = true ]; then
        runtime rm --force "$container_name" >/dev/null 2>&1 || true
    fi
    if [ -n "$credential_volume" ]; then
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
    --network "$network_name"
    --publish 127.0.0.1:8080:8080
    --label "$managed_label=true" "${config_args[@]}" "${client_args[@]}")
if [ "$needs_upstream" = proxy ]; then
    run_args+=(--env "UPSTREAM_SQUID_HOST=$UPSTREAM_SQUID_HOST"
        --env "UPSTREAM_SQUID_PORT=$UPSTREAM_SQUID_PORT")
fi
if [ "$runtime_kind" = podman ]; then
    if [ "$needs_upstream" = proxy ]; then
        printf '%s\0%s' "$proxy_username" "$proxy_password" |
            runtime secret create --replace squid-digest-bridge-credentials - >/dev/null
        unset proxy_username proxy_password
        run_args+=(--secret source=squid-digest-bridge-credentials,type=mount,target=proxy_digest_credentials,mode=0400)
    fi
    run_args+=(--replace)
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
    if [ "$needs_upstream" = proxy ]; then
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
    fi
    if [ -n "$existing" ]; then
        runtime rm --force "$container_name" >/dev/null
    fi
    if [ "$needs_upstream" = proxy ]; then
        run_args+=(--label "$credentials_label=$credential_volume"
            --mount "type=volume,source=$credential_volume,target=/run/secrets,readonly")
    fi
    new_container_attempted=true
    runtime run "${run_args[@]}" "$image" python /app/bridge.py
    new_container_attempted=false
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
