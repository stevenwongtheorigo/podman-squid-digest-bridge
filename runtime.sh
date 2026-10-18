#!/bin/bash
# Shared by startup.sh and shutdown.sh; configuration/state is parsed, never sourced.

container_name=squid-digest-bridge
network_name=$container_name-network
client_token_file=.bridge-client-token
image=docker.io/library/python:3.12-alpine
managed_label=io.squid-digest-bridge.managed
credentials_label=io.squid-digest-bridge.credentials
state_file=.bridge-runtime

load_settings() {
    if [ -f .env ]; then
        while IFS='=' read -r name value || [ -n "$name" ]; do
            value=${value%$'\r'}
            case "$name" in
                UPSTREAM_SQUID_HOST) UPSTREAM_SQUID_HOST=${UPSTREAM_SQUID_HOST-$value} ;;
                UPSTREAM_SQUID_PORT) UPSTREAM_SQUID_PORT=${UPSTREAM_SQUID_PORT-$value} ;;
                CONTAINER_RUNTIME) CONTAINER_RUNTIME=${CONTAINER_RUNTIME-$value} ;;
                PROXY_DOMAINS_FILE) PROXY_DOMAINS_FILE=${PROXY_DOMAINS_FILE-$value} ;;
            esac
        done < .env
    fi
}

installation_help() {
    printf 'Error: %s is not installed or is not available on PATH.\n' "$1" >&2
    case "$(uname -s 2>/dev/null || printf unknown)" in
        Darwin) printf '\n  macOS:\n    Install Podman, Docker Desktop, or OrbStack.\n    For Podman, run: podman machine init\n                    podman machine start\n' >&2 ;;
        MINGW*|MSYS*|CYGWIN*|Windows_NT) printf '\n  Windows:\n    Install Podman or Docker Desktop and run scripts from Bash (e.g. Git Bash).\n    For Podman, run: podman machine init\n                    podman machine start\n' >&2 ;;
        Linux) printf '\n  Linux:\n    Install Podman or Docker Engine using your distribution setup guide.\n' >&2 ;;
    esac
    printf '\nhttps://podman.io/docs/installation\nhttps://docs.docker.com/get-started/get-docker/\nhttps://orbstack.dev/ (macOS)\n\nVerify with podman info or docker info, then run ./startup.sh again.\n' >&2
    exit 127
}

select_runtime() {
    runtime_kind=${CONTAINER_RUNTIME:-auto}
    case "$runtime_kind" in
        auto)
            if command -v docker >/dev/null 2>&1; then
                if docker context inspect orbstack >/dev/null 2>&1; then
                    runtime_kind=orbstack
                else
                    runtime_kind=docker
                fi
            elif command -v podman >/dev/null 2>&1; then
                runtime_kind=podman
            else
                installation_help 'Podman or Docker'
            fi ;;
        podman|docker|orbstack) ;;
        *) printf 'Error: CONTAINER_RUNTIME must be auto, podman, docker, or orbstack.\n' >&2; exit 1 ;;
    esac
    runtime_context= runtime_host= runtime_identity=
    runtime_tls= runtime_tls_verify= runtime_cert_path=
    if [ "$runtime_kind" = podman ]; then
        command -v podman >/dev/null 2>&1 || installation_help Podman
        runtime_context=${CONTAINER_CONNECTION:-}
        runtime_host=${CONTAINER_HOST:-}
        runtime_identity=${CONTAINER_SSHKEY:-}
        if [ -z "$runtime_context$runtime_host" ]; then
            case "$(uname -s)" in
                Darwin|MINGW*|MSYS*|CYGWIN*|Windows_NT)
                    runtime_context=$(podman system connection list --format '{{if .Default}}{{.Name}}{{end}}')
                    # A template may emit empty lines for non-default connections.
                    runtime_context=${runtime_context//$'\n'/}
                    if [ -z "$runtime_context" ]; then
                        printf 'Error: No default Podman connection; initialize and start a Podman machine.\n' >&2
                        exit 1
                    fi ;;
            esac
        fi
    else
        command -v docker >/dev/null 2>&1 || installation_help Docker
        if [ "$runtime_kind" = orbstack ]; then
            runtime_context=orbstack
        elif [ -n "${DOCKER_CONTEXT:-}" ] || [ -z "${DOCKER_HOST:-}" ]; then
            runtime_context=$(docker context show)
        else
            runtime_host=$DOCKER_HOST
        fi
        runtime_tls=${DOCKER_TLS:-}
        runtime_tls_verify=${DOCKER_TLS_VERIFY:-}
        runtime_cert_path=${DOCKER_CERT_PATH:-}
    fi
}

runtime() (
    # Keep the saved target stable even if the caller changes CLI environment.
    unset DOCKER_CONTEXT DOCKER_HOST DOCKER_TLS DOCKER_TLS_VERIFY DOCKER_CERT_PATH
    unset CONTAINER_CONNECTION CONTAINER_HOST CONTAINER_SSHKEY
    if [ "$runtime_kind" = podman ]; then
        command_args=(podman)
        if [ -n "$runtime_context" ]; then
            command_args+=(--connection "$runtime_context")
        elif [ -n "$runtime_host" ]; then
            command_args+=(--url "$runtime_host")
            [ -z "$runtime_identity" ] || command_args+=(--identity "$runtime_identity")
        else
            command_args+=(--remote=false)
        fi
    else
        command_args=(docker)
        if [ -n "$runtime_context" ]; then
            command_args+=(--context "$runtime_context")
        else
            command_args+=(--host "$runtime_host")
        fi
        [ -z "$runtime_tls" ] || export DOCKER_TLS=$runtime_tls
        [ -z "$runtime_tls_verify" ] || export DOCKER_TLS_VERIFY=$runtime_tls_verify
        [ -z "$runtime_cert_path" ] || export DOCKER_CERT_PATH=$runtime_cert_path
    fi
    "${command_args[@]}" "$@"
)

check_runtime() {
    if [ "$runtime_kind" = podman ]; then
        command -v podman >/dev/null 2>&1 || installation_help Podman
    else
        command -v docker >/dev/null 2>&1 || installation_help Docker
    fi
    if ! runtime info >/dev/null; then
        printf 'Error: Cannot connect to %s. Start its engine/machine and check its connection settings.\n' "$runtime_kind" >&2
        exit 1
    fi
}

runtime_state() {
    for name in runtime_kind runtime_context runtime_host runtime_identity runtime_tls runtime_tls_verify runtime_cert_path; do
        value=${!name}
        case "$value" in
            *$'\n'*|*$'\r'*) printf 'Error: Runtime settings must not contain newlines.\n' >&2; return 1 ;;
        esac
        printf '%s=%s\n' "$name" "$value"
    done
}

load_runtime_state() {
    runtime_kind= runtime_context= runtime_host= runtime_identity=
    runtime_tls= runtime_tls_verify= runtime_cert_path=
    while IFS='=' read -r name value || [ -n "$name" ]; do
        case "$name" in
            runtime_kind|runtime_context|runtime_host|runtime_identity|runtime_tls|runtime_tls_verify|runtime_cert_path)
                printf -v "$name" '%s' "$value" ;;
            *) printf 'Error: Invalid runtime state in %s.\n' "$state_file" >&2; exit 1 ;;
        esac
    done < "$state_file"
    case "$runtime_kind" in
        podman) ;;
        docker|orbstack)
            if [ -z "$runtime_context$runtime_host" ]; then
                printf 'Error: Missing Docker target in %s.\n' "$state_file" >&2; exit 1
            fi ;;
        *) printf 'Error: Invalid runtime in %s.\n' "$state_file" >&2; exit 1 ;;
    esac
}
