#!/bin/bash
set -euo pipefail

unset PROXY_DIGEST_USER PROXY_DIGEST_PASS
cd -- "$(dirname -- "$0")"
source ./runtime.sh
if [ -f "$state_file" ]; then
    load_runtime_state
else
    load_settings
    select_runtime
fi
check_runtime
runtime stop "$container_name"
rm -f -- "$state_file"
