#!/bin/bash

if [ -f ".bridge-client-token" ]; then
    token=$(cat ".bridge-client-token")
else
    echo ".bridge-client-token is missing, run"
	echo ""
    echo "openssl rand -base64 128 | sha256sum | base64 | head -c 64 > .bridge-client-token"
    return 1
fi

export HTTP_PROXY="http://bridge:${token}@localhost:8080"
export HTTPS_PROXY="http://bridge:${token}@localhost:8080"
export NO_PROXY="localhost,127.0.0.1"
