#!/bin/bash -ex

case "${1}" in
    install)
        pip install uv
        git clone --depth=1 https://github.com/mitmproxy/mitmproxy
        cd mitmproxy
        git rev-parse HEAD
        uv pip install --system --requirements <(uv export --locked) -e .
        ;;
    run)
        cd mitmproxy
        pytest test
        ;;
    *)
        exit 1
        ;;
esac
