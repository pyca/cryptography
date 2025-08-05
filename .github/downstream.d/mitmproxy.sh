#!/bin/bash -ex

case "${1}" in
    install)
        cd mitmproxy
        uv pip install -r <(uv export --locked) -e .
        ;;
    run)
        cd mitmproxy
        pytest test
        ;;
    *)
        exit 1
        ;;
esac
