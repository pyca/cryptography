#!/bin/bash -ex

case "${1}" in
    install)
        git clone --depth=1 https://github.com/mitmproxy/mitmproxy
        cd mitmproxy
        git rev-parse HEAD
        pip install -e ".[dev]"
        ;;
    run)
        cd mitmproxy
        pytest test
        ;;
    *)
        exit 1
        ;;
esac
