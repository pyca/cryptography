#!/bin/bash -ex

case "${1}" in
    install)
        git clone --depth=1 https://github.com/secdev/scapy
        cd scapy
        git rev-parse HEAD
        uv pip install tox
        ;;
    run)
        cd scapy
        TOX_OVERRIDE="testenv:cryptography.deps=file://.." tox -e cryptography
        ;;
    *)
        exit 1
        ;;
esac
