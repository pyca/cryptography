#!/bin/bash -ex

case "${1}" in
    install)
        cd scapy
        uv pip install tox
        ;;
    run)
        cd scapy
        TOX_OVERRIDE="testenv:cryptography.deps=file://$(realpath ..)" tox -e cryptography
        ;;
    *)
        exit 1
        ;;
esac
