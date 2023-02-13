#!/bin/bash -ex

case "${1}" in
    install)
        git clone --depth=1 https://github.com/secdev/scapy
        cd scapy
        git rev-parse HEAD
        pip install tox
        ;;
    run)
        cd scapy
        # this tox case uses sitepackages=true to use local cryptography
        tox -qe cryptography
        ;;
    *)
        exit 1
        ;;
esac
