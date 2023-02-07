#!/bin/bash -ex

case "${1}" in
    install)
        git clone --depth=1 https://github.com/secdev/scapy
        cd scapy
        git rev-parse HEAD
        # Pin virtualenv until https://github.com/secdev/scapy/pull/3862 is merged
        pip install tox 'virtualenv<20.18'
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
