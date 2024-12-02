#!/bin/bash -ex

case "${1}" in
    install)
        # NOTE: placed in /tmp to avoid inscrutable pytest failures
        # with 'unrecognized arguments: --benchmark-disable'
        git clone --depth=1 https://github.com/sigstore/sigstore-python /tmp/sigstore-python
        cd /tmp/sigstore-python
        git rev-parse HEAD
        pip install -e ".[test]"
        ;;
    run)
        cd /tmp/sigstore-python
        pytest test
        ;;
    *)
        exit 1
        ;;
esac
