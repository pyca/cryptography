#!/bin/bash -ex

case "${1}" in
    install)
        # NOTE: placed in /tmp to avoid inscrutable pytest failures
        # with 'unrecognized arguments: --benchmark-disable'
        git clone --depth=1 https://github.com/sigstore/sigstore-python /tmp/sigstore-python
        cd /tmp/sigstore-python
        git rev-parse HEAD
        uv pip install -e ".[test]"
        ;;
    run)
        cd /tmp/sigstore-python
        # Run only the unit tests, and skip any that require network access.
        pytest test/unit --skip-online
        ;;
    *)
        exit 1
        ;;
esac
