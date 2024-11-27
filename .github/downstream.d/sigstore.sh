#!/bin/bash -ex

case "${1}" in
    install)
        git clone --depth=1 https://github.com/sigstore/sigstore-python
        cd sigstore-python
        git rev-parse HEAD
        pip install -e ".[test]"
        ;;
    run)
        cd sigstore-python
        pytest test
        ;;
    *)
        exit 1
        ;;
esac
