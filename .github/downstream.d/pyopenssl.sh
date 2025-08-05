#!/bin/bash -ex

case "${1}" in
    install)
        cd pyopenssl
        uv pip install -e ".[test]"
        ;;
    run)
        cd pyopenssl
        pytest tests
        ;;
    *)
        exit 1
        ;;
esac
