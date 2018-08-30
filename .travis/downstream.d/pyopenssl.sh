#!/bin/bash

case "${1}" in
    install)
        git clone --depth=1 https://github.com/pyca/pyopenssl
        cd pyopenssl
        pip install -e ".[test]"
        ;;
    run)
        cd pyopenssl
        pytest tests
        ;;
    *)
        exit 1
        ;;
esac
