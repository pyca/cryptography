#!/bin/bash -ex

case "${1}" in
    install)
        VERSION=$(curl https://pypi.org/pypi/pyOpenSSL/json | jq -r .info.version)
        git clone https://github.com/pyca/pyopenssl
        cd pyopenssl
        git checkout "$VERSION"
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
