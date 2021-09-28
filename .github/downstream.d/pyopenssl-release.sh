#!/bin/bash -ex

case "${1}" in
    install)
        pip install "pyopenssl[test]"
        git clone https://github.com/pyca/pyopenssl
        cd pyopenssl
        VERSION=$(python -c "import OpenSSL;print(OpenSSL.__version__)")
        git checkout "$VERSION"
        ;;
    run)
        cd pyopenssl
        pytest tests
        ;;
    *)
        exit 1
        ;;
esac
