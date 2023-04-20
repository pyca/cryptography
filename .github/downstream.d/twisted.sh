#!/bin/bash -ex

case "${1}" in
    install)
        git clone --depth=1 https://github.com/twisted/twisted
        cd twisted
        git rev-parse HEAD
        pip install ".[all_non_platform]" "pyasn1!=0.5.0"
        ;;
    run)
        cd twisted
        python -m twisted.trial -j4 src/twisted
        ;;
    *)
        exit 1
        ;;
esac
