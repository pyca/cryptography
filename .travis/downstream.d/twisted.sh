#!/bin/bash -ex

case "${1}" in
    install)
        git clone --depth=1 https://github.com/twisted/twisted
        cd twisted
        git rev-parse HEAD
        pip install ".[all_non_platform]"
        ;;
    run)
        cd twisted
        python -m twisted.trial src/twisted
        ;;
    *)
        exit 1
        ;;
esac
