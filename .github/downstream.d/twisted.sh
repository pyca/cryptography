#!/bin/bash -ex

case "${1}" in
    install)
        git clone --depth=1 https://github.com/twisted/twisted
        cd twisted
        git rev-parse HEAD
        uv pip install ".[all_non_platform]"
        ;;
    run)
        cd twisted
        python -m twisted.trial -j4 src/twisted
        ;;
    *)
        exit 1
        ;;
esac
