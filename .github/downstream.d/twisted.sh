#!/bin/bash -ex

case "${1}" in
    install)
        cd twisted
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
