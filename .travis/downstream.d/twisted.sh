#!/bin/bash

case "${1}" in
    install)
        git clone --depth=1 https://github.com/twisted/twisted
        cd twisted
        pip install -e .[tls,conch,http2]
        ;;
    run)
        cd twisted
        python -m twisted.trial src/twisted
        ;;
    *)
        exit 1
        ;;
esac
