#!/bin/bash -ex

case "${1}" in
    install)
        git clone --depth 1 https://github.com/shazow/urllib3
        cd urllib3
        git rev-parse HEAD
        pip install -r ./dev-requirements.txt
        pip install -e ".[socks]"
        ;;
    run)
        cd urllib3
        pytest test
        ;;
    *)
        exit 1
        ;;
esac
