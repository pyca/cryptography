#!/bin/bash -ex

case "${1}" in
    install)
        git clone --depth=1 https://github.com/certbot/josepy
        cd josepy
        git rev-parse HEAD
        pip install -e ".[tests]" -c constraints.txt
        ;;
    run)
        cd josepy
        pytest src
        ;;
    *)
        exit 1
        ;;
esac
