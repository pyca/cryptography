#!/bin/bash -ex

case "${1}" in
    install)
        git clone --depth=1 https://github.com/certbot/josepy
        cd josepy
        pip install -e ".[tests]"
        ;;
    run)
        cd josepy
        pytest src
        ;;
    *)
        exit 1
        ;;
esac
