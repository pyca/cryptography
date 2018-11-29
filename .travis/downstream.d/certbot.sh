#!/bin/bash -ex

case "${1}" in
    install)
        git clone --depth=1 https://github.com/certbot/certbot
        cd certbot
        git rev-parse HEAD
        pip install -e acme[dev]
        pip install -e .[dev]
        ;;
    run)
        cd certbot
        pytest certbot/tests
        pytest acme
        ;;
    *)
        exit 1
        ;;
esac
