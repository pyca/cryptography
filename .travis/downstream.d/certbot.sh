#!/bin/bash

case "${1}" in
    install)
        git clone --depth=1 https://github.com/certbot/certbot
        cd certbot
        pip install pytest pytest-mock mock
        pip install -e acme
        pip install -e .
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
