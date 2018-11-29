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
        # Ignore some warnings for now since they're now automatically promoted
        # to errors. We can probably remove this when acme gets split into
        # its own repo
        pytest -Wignore certbot/tests
        pytest acme
        ;;
    *)
        exit 1
        ;;
esac
