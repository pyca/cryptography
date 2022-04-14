#!/bin/bash -ex

case "${1}" in
    install)
        git clone --depth=1 https://github.com/certbot/josepy
        cd josepy
        git rev-parse HEAD
        curl -sSL https://install.python-poetry.org | python3 -
        "${HOME}/.local/bin/poetry" install
        ;;
    run)
        cd josepy
        .venv/bin/pytest tests
        ;;
    *)
        exit 1
        ;;
esac
