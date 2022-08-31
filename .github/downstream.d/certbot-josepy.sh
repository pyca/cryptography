#!/bin/bash -ex

case "${1}" in
    install)
        git clone --depth=1 https://github.com/certbot/josepy
        cd josepy
        git rev-parse HEAD
        curl -sSL https://install.python-poetry.org | python3 - --version=1.1.15
        "${HOME}/.local/bin/poetry" export -f requirements.txt --dev --without-hashes -o constraints.txt
        pip install -e . pytest -c constraints.txt
        ;;
    run)
        cd josepy
        pytest tests
        ;;
    *)
        exit 1
        ;;
esac
