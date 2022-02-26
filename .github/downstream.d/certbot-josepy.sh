#!/bin/bash -ex

case "${1}" in
    install)
        git clone --depth=1 https://github.com/adferrand/josepy --branch poetry
        cd josepy
        git rev-parse HEAD
        pip install poetry
        poetry install -v
        ;;
    run)
        cd josepy
        pytest
        ;;
    *)
        exit 1
        ;;
esac
