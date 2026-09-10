#!/bin/bash -ex

case "${1}" in
    install)
        cd josepy
        curl -sSL https://install.python-poetry.org | python3 -
        "${HOME}/.local/bin/poetry" self add poetry-plugin-export
        "${HOME}/.local/bin/poetry" export -f constraints.txt --dev --without-hashes -o constraints.txt
        uv pip install -e . pytest -c constraints.txt
        ;;
    run)
        cd josepy
        # josepy's tests load a DSA key, which now emits a deprecation
        # warning.
        pytest -W "ignore:DSA is deprecated:cryptography.utils.CryptographyDeprecationWarning" tests
        ;;
    *)
        exit 1
        ;;
esac
