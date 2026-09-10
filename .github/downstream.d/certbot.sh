#!/bin/bash -ex

case "${1}" in
    install)
        cd certbot
        uv pip install pip
        tools/pip_install.py -e ./acme[test]
        tools/pip_install.py -e ./certbot[test]
        uv pip install -U pyopenssl
        ;;
    run)
        cd certbot
        # Ignore some warnings for now since they're now automatically promoted
        # to errors. We can probably remove this when acme gets split into
        # its own repo
        pytest -Wignore certbot
        # pyOpenSSL references cryptography's DSA types at import time,
        # which now emits a deprecation warning.
        pytest -W "ignore:DSA is deprecated:cryptography.utils.CryptographyDeprecationWarning" acme
        ;;
    *)
        exit 1
        ;;
esac
