#!/bin/bash

set -e
set -x

if [[ "$(uname -s)" == "Darwin" ]]; then
    eval "$(pyenv init -)"
    if [[ "${OPENSSL}" != "0.9.8" ]]; then
        # set our flags to use homebrew openssl and not error on
        # unused compiler args (looking at you mno-fused-madd)
        export ARCHFLAGS="-arch x86_64 -Wno-error=unused-command-line-argument-hard-error-in-future"
        export LDFLAGS="-L/usr/local/opt/openssl/lib"
        export CFLAGS="-I/usr/local/opt/openssl/include"
        # The Travis OS X jobs are run for two versions
        # of OpenSSL, but we only need to run the
        # CommonCrypto backend tests once. Exclude
        # CommonCrypto when we test against brew OpenSSL
        export TOX_FLAGS="--backend=openssl"
    else
        export ARCHFLAGS="-Wno-error=unused-command-line-argument-hard-error-in-future"
    fi
fi
source ~/.venv/bin/activate
tox -e $TOX_ENV -- $TOX_FLAGS
