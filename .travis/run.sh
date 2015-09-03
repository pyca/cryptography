#!/bin/bash

set -e
set -x

if [[ "$(uname -s)" == "Darwin" ]]; then
    eval "$(pyenv init -)"
    if [[ "${OPENSSL}" != "0.9.8" ]]; then
        # set our flags to use homebrew openssl
        export ARCHFLAGS="-arch x86_64"
        export LDFLAGS="-L/usr/local/opt/openssl/lib"
        export CFLAGS="-I/usr/local/opt/openssl/include"
        # The Travis OS X jobs are run for two versions
        # of OpenSSL, but we only need to run the
        # CommonCrypto backend tests once. Exclude
        # CommonCrypto when we test against brew OpenSSL
        export TOX_FLAGS="--backend=openssl"
    fi
else
    if [[ "${TOXENV}" == "pypy" ]]; then
        PYENV_ROOT="$HOME/.pyenv"
        PATH="$PYENV_ROOT/bin:$PATH"
        eval "$(pyenv init -)"
        pyenv global pypy-2.6.1
    fi
fi

# If we're building on Python 3.5, then we need to use plain asserts until
# pytest is updated.
if [[ $TOXENV = "py35" ]]; then
    export TOX_FLAGS="--assert=plain $TOX_FLAGS"
fi

source ~/.venv/bin/activate
tox -- $TOX_FLAGS
