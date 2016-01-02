#!/bin/bash

set -e
set -x

if [[ "$(uname -s)" == "Darwin" ]]; then
    # initialize our pyenv
    PYENV_ROOT="$HOME/.pyenv"
    PATH="$PYENV_ROOT/bin:$PATH"
    eval "$(pyenv init -)"

    # set our flags to use homebrew openssl
    # if the build is static we need different LDFLAGS
    if [[ "${CRYPTOGRAPHY_OSX_NO_LINK_FLAGS}" == "1" ]]; then
        export LDFLAGS="/usr/local/opt/openssl/lib/libssl.a /usr/local/opt/openssl/lib/libcrypto.a"
    else
        export LDFLAGS="-L/usr/local/opt/openssl/lib"
    fi
    export CFLAGS="-I/usr/local/opt/openssl/include"
else
    if [[ "${TOXENV}" == "pypy" ]]; then
        PYENV_ROOT="$HOME/.pyenv"
        PATH="$PYENV_ROOT/bin:$PATH"
        eval "$(pyenv init -)"
    fi
    if [[ "${OPENSSL}" == "0.9.8" ]]; then
      export PATH="$HOME/ossl-098l/bin:$PATH"
      export CFLAGS="-I$HOME/ossl-098l/include"
      export LDFLAGS="-L$HOME/ossl-098l/lib"
      export LD_LIBRARY_PATH="$HOME/ossl-098l/lib"
    fi
fi
source ~/.venv/bin/activate
tox -- $TOX_FLAGS
# Output information about linking of the OpenSSL library on OS X
if [[ "$(uname -s)" == "Darwin" ]]; then
    otool -L `find .tox -name _openssl*.so`
fi
