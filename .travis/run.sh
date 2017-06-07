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
    if [[ "${CRYPTOGRAPHY_SUPPRESS_LINK_FLAGS}" == "1" ]]; then
        export LDFLAGS="/usr/local/opt/openssl\@1.1/lib/libssl.a /usr/local/opt/openssl\@1.1/lib/libcrypto.a"
        export CFLAGS="-I/usr/local/opt/openssl\@1.1/include"
    else
        # Compile the dynamic link build against 1.0.2 because the linker refuses to properly load 1.1.0
        export LDFLAGS="-L/usr/local/opt/openssl/lib"
        export CFLAGS="-I/usr/local/opt/openssl/include"
    fi
else
    if [[ "${TOXENV}" == "pypy" ]]; then
        PYENV_ROOT="$HOME/.pyenv"
        PATH="$PYENV_ROOT/bin:$PATH"
        eval "$(pyenv init -)"
    fi
    if [ -n "${OPENSSL}" ]; then
        OPENSSL_DIR="ossl-1/${OPENSSL}"

        export PATH="$HOME/$OPENSSL_DIR/bin:$PATH"
        export CFLAGS="-I$HOME/$OPENSSL_DIR/include"
        # rpath on linux will cause it to use an absolute path so we don't need to do LD_LIBRARY_PATH
        export LDFLAGS="-L$HOME/$OPENSSL_DIR/lib -Wl,-rpath=$HOME/$OPENSSL_DIR/lib"
    fi
fi
source ~/.venv/bin/activate
tox
# Output information about linking of the OpenSSL library on OS X
if [[ "$(uname -s)" == "Darwin" ]]; then
    otool -L $(find .tox -name "_openssl*.so")
fi
