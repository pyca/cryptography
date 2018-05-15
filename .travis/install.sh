#!/bin/bash

set -e
set -x

# download, compile, and install if it's not already present via travis
# cache
if [ -n "${OPENSSL}" ]; then
    OPENSSL_DIR="ossl-1/${OPENSSL}"
    if [[ ! -f "$HOME/$OPENSSL_DIR/bin/openssl" ]]; then
        curl -O https://www.openssl.org/source/openssl-$OPENSSL.tar.gz
        tar zxf openssl-$OPENSSL.tar.gz
        cd openssl-$OPENSSL
        ./config shared no-asm no-ssl2 no-ssl3 -fPIC --prefix="$HOME/$OPENSSL_DIR"
        # modify the shlib version to a unique one to make sure the dynamic
        # linker doesn't load the system one. This isn't required for 1.1.0 at the
        # moment since our Travis builders have a diff shlib version, but it doesn't hurt
        sed -i "s/^SHLIB_MAJOR=.*/SHLIB_MAJOR=100/" Makefile
        sed -i "s/^SHLIB_MINOR=.*/SHLIB_MINOR=0.0/" Makefile
        sed -i "s/^SHLIB_VERSION_NUMBER=.*/SHLIB_VERSION_NUMBER=100.0.0/" Makefile
        make depend
        make install
    fi
fi
pip install virtualenv

python -m virtualenv ~/.venv
source ~/.venv/bin/activate
# This coverage pin must be kept in sync with tox.ini
pip install tox codecov coverage==4.3.4
