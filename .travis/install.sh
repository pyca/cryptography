#!/bin/bash

set -e
set -x

shlib_sed() {
    # modify the shlib version to a unique one to make sure the dynamic
    # linker doesn't load the system one.
    sed -i "s/^SHLIB_MAJOR=.*/SHLIB_MAJOR=100/" Makefile
    sed -i "s/^SHLIB_MINOR=.*/SHLIB_MINOR=0.0/" Makefile
    sed -i "s/^SHLIB_VERSION_NUMBER=.*/SHLIB_VERSION_NUMBER=100.0.0/" Makefile
}

# download, compile, and install if it's not already present via travis
# cache
if [ -n "${OPENSSL}" ]; then
    OPENSSL_DIR="ossl-2/${OPENSSL}"
    if [[ ! -f "$HOME/$OPENSSL_DIR/bin/openssl" ]]; then
        curl -O "https://www.openssl.org/source/openssl-${OPENSSL}.tar.gz"
        tar zxf "openssl-${OPENSSL}.tar.gz"
        pushd "openssl-${OPENSSL}"
        ./config shared no-ssl2 no-ssl3 -fPIC --prefix="$HOME/$OPENSSL_DIR"
        shlib_sed
        make depend
        make -j"$(nproc)"
        # avoid installing the docs
        # https://github.com/openssl/openssl/issues/6685#issuecomment-403838728
        make install_sw install_ssldirs
        popd
    fi
elif [ -n "${LIBRESSL}" ]; then
    LIBRESSL_DIR="ossl-2/${LIBRESSL}"
    if [[ ! -f "$HOME/$LIBRESSL_DIR/bin/openssl" ]]; then
        curl -O "https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${LIBRESSL}.tar.gz"
        tar zxf "libressl-${LIBRESSL}.tar.gz"
        pushd "libressl-${LIBRESSL}"
        ./config -Wl -Wl,-Bsymbolic-functions -fPIC shared --prefix="$HOME/$LIBRESSL_DIR"
        shlib_sed
        make -j"$(nproc)" install
        popd
    fi
fi

if [ -z "${DOWNSTREAM}" ]; then
    git clone --depth=1 https://github.com/google/wycheproof "$HOME/wycheproof"
fi

pip install virtualenv

python -m virtualenv ~/.venv
source ~/.venv/bin/activate
# If we pin coverage it must be kept in sync with tox.ini and Jenkinsfile
pip install tox codecov coverage
