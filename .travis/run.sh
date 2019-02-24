#!/bin/bash -ex

SCRIPT_DIR=$(dirname "${BASH_SOURCE[0]}")

if [[ "${TOXENV}" == "pypy" ]]; then
    PYENV_ROOT="$HOME/.pyenv"
    PATH="$PYENV_ROOT/bin:$PATH"
    eval "$(pyenv init -)"
fi
if [ -n "${LIBRESSL}" ]; then
    LIBRESSL_DIR="ossl-2/${LIBRESSL}"
    export CFLAGS="-Werror -Wno-error=deprecated-declarations -Wno-error=discarded-qualifiers -Wno-error=unused-function -I$HOME/$LIBRESSL_DIR/include"
    export PATH="$HOME/$LIBRESSL_DIR/bin:$PATH"
    export LDFLAGS="-L$HOME/$LIBRESSL_DIR/lib -Wl,-rpath=$HOME/$LIBRESSL_DIR/lib"
fi

if [ -n "${OPENSSL}" ]; then
    . "$SCRIPT_DIR/openssl_config.sh"
    export PATH="$HOME/$OPENSSL_DIR/bin:$PATH"
    export CFLAGS="${CFLAGS} -I$HOME/$OPENSSL_DIR/include"
    # rpath on linux will cause it to use an absolute path so we don't need to
    # do LD_LIBRARY_PATH
    export LDFLAGS="-L$HOME/$OPENSSL_DIR/lib -Wl,-rpath=$HOME/$OPENSSL_DIR/lib"
fi

source ~/.venv/bin/activate

if [ -n "${DOCKER}" ]; then
    # We will be able to drop the -u once we switch the default container user in the
    # dockerfiles.
    docker run --rm -u 2000:2000 \
        -v "${TRAVIS_BUILD_DIR}":"${TRAVIS_BUILD_DIR}" \
        -v "${HOME}/wycheproof":/wycheproof \
        -w "${TRAVIS_BUILD_DIR}" \
        -e TOXENV "${DOCKER}" \
        /bin/sh -c "tox -- --wycheproof-root='/wycheproof'"
elif [ -n "${TOXENV}" ]; then
    tox -- --wycheproof-root="$HOME/wycheproof"
else
    downstream_script="${TRAVIS_BUILD_DIR}/.travis/downstream.d/${DOWNSTREAM}.sh"
    if [ ! -x "$downstream_script" ]; then
        exit 1
    fi
    $downstream_script install
    pip install .
    $downstream_script run
fi
