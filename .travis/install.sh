#!/bin/bash

set -e
set -x

if [[ "$(uname -s)" == 'Darwin' ]]; then
    sw_vers
    brew update || brew update

    brew outdated openssl || brew upgrade openssl

    # install pyenv
    git clone --depth 1 https://github.com/pyenv/pyenv ~/.pyenv
    PYENV_ROOT="$HOME/.pyenv"
    PATH="$PYENV_ROOT/bin:$PATH"
    eval "$(pyenv init -)"

    case "${TOXENV}" in
        py27)
            curl -O https://bootstrap.pypa.io/get-pip.py
            python get-pip.py --user
            ;;
        py33)
            pyenv install 3.3.6
            pyenv global 3.3.6
            ;;
        py34)
            pyenv install 3.4.5
            pyenv global 3.4.5
            ;;
        py35)
            pyenv install 3.5.2
            pyenv global 3.5.2
            ;;
        py36)
            pyenv install 3.6.0
            pyenv global 3.6.0
            ;;
        pypy*)
            pyenv install "pypy-$PYPY_VERSION"
            pyenv global "pypy-$PYPY_VERSION"
            ;;
        pypy3)
            pyenv install pypy3-2.4.0
            pyenv global pypy3-2.4.0
            ;;
        docs)
            brew install enchant
            curl -O https://bootstrap.pypa.io/get-pip.py
            python get-pip.py --user
            ;;
    esac
    pyenv rehash
    python -m pip install --user virtualenv
else
    # temporary pyenv installation to get latest pypy until the travis
    # container infra is upgraded
    if [[ "${TOXENV}" = pypy* ]]; then
        rm -rf ~/.pyenv
        git clone https://github.com/pyenv/pyenv ~/.pyenv
        PYENV_ROOT="$HOME/.pyenv"
        PATH="$PYENV_ROOT/bin:$PATH"
        eval "$(pyenv init -)"
        pyenv install "pypy-$PYPY_VERSION"
        pyenv global "pypy-$PYPY_VERSION"
    fi

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
fi

python -m virtualenv ~/.venv
source ~/.venv/bin/activate
pip install tox codecov
