#!/bin/bash

set -e
set -x

if [[ "$(uname -s)" == 'Darwin' ]]; then
    brew update || brew update

    brew outdated openssl || brew upgrade openssl

    # install pyenv
    git clone https://github.com/yyuu/pyenv.git ~/.pyenv
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
            pyenv install 3.4.4
            pyenv global 3.4.4
            ;;
        py35)
            pyenv install 3.5.1
            pyenv global 3.5.1
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
        git clone https://github.com/yyuu/pyenv.git ~/.pyenv
        PYENV_ROOT="$HOME/.pyenv"
        PATH="$PYENV_ROOT/bin:$PATH"
        eval "$(pyenv init -)"
        pyenv install "pypy-$PYPY_VERSION"
        pyenv global "pypy-$PYPY_VERSION"
    fi

    if [[ "${OPENSSL}" == "1.0.0" ]]; then
        OPENSSL_VERSION_NUMBER="1.0.0t"
        OPENSSL_DIR="ossl-100t"
    fi
    # download, compile, and install if it's not already present via travis
    # cache
    if [ -n "$OPENSSL_DIR" ]; then
        if [[ ! -f "$HOME/$OPENSSL_DIR/bin/openssl" ]]; then
            curl -O https://www.openssl.org/source/openssl-$OPENSSL_VERSION_NUMBER.tar.gz
            tar zxf openssl-$OPENSSL_VERSION_NUMBER.tar.gz
            cd openssl-$OPENSSL_VERSION_NUMBER
            ./config shared no-asm no-ssl2 -fPIC --prefix="$HOME/$OPENSSL_DIR"
            # modify the shlib version to a unique one to make sure the dynamic
            # linker doesn't load the system one.
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
