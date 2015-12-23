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
        py26)
            curl -O https://bootstrap.pypa.io/get-pip.py
            python get-pip.py --user
            ;;
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
        pypy)
            pyenv install pypy-4.0.1
            pyenv global pypy-4.0.1
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
    # temporary pyenv installation to get latest pypy before container infra upgrade
    # now using the -latest because of a segfault bug we're encountering in 2.6.1
    if [[ "${TOXENV}" == "pypy" ]]; then
        git clone https://github.com/yyuu/pyenv.git ~/.pyenv
        PYENV_ROOT="$HOME/.pyenv"
        PATH="$PYENV_ROOT/bin:$PATH"
        eval "$(pyenv init -)"
        pyenv install pypy-4.0.1
        pyenv global pypy-4.0.1
    fi
    if [[ "${OPENSSL}" == "0.9.8" ]]; then
      # download, compile, and install if it's not already present via travis cache
      if [[ ! -f "$HOME/ossl-098/bin/openssl" ]]; then
        curl -O https://www.openssl.org/source/openssl-0.9.8zh.tar.gz
        tar zxvf openssl-0.9.8zh.tar.gz
        cd openssl-0.9.8zh
        echo "OPENSSL_0.9.8ZH_CUSTOM {
            global:
              *;
        };" > openssl.ld
        ./config no-ssl2 -Wl,--version-script=openssl.ld -Wl,-Bsymbolic-functions -fPIC shared --prefix=$HOME/ossl-098
        make depend
        make install
      fi
      export PATH="$HOME/ossl-098/bin:$PATH"
      export CFLAGS="-I$HOME/ossl-098/include"
      export LDFLAGS="-L$HOME/ossl-098/lib"
      export LD_LIBRARY_PATH="$HOME/ossl-098/lib"
    fi
    pip install virtualenv
fi

python -m virtualenv ~/.venv
source ~/.venv/bin/activate
pip install tox codecov
