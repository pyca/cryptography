#!/bin/bash

set -e
set -x

if [[ "$(uname -s)" == 'Darwin' ]]; then
    brew update

    if [[ "${OPENSSL}" != "0.9.8" ]]; then
        brew upgrade openssl
    fi

    if which pyenv > /dev/null; then
        eval "$(pyenv init -)"
    fi

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
            brew upgrade pyenv
            pyenv install 3.3.6
            pyenv global 3.3.6
            ;;
        py34)
            brew upgrade pyenv
            pyenv install 3.4.2
            pyenv global 3.4.2
            ;;
        pypy)
            brew upgrade pyenv
            pyenv install pypy-2.5.1
            pyenv global pypy-2.5.1
            ;;
        pypy3)
            brew upgrade pyenv
            pyenv install pypy3-2.4.0
            pyenv global pypy3-2.4.0
            ;;
        docs)
            curl -O https://bootstrap.pypa.io/get-pip.py
            python get-pip.py --user
            ;;
    esac
    pyenv rehash
    pip install --user virtualenv
else
    pip install virtualenv
fi

python -m virtualenv ~/.venv
source ~/.venv/bin/activate
pip install tox coveralls
