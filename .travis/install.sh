#!/bin/bash

set -e
set -x

if [[ "$(uname -s)" == 'Darwin' ]]; then
    DARWIN=true
else
    DARWIN=false
fi

if [[ "${OPENSSL}" == "0.9.8" ]]; then
    if [[ "$DARWIN" = false ]]; then
        sudo add-apt-repository "deb http://archive.ubuntu.com/ubuntu/ lucid main"
        sudo apt-get -y update
        sudo apt-get install -y --force-yes libssl-dev/lucid
    fi
else
    if [[ "$DARWIN" = true ]]; then
        brew update
        brew upgrade openssl
    fi
fi

if [[ "${TOX_ENV}" == "docs" ]]; then
    if [[ "$DARWIN" = true ]]; then
        brew update
        brew install enchant
    else
        sudo apt-get -y update
        sudo apt-get install libenchant-dev
    fi
fi

if [[ "$DARWIN" = true ]]; then
    if which pyenv > /dev/null; then
        eval "$(pyenv init -)"
    fi

    case "${TOX_ENV}" in
        py26)
            curl -O https://bootstrap.pypa.io/get-pip.py
            sudo python get-pip.py
            sudo pip install virtualenv
            ;;
        py27)
            curl -O https://bootstrap.pypa.io/get-pip.py
            sudo python get-pip.py
            sudo pip install virtualenv
            ;;
        pypy)
            brew update
            brew upgrade pyenv
            pyenv install pypy-2.4.0
            pyenv global pypy-2.4.0
            pip install virtualenv
            ;;
        py32)
            pyenv install 3.2.5
            pyenv global 3.2.5
            pip install virtualenv
            ;;
        py33)
            pyenv install 3.3.5
            pyenv global 3.3.5
            pip install virtualenv
            ;;
        py34)
            pyenv install 3.4.1
            pyenv global 3.4.1
            pip install virtualenv
            ;;
        docs)
            curl -O https://bootstrap.pypa.io/get-pip.py
            sudo python get-pip.py
            sudo pip install virtualenv
            ;;
    esac
    pyenv rehash
else
    # add mega-python ppa
    sudo add-apt-repository -y ppa:fkrull/deadsnakes
    sudo apt-get -y update

    case "${TOX_ENV}" in
        py26)
            sudo apt-get install python2.6 python2.6-dev
            ;;
        py32)
            sudo apt-get install python3.2 python3.2-dev
            ;;
        py33)
            sudo apt-get install python3.3 python3.3-dev
            ;;
        py34)
            sudo apt-get install python3.4 python3.4-dev
            ;;
        py3pep8)
            sudo apt-get install python3.3 python3.3-dev
            ;;
        pypy)
            sudo add-apt-repository -y ppa:pypy/ppa
            sudo apt-get -y update
            sudo apt-get install -y --force-yes pypy pypy-dev
            ;;
    esac
    sudo pip install virtualenv
fi

virtualenv ~/.venv
source ~/.venv/bin/activate
pip install tox coveralls
