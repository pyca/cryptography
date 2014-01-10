#!/bin/bash

set -e
set -x

if [[ "${OPENSSL}" == "0.9.8" && "$(uname -s)" != "Darwin" ]]; then
    sudo add-apt-repository "deb http://archive.ubuntu.com/ubuntu/ lucid main"
    sudo apt-get -y update
    sudo apt-get install -y --force-yes libssl-dev/lucid
fi

if [[ "$(uname -s)" == "Darwin" ]]; then
    brew update
    brew install pyenv
    if which pyenv > /dev/null; then eval "$(pyenv init -)"; fi
    case "${TOX_ENV}" in
        py26)
            curl -O https://raw.github.com/pypa/pip/master/contrib/get-pip.py
            sudo python get-pip.py
            sudo pip install setuptools --no-use-wheel --upgrade
            sudo pip install virtualenv
            ;;
        py27)
            curl -O https://raw.github.com/pypa/pip/master/contrib/get-pip.py
            sudo python get-pip.py
            sudo pip install setuptools --no-use-wheel --upgrade
            sudo pip install virtualenv
            ;;
        pypy)
            pyenv install pypy-2.2.1
            pyenv global pypy-2.2.1
            pip install virtualenv
            ;;
        py32)
            pyenv install 3.2.5
            pyenv global 3.2.5
            pip install virtualenv
            ;;
        py33)
            pyenv install 3.3.2
            pyenv global 3.3.2
            pip install virtualenv
            ;;
    esac
    pyenv rehash
    if [[ "${OPENSSL}" != "0.9.8" ]]; then
        curl -O https://langui.sh/travis/openssl-1.0.1f.mavericks.bottle.tar.gz
        brew install openssl-1.0.1f.mavericks.bottle.tar.gz
    fi
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

if [[ "$(uname -s)" == "Darwin" ]]; then
    pyenv rehash
fi
