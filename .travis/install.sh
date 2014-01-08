#!/bin/bash

set -e
set -x

if [[ "${OPENSSL}" == "0.9.8" ]]; then
    sudo add-apt-repository "deb http://archive.ubuntu.com/ubuntu/ lucid main"
    sudo apt-get -y update
    sudo apt-get install -y --force-yes libssl-dev/lucid
fi

if [[ "$(uname -s)" == "Darwin" ]]; then
    curl -O https://bitbucket.org/pypa/setuptools/raw/bootstrap/ez_setup.py
    sudo python ez_setup.py
    curl -O https://raw.github.com/pypa/pip/master/contrib/get-pip.py
    sudo python get-pip.py
    sudo pip install virtualenv
    if [[ "${TOX_ENV}" == "pypy" ]]; then
        sudo brew install pypy
    fi
else
    sudo apt-get install python-virtualenv

    if [[ "${TOX_ENV}" == "pypy" ]]; then
        sudo add-apt-repository -y ppa:pypy/ppa
        sudo apt-get -y update
        sudo apt-get install -y --force-yes pypy pypy-dev
    fi
fi

virtualenv "VIRTUALENV"
source "./VIRTUALENV/bin/activate"
pip install tox coveralls
