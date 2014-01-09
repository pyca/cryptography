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
    case "${TOX_ENV}" in
        pypy)
            sudo brew install pypy
            ;;
        py32)
            sudo brew install python32
            ;;
        py33)
            sudo brew install python3
            ;;
    esac
else
    sudo apt-get install python-virtualenv

    case "${TOX_ENV}" in
        py26)
            sudo apt-get install python2.6
            ;;
        py32)
            sudo apt-get install python3.2
            ;;
        py33)
            sudo apt-get install python3.3
            ;;
        pypy)
            sudo add-apt-repository -y ppa:pypy/ppa
            sudo apt-get -y update
            sudo apt-get install -y --force-yes pypy pypy-dev
            ;;
    esac
fi

virtualenv "~/VIRTUALENV"
source "~/VIRTUALENV/bin/activate"
pip install tox coveralls
