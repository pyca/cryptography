#!/bin/bash

set -e
set -x

if [[ "${OPENSSL}" == "0.9.8" ]]; then
    sudo add-apt-repository "deb http://archive.ubuntu.com/ubuntu/ lucid main"
fi

if [[ "${TOX_ENV}" == "pypy" ]]; then
    sudo add-apt-repository -y ppa:pypy/ppa
fi

sudo apt-get -y update

if [[ "${OPENSSL}" == "0.9.8" ]]; then
    sudo apt-get install -y --force-yes libssl-dev/lucid
fi

if [[ "${TOX_ENV}" == "pypy" ]]; then
    sudo apt-get install -y pypy

    # This is required because we need to get rid of the Travis installed PyPy
    # or it'll take precedence over the PPA installed one.
    sudo rm -rf /usr/local/pypy/bin
fi

pip install tox coveralls
