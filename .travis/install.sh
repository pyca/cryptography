#!/bin/bash

set -e
set -x

if [[ "${OPENSSL}" == "0.9.8" ]]; then
    sudo add-apt-repository "deb http://archive.ubuntu.com/ubuntu/ lucid main"
    sudo apt-get -y update
    sudo apt-get install -y --force-yes libssl-dev/lucid
fi

pip install tox coveralls
