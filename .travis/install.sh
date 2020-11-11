#!/bin/bash

set -e
set -x

if [ -z "${DOWNSTREAM}" ]; then
    git clone --depth=1 https://github.com/google/wycheproof "$HOME/wycheproof"
fi

pip install -U pip
pip install virtualenv

python -m virtualenv ~/.venv
source ~/.venv/bin/activate
# If we pin coverage it must be kept in sync with tox.ini and .github/workflows/ci.yml
pip install tox coverage
