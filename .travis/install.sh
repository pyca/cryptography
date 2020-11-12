#!/bin/bash

set -e
set -x

pip install -U pip
pip install virtualenv

python -m virtualenv ~/.venv
source ~/.venv/bin/activate
# If we pin coverage it must be kept in sync with tox.ini and .github/workflows/ci.yml
pip install tox coverage
