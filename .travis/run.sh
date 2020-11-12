#!/bin/bash -ex

source ~/.venv/bin/activate

downstream_script="${TRAVIS_BUILD_DIR}/.travis/downstream.d/${DOWNSTREAM}.sh"
if [ ! -x "$downstream_script" ]; then
    exit 1
fi
$downstream_script install
pip install .
$downstream_script run
