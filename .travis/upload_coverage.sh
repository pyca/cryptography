#!/bin/bash

set -e
set -x

NO_COVERAGE_TOXENVS=(pypy3 pep8 py3pep8 docs)
if ! [[ "${NO_COVERAGE_TOXENVS[*]}" =~ "${TOXENV}" ]]; then
    source ~/.venv/bin/activate
    codecov --env TRAVIS_OS_NAME,TOXENV,OPENSSL
fi
