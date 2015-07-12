#!/bin/bash

set -e
set -x

NO_COVERAGE_TOXENVS=(pypy pypy3 pep8 py3pep8 docs)
if ! [[ "${NO_COVERAGE_TOXENVS[*]}" =~ "${TOXENV}" ]]; then
    source ~/.venv/bin/activate
    bash <(curl -s https://codecov.io/bash) -e TRAVIS_OS_NAME,TOXENV,OPENSSL
fi
