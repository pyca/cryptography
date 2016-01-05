#!/bin/bash

set -e
set -x

case "${TOXENV}" in
    pypy-nocoverage);;
    pep8);;
    py3pep8);;
    docs);;
    *)
        source ~/.venv/bin/activate
        codecov --env TRAVIS_OS_NAME,TOXENV,OPENSSL
        ;;
esac
