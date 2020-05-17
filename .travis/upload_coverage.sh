#!/bin/bash

set -e
set -x

if [ -n "${TOXENV}" ]; then
    case "${TOXENV}" in
        pypy-nocoverage);;
        pypy3-nocoverage);;
        pep8);;
        py3pep8);;
        docs);;
        *)
            source ~/.venv/bin/activate
            curl -o codecov.sh -f https://codecov.io/bash || curl -o codecov.sh -f https://codecov.io/bash || curl -o codecov.sh -f https://codecov.io/bash

            bash codecov.sh -Z -e TRAVIS_OS_NAME,TOXENV,OPENSSL,DOCKER || \
                bash codecov.sh -Z -e TRAVIS_OS_NAME,TOXENV,OPENSSL,DOCKER
            ;;
    esac
fi
