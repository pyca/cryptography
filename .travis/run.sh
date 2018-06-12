#!/bin/bash

set -e
set -x

if [[ "${TOXENV}" == "pypy" ]]; then
    PYENV_ROOT="$HOME/.pyenv"
    PATH="$PYENV_ROOT/bin:$PATH"
    eval "$(pyenv init -)"
fi
if [ -n "${LIBRESSL}" ]; then
    OPENSSL=$LIBRESSL
fi
if [ -n "${OPENSSL}" ]; then
    OPENSSL_DIR="ossl-1/${OPENSSL}"

    export PATH="$HOME/$OPENSSL_DIR/bin:$PATH"
    export CFLAGS="-I$HOME/$OPENSSL_DIR/include"
    # rpath on linux will cause it to use an absolute path so we don't need to
    # do LD_LIBRARY_PATH
    export LDFLAGS="-L$HOME/$OPENSSL_DIR/lib -Wl,-rpath=$HOME/$OPENSSL_DIR/lib"
fi

source ~/.venv/bin/activate

if [ -n "${TOXENV}" ]; then
    tox
else
    pip install .
    case "${DOWNSTREAM}" in
        pyopenssl)
            git clone --depth=1 https://github.com/pyca/pyopenssl
            cd pyopenssl
            pip install -e ".[test]"
            pytest tests
            ;;
        twisted)
            git clone --depth=1 https://github.com/twisted/twisted
            cd twisted
            pip install -e .[tls,conch,http2]
            python -m twisted.trial src/twisted
            ;;
        paramiko)
            git clone --depth=1 https://github.com/paramiko/paramiko
            cd paramiko
            pip install -e .
            pip install -r dev-requirements.txt
            inv test
            ;;
        aws-encryption-sdk)
            git clone --depth=1 https://github.com/awslabs/aws-encryption-sdk-python
            cd aws-encryption-sdk-python
            pip install -r test/requirements.txt
            pip install -e .
            pytest -m local -l
            ;;
        dynamodb-encryption-sdk)
            git clone --depth=1 https://github.com/awslabs/aws-dynamodb-encryption-python
            cd aws-dynamodb-encryption-python
            pip install -r test/requirements.txt
            pip install -e .
            pytest -m "local and not slow and not veryslow and not nope" -l
            ;;
        certbot)
            git clone --depth=1 https://github.com/certbot/certbot
            cd certbot
            pip install pytest pytest-mock mock
            pip install -e acme
            pip install -e .
            pytest certbot/tests
            pytest acme
            ;;
        certbot-josepy)
            git clone --depth=1 https://github.com/certbot/josepy
            cd josepy
            pip install -e ".[tests]"
            pytest src
            ;;
        urllib3)
            git clone --depth 1 https://github.com/shazow/urllib3
            cd urllib3
            pip install -r ./dev-requirements.txt
            pip install -e ".[socks]"
            pytest test
            ;;
        *)
            exit 1
            ;;
    esac
fi
