#!/bin/bash

case "${1}" in
    install)
        git clone --depth=1 https://github.com/awslabs/aws-encryption-sdk-python
        cd aws-encryption-sdk-python
        pip install -r test/upstream-requirements-py27.txt
        pip install -e .
        ;;
    run)
        cd aws-encryption-sdk-python
        pytest -m local test/
        ;;
    *)
        exit 1
        ;;
esac
