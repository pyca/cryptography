#!/bin/bash -ex

case "${1}" in
    install)
        git clone --depth=1 https://github.com/awslabs/aws-encryption-sdk-python
        cd aws-encryption-sdk-python
        git rev-parse HEAD
        uv pip install -e .
        uv pip install -r test/upstream-requirements-py311.txt
        ;;
    run)
        cd aws-encryption-sdk-python
        pytest -m local test/ --ignore test/mpl/
        ;;
    *)
        exit 1
        ;;
esac
