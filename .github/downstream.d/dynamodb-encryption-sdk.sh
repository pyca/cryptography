#!/bin/bash -ex

case "${1}" in
    install)
        git clone --depth=1 https://github.com/awslabs/aws-dynamodb-encryption-python
        cd aws-dynamodb-encryption-python
        git rev-parse HEAD
        uv pip install -e .
        uv pip install -r test/upstream-requirements-py311.txt
        ;;
    run)
        cd aws-dynamodb-encryption-python
        pytest -n auto test/ -m "local and not slow and not veryslow and not nope"
        ;;
    *)
        exit 1
        ;;
esac
