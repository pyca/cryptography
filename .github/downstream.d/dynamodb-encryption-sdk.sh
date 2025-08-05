#!/bin/bash -ex

case "${1}" in
    install)
        cd aws-dynamodb-encryption-python
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
