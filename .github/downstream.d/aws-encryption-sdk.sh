#!/bin/bash -ex

case "${1}" in
    install)
        cd aws-encryption-sdk-python
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
