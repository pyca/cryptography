#!/bin/bash -ex

case "${1}" in
    install)
        cd aws-encryption-sdk-python
        uv pip install -e .
        # cffi 1.15.1 cannot be built for Python 3.14 with GCC 14+, and
        # installing cryptography below replaces it with a current cffi anyway.
        uv pip install -r <(grep -v '^cffi==' test/upstream-requirements-py311.txt)
        ;;
    run)
        cd aws-encryption-sdk-python
        pytest -m local test/ --ignore test/mpl/
        ;;
    *)
        exit 1
        ;;
esac
