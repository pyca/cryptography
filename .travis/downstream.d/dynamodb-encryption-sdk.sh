#!/bin/bash

case "${1}" in
    install)
        git clone --depth=1 https://github.com/awslabs/aws-dynamodb-encryption-python
        cd aws-dynamodb-encryption-python
        pip install -r test/requirements.txt
        pip install -e .
        ;;
    run)
        cd aws-dynamodb-encryption-python
        pytest -m "local and not slow and not veryslow and not nope"
        ;;
    *)
        exit 1
        ;;
esac
