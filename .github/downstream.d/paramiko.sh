#!/bin/bash -ex

case "${1}" in
    install)
        git clone --depth=1 https://github.com/paramiko/paramiko
        cd paramiko
        git rev-parse HEAD
        pip install -e .
        pip install -r dev-requirements.txt
        ;;
    run)
        cd paramiko
        inv test
        ;;
    *)
        exit 1
        ;;
esac
