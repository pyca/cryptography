#!/bin/bash -ex

case "${1}" in
    install)
        cd paramiko
        uv --version
        uv sync --inexact --active
        ;;
    run)
        cd paramiko
        # https://github.com/paramiko/paramiko/issues/1927
        inv test || inv test
        ;;
    *)
        exit 1
        ;;
esac
