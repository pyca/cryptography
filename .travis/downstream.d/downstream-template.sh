#!/bin/bash

case "${1}" in
    install)
        # Download source and install requirements
        ;;
    run)
        # Run tests
        ;;
    *)
        exit 1
        ;;
esac
