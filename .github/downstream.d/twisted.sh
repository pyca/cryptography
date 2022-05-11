#!/bin/bash -ex

case "${1}" in
    install)
        git clone --depth=1 https://github.com/twisted/twisted
        cd twisted
        git rev-parse HEAD
        pip install ".[all_non_platform]"
        ;;
    run)
        cd twisted
        # TODO: temporarily restrict which tests we run on request from @glyph
        # python -m twisted.trial src/twisted
        python -m twisted.trial twisted.conch twisted.internet.test.test_tls twisted.protocols.test.test_tls
        ;;
    *)
        exit 1
        ;;
esac
