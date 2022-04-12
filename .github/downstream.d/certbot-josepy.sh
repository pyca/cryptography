#!/bin/bash -ex

case "${1}" in
    install)
        # Josepy is pinned to 1.13.0 because the project is migrating to Poetry, and
        # this test is not compatible with it yet.
        #
        # TODO: Update this test with Poetry once a new release of Josepy includes
        #       https://github.com/certbot/josepy/pull/129
        git clone --depth=1 --branch v1.13.0 https://github.com/certbot/josepy
        cd josepy
        git rev-parse HEAD
        pip install -e ".[tests]" -c constraints.txt
        ;;
    run)
        cd josepy
        pytest src
        ;;
    *)
        exit 1
        ;;
esac
