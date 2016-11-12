# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import pkg_resources

from cryptography.hazmat.backends.multibackend import MultiBackend


_available_backends_list = None


def _available_backends():
    global _available_backends_list

    if _available_backends_list is None:
        _entry_point_backends = [
            # DeprecatedIn16
            # setuptools 11.3 deprecated support for the require parameter to
            # load(), and introduced the new resolve() method instead.
            # We previously removed this fallback, but users are having issues
            # where Python loads an older setuptools due to various syspath
            # weirdness.
            ep.resolve() if hasattr(ep, "resolve") else ep.load(require=False)
            for ep in pkg_resources.iter_entry_points(
                "cryptography.backends"
            )
        ]

        _available_backends_list = _backend_import_fallback(
            _entry_point_backends
        )

    return _available_backends_list


def _backend_import_fallback(backends):
    # If backends already exist just return them. This branch is here
    # to get full line coverage from our tests.
    if backends:
        return backends

    # if iter_entry_points fails to find any backends then manually try to
    # import our current backends as a workaround for issues with application
    # bundlers like pyinstaller, cx_freeze, etc

    # OpenSSL is guaranteed to be present until we unbundle the backends.
    from cryptography.hazmat.backends.openssl.backend import backend as be_ossl

    try:
        # CommonCrypto will only be present on macOS so failure is possible.
        from cryptography.hazmat.backends.commoncrypto.backend import (
            backend as be_cc
        )
    except ImportError:
        be_cc = None

    _found_backends = [be for be in (be_cc, be_ossl) if be is not None]

    return _found_backends


_default_backend = None


def default_backend():
    global _default_backend

    if _default_backend is None:
        _default_backend = MultiBackend(_available_backends())

    return _default_backend
