# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import sys
import pkg_resources

from cryptography.hazmat.backends.multibackend import MultiBackend


def _build_frozen_backend_list():
    # if found frozen then manually try to import known packaged backends
    try:
        from cryptography.hazmat.backends.commoncrypto.backend import backend as be_cc
    except ImportError:
        be_cc = None

    try:
        from cryptography.hazmat.backends.openssl.backend import backend as be_ossl
    except ImportError:
        be_ossl = None

    _found_backends = [be for be in (be_cc, be_ossl) if be is not None]

    return _found_backends

_available_backends_list = None


def _available_backends():
    global _available_backends_list

    if _available_backends_list is None:
        _available_backends_list = [
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

    return _available_backends_list

_default_backend = None


def default_backend():
    global _default_backend

    if _default_backend is None:
        if _available_backends():
            _default_backend = MultiBackend(_available_backends())
        elif getattr(sys, 'frozen', False):
            _default_backend = MultiBackend(_build_frozen_backend_list())

    return _default_backend
