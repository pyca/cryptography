# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import pkg_resources

from cryptography.hazmat.backends.multibackend import MultiBackend

try:
    from cryptography.hazmat.backends.commoncrypto.backend import backend as be_cc
except ImportError:
    be_cc = None

try:
    from cryptography.hazmat.backends.openssl.backend import backend as be_ossl
except ImportError:
    be_ossl = None

_found_backends = [be for be in (be_cc, be_ossl) if be is not None]
_available_backends_list = None

def _available_backends():
    global _available_backends_list

    if _available_backends_list is None:
        _available_backends_list = [
            ep.resolve()
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
        elif _found_backends:
            _default_backend = MultiBackend(_found_backends)

    return _default_backend
