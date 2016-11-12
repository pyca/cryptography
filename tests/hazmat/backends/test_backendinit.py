# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography.hazmat.backends import _backend_import_fallback


def test_backend_import_fallback_empty_backends():
    backends = _backend_import_fallback([])
    assert len(backends) >= 1


def test_backend_import_fallback_existing_backends():
    backend_list = [1, 2, 3, 4]
    assert backend_list == _backend_import_fallback(backend_list)
