# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


from cryptography.hazmat.backends import _get_backend, default_backend


def test_get_backend_no_backend():
    assert _get_backend(None) is default_backend()


def test_get_backend():
    faux_backend = object()
    assert _get_backend(faux_backend) is faux_backend
