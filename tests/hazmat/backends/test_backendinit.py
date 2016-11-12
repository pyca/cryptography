# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography.hazmat.backends import _build_frozen_backend_list


def test_build_frozen_backend_list():
    backends = _build_frozen_backend_list()
    assert len(backends) >= 1
