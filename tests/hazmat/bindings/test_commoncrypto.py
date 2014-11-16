# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import pytest

from cryptography.hazmat.backends import _available_backends
from cryptography.hazmat.bindings.commoncrypto.binding import Binding


@pytest.mark.skipif("commoncrypto" not in
                    [i.name for i in _available_backends()],
                    reason="CommonCrypto not available")
class TestCommonCrypto(object):
    def test_binding_loads(self):
        binding = Binding()
        assert binding
        assert binding.lib
        assert binding.ffi

    def test_binding_returns_same_lib(self):
        binding = Binding()
        binding2 = Binding()
        assert binding.lib == binding2.lib
        assert binding.ffi == binding2.ffi
