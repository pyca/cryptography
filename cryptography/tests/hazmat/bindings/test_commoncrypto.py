# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import pytest


ccbinding = pytest.importorskip(
    "cryptography.hazmat.bindings.commoncrypto.binding"
)


class TestCommonCrypto(object):
    def test_binding_loads(self):
        binding = ccbinding.Binding()
        assert binding
        assert binding.lib
        assert binding.ffi

    def test_binding_returns_same_lib(self):
        binding = ccbinding.Binding()
        binding2 = ccbinding.Binding()
        assert binding.lib == binding2.lib
        assert binding.ffi == binding2.ffi
