# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
