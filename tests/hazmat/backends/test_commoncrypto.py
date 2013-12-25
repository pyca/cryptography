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

import pytest


@pytest.mark.commoncrypto
class TestCommonCrypto(object):
    def test_backend_exists(self):
        from cryptography.hazmat.backends.commoncrypto.backend import backend
        assert backend

    def test_instances_share_ffi(self):
        from cryptography.hazmat.backends.commoncrypto.backend import backend
        from cryptography.hazmat.backends.commoncrypto.backend import Backend
        b = Backend()
        assert b.ffi is backend.ffi
        assert b.lib is backend.lib
