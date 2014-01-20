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

from cryptography.hazmat.bindings.commoncrypto.binding import Binding
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC


@pytest.mark.skipif(not Binding.is_available(),
                    reason="CommonCrypto not available")
class TestCommonCrypto(object):
    def test_supports_cipher(self):
        from cryptography.hazmat.backends.commoncrypto.backend import backend
        assert backend.cipher_supported(None, None) is False

    def test_register_duplicate_cipher_adapter(self):
        from cryptography.hazmat.backends.commoncrypto.backend import backend
        with pytest.raises(ValueError):
            backend.register_cipher_adapter(AES, CBC, None)
