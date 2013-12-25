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

from cryptography import utils
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends.commoncrypto.backend import (
    backend, Backend, GetCipherModeEnum
)
from cryptography.hazmat.primitives import interfaces
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import ECB


class DummyMode(object):
    pass


@utils.register_interface(interfaces.CipherAlgorithm)
class DummyCipher(object):
    pass


class TestCommonCrypto(object):
    def test_backend_exists(self):
        assert backend

    def test_supports_cipher(self):
        assert backend.cipher_supported(None, None) is False

    def test_register_duplicate_cipher_adapter(self):
        with pytest.raises(ValueError):
            backend.register_cipher_adapter(AES, ECB, None)

    def test_instances_share_ffi(self):
        b = Backend()
        assert b.ffi is backend.ffi
        assert b.lib is backend.lib

    def test_nonexistent_cipher(self):
        b = Backend()
        b.register_cipher_adapter(
            DummyCipher,
            ECB,
            GetCipherModeEnum()
        )
        cipher = Cipher(
            DummyCipher(), ECB(), backend=b,
        )
        with pytest.raises(UnsupportedAlgorithm):
            cipher.encryptor()

    def test_nonexistent_mode(self):
        b = Backend()
        b.register_cipher_adapter(
            AES,
            DummyMode,
            GetCipherModeEnum()
        )
        cipher = Cipher(
            AES("\x00"*16), DummyMode(), backend=b,
        )
        with pytest.raises(UnsupportedAlgorithm):
            cipher.encryptor()
