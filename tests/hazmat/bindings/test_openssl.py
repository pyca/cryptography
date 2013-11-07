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

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.bindings.openssl.backend import backend, Backend
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC


class FakeMode(object):
    pass


class FakeCipher(object):
    pass


class TestOpenSSL(object):
    def test_backend_exists(self):
        assert backend

    def test_openssl_version_text(self):
        """
        This test checks the value of OPENSSL_VERSION_TEXT.

        Unfortunately, this define does not appear to have a
        formal content definition, so for now we'll test to see
        if it starts with OpenSSL as that appears to be true
        for every OpenSSL.
        """
        assert backend.openssl_version_text().startswith("OpenSSL")

    def test_supports_cipher(self):
        assert backend.ciphers.supported(None, None) is False

    def test_register_duplicate_cipher_adapter(self):
        with pytest.raises(ValueError):
            backend.ciphers.register_cipher_adapter(AES, CBC, None)

    def test_instances_share_ffi(self):
        b = Backend()
        assert b.ffi is backend.ffi
        assert b.lib is backend.lib

    def test_nonexistent_cipher(self):
        b = Backend()
        b.ciphers.register_cipher_adapter(
            FakeCipher,
            FakeMode,
            lambda backend, cipher, mode: backend.ffi.NULL
        )
        cipher = Cipher(
            FakeCipher(), FakeMode(), backend=b,
        )
        with pytest.raises(UnsupportedAlgorithm):
            cipher.encryptor()
