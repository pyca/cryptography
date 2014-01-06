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
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl.backend import backend, Backend
from cryptography.hazmat.primitives import interfaces
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC


@utils.register_interface(interfaces.Mode)
class DummyMode(object):
    name = "dummy-mode"

    def validate_for_algorithm(self, algorithm):
        pass


@utils.register_interface(interfaces.CipherAlgorithm)
class DummyCipher(object):
    name = "dummy-cipher"


class TestOpenSSL(object):
    def test_backend_exists(self):
        assert backend

    def test_is_default(self):
        assert backend == default_backend()

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
        assert backend.cipher_supported(None, None) is False

    def test_register_duplicate_cipher_adapter(self):
        with pytest.raises(ValueError):
            backend.register_cipher_adapter(AES, CBC, None)

    @pytest.mark.parametrize("mode", [DummyMode(), None])
    def test_nonexistent_cipher(self, mode):
        b = Backend()
        b.register_cipher_adapter(
            DummyCipher,
            type(mode),
            lambda backend, cipher, mode: backend._ffi.NULL
        )
        cipher = Cipher(
            DummyCipher(), mode, backend=b,
        )
        with pytest.raises(UnsupportedAlgorithm):
            cipher.encryptor()

    def test_handle_unknown_error(self):
        with pytest.raises(SystemError):
            backend._handle_error_code(0, 0, 0)

        with pytest.raises(SystemError):
            backend._handle_error_code(backend._lib.ERR_LIB_EVP, 0, 0)

        with pytest.raises(SystemError):
            backend._handle_error_code(
                backend._lib.ERR_LIB_EVP,
                backend._lib.EVP_F_EVP_ENCRYPTFINAL_EX,
                0
            )

        with pytest.raises(SystemError):
            backend._handle_error_code(
                backend._lib.ERR_LIB_EVP,
                backend._lib.EVP_F_EVP_DECRYPTFINAL_EX,
                0
            )
