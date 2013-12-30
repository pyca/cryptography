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

import threading

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

    def test_ssl_ciphers_registered(self):
        meth = backend._lib.TLSv1_method()
        ctx = backend._lib.SSL_CTX_new(meth)
        assert ctx != backend._ffi.NULL
        backend._lib.SSL_CTX_free(ctx)

    def test_evp_ciphers_registered(self):
        cipher = backend._lib.EVP_get_cipherbyname(b"aes-256-cbc")
        assert cipher != backend._ffi.NULL

    def test_error_strings_loaded(self):
        # returns a value in a static buffer
        err = backend._lib.ERR_error_string(101183626, backend._ffi.NULL)
        assert backend._ffi.string(err) == (
            b"error:0607F08A:digital envelope routines:EVP_EncryptFinal_ex:"
            b"data not multiple of block length"
        )

    def test_locking_callback_set(self):
        b = Backend()

        locking_cb = b.lib.CRYPTO_get_locking_callback()
        assert locking_cb != b.ffi.NULL

        # emulate import _ssl not setting this for some reason
        b.lib.CRYPTO_set_locking_callback(b.ffi.NULL)

        # force cffi to reinit
        Backend.ffi = None
        Backend.lib = None

        # now it should get set to our one
        b = Backend()
        locking_cb = b.lib.CRYPTO_get_locking_callback()

        assert locking_cb != b.ffi.NULL
        assert locking_cb == b.lib.Cryptography_locking_function_ptr

    def test_threads(self):
        b = Backend()

        def randloop():
            s = b.ffi.new("char[]", 16)
            sb = b.ffi.buffer(s)
            sb[:] = b"\0" * 16

            for i in range(300000):
                b.lib.RAND_seed(s, 16)

        threads = []
        for x in range(3):
            t = threading.Thread(target=randloop)
            t.daemon = True
            t.start()

            threads.append(t)

        while threads:
            for t in threads:
                t.join(0.1)
                if not t.isAlive():
                    threads.remove(t)
