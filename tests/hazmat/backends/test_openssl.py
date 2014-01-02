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

import cffi

import pytest

from cryptography import utils
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl.backend import backend, Backend
from cryptography.hazmat.primitives import interfaces
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC


ffi = cffi.FFI()

ffi.cdef("""
static const char *const Cryptography_faux_engine_name;
static const char *const Cryptography_faux_engine_id;
int Cryptography_add_faux_engine(void);
""")
dummy_engine = ffi.verify(
    source="""
        #include <openssl/engine.h>
        #include <string.h>
        static const char *const Cryptography_faux_engine_name="faux_engine";
        static const char *const Cryptography_faux_engine_id="faux";
        static int faux_bytes(unsigned char *buffer, int size) {
            memset(buffer, 1, size);
            return 1;
        }
        static int faux_status(void) { return 1; }
        static int faux_init(ENGINE *e) { return 1; }
        static int faux_finish(ENGINE *e) { return 1; }
        static RAND_METHOD faux_rand = {
            NULL,
            faux_bytes,
            NULL,
            NULL,
            faux_bytes,
            faux_status,
        };

        int Cryptography_add_faux_engine(void) {
            ENGINE *e = ENGINE_new();
            if (e == NULL) {
                return 0;
            }
            if(!ENGINE_set_id(e, Cryptography_faux_engine_id) ||
                    !ENGINE_set_name(e, Cryptography_faux_engine_name) ||
                    !ENGINE_set_RAND(e, &faux_rand) ||
                    !ENGINE_set_init_function(e, faux_init) ||
                    !ENGINE_set_finish_function(e, faux_finish)) {
                return 0;
            }
            if (!ENGINE_add(e)) {
                ENGINE_free(e);
                return 0;
            }
            if (!ENGINE_free(e)) {
                return 0;
            }

            return 1;
        }
    """,
    libraries=["crypto", "ssl"],
)


def register_dummy_engine():
    current_rand = backend.lib.ENGINE_get_default_RAND()
    assert current_rand != backend.ffi.NULL
    name = backend.lib.ENGINE_get_name(current_rand)
    assert name != backend.ffi.NULL
    assert name != dummy_engine.Cryptography_faux_engine_id
    res = backend.lib.ENGINE_finish(current_rand)
    assert res == 1
    e = backend.lib.ENGINE_by_id(dummy_engine.Cryptography_faux_engine_id)
    assert e != backend.ffi.NULL
    res = backend.lib.ENGINE_init(e)
    assert res == 1
    res = backend.lib.ENGINE_set_default_RAND(e)
    assert res == 1
    res = backend.lib.ENGINE_finish(e)
    assert res == 1
    res = backend.lib.ENGINE_free(e)
    assert res == 1
    # this resets the RNG to use the new engine
    backend.lib.RAND_cleanup()


def unregister_dummy_engine():
    e = backend.lib.ENGINE_get_default_RAND()
    if e != backend.ffi.NULL:
        name = backend.lib.ENGINE_get_name(e)
        assert name != backend.ffi.NULL
        if name == dummy_engine.Cryptography_faux_engine_name:
            backend.lib.ENGINE_unregister_RAND(e)
            backend.lib.RAND_cleanup()
        res = backend.lib.ENGINE_finish(e)
        assert res == 1


@utils.register_interface(interfaces.Mode)
class DummyMode(object):
    name = "dummy-mode"


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

    # This test is not in the next class because to check if it's really
    # default we don't want to run the setup_method before it
    def test_osrandom_engine_is_default(self):
        e = backend.lib.ENGINE_get_default_RAND()
        name = backend.lib.ENGINE_get_name(e)
        assert name == backend.lib.Cryptography_osrandom_engine_name
        res = backend.lib.ENGINE_free(e)
        assert res == 1


class TestOpenSSLRandomEngine(object):
    @classmethod
    def setup_class(cls):
        # add the faux engine to the list of available engines
        res = dummy_engine.Cryptography_add_faux_engine()
        assert res == 1

    def teardown_method(self, method):
        # we need to reset state to being default. backend is a shared global
        # for all these tests.
        unregister_dummy_engine()
        backend.register_osrandom_engine()
        current_default = backend.lib.ENGINE_get_default_RAND()
        name = backend.lib.ENGINE_get_name(current_default)
        assert name == backend.lib.Cryptography_osrandom_engine_name

    def test_register_osrandom_already_default(self):
        e = backend.lib.ENGINE_get_default_RAND()
        name = backend.lib.ENGINE_get_name(e)
        assert name == backend.lib.Cryptography_osrandom_engine_name
        res = backend.lib.ENGINE_free(e)
        assert res == 1
        backend.register_osrandom_engine()
        e = backend.lib.ENGINE_get_default_RAND()
        name = backend.lib.ENGINE_get_name(e)
        assert name == backend.lib.Cryptography_osrandom_engine_name
        res = backend.lib.ENGINE_free(e)
        assert res == 1

    def test_unregister_osrandom_engine_nothing_registered(self):
        backend.unregister_osrandom_engine()
        e = backend.lib.ENGINE_get_default_RAND()
        assert e == backend.ffi.NULL
        backend.unregister_osrandom_engine()
        e = backend.lib.ENGINE_get_default_RAND()
        assert e == backend.ffi.NULL

    def test_unregister_osrandom_engine(self):
        e = backend.lib.ENGINE_get_default_RAND()
        assert e != backend.ffi.NULL
        name = backend.lib.ENGINE_get_name(e)
        assert name == backend.lib.Cryptography_osrandom_engine_name
        res = backend.lib.ENGINE_free(e)
        assert res == 1
        backend.unregister_osrandom_engine()
        e = backend.lib.ENGINE_get_default_RAND()
        assert e == backend.ffi.NULL

    def test_register_osrandom_no_default(self):
        backend.unregister_osrandom_engine()
        e = backend.lib.ENGINE_get_default_RAND()
        assert e == backend.ffi.NULL
        backend.register_osrandom_engine()
        e = backend.lib.ENGINE_get_default_RAND()
        name = backend.lib.ENGINE_get_name(e)
        assert name == backend.lib.Cryptography_osrandom_engine_name
        res = backend.lib.ENGINE_free(e)
        assert res == 1

    def test_unregister_osrandom_other_engine_default(self):
        register_dummy_engine()
        default = backend.lib.ENGINE_get_default_RAND()
        default_name = backend.lib.ENGINE_get_name(default)
        assert default_name == dummy_engine.Cryptography_faux_engine_name
        res = backend.lib.ENGINE_finish(default)
        assert res == 1
        backend.unregister_osrandom_engine()
        current_default = backend.lib.ENGINE_get_default_RAND()
        name = backend.lib.ENGINE_get_name(current_default)
        assert name == dummy_engine.Cryptography_faux_engine_name
        res = backend.lib.ENGINE_finish(current_default)
        assert res == 1

    def test_register_osrandom_other_engine_default(self):
        register_dummy_engine()
        default = backend.lib.ENGINE_get_default_RAND()
        default_name = backend.lib.ENGINE_get_name(default)
        assert default_name == dummy_engine.Cryptography_faux_engine_name
        res = backend.lib.ENGINE_finish(default)
        assert res == 1
        backend.register_osrandom_engine()
        current_default = backend.lib.ENGINE_get_default_RAND()
        name = backend.lib.ENGINE_get_name(current_default)
        assert name == backend.lib.Cryptography_osrandom_engine_name
        res = backend.lib.ENGINE_finish(current_default)
        assert res == 1
