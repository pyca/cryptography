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

import itertools

from cryptography import utils
from cryptography.exceptions import (
    UnsupportedAlgorithm, InvalidTag, InternalError
)
from cryptography.hazmat.backends.interfaces import (
    CipherBackend, HashBackend, HMACBackend, PBKDF2HMACBackend, RSABackend
)
from cryptography.hazmat.bindings.openssl.binding import Binding
from cryptography.hazmat.primitives import interfaces, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.algorithms import (
    AES, Blowfish, Camellia, TripleDES, ARC4, CAST5
)
from cryptography.hazmat.primitives.ciphers.modes import (
    CBC, CTR, ECB, OFB, CFB, GCM,
)


@utils.register_interface(CipherBackend)
@utils.register_interface(HashBackend)
@utils.register_interface(HMACBackend)
@utils.register_interface(PBKDF2HMACBackend)
@utils.register_interface(RSABackend)
class Backend(object):
    """
    OpenSSL API binding interfaces.
    """
    name = "openssl"

    def __init__(self):
        self._binding = Binding()
        self._ffi = self._binding.ffi
        self._lib = self._binding.lib

        self._binding.init_static_locks()

        # adds all ciphers/digests for EVP
        self._lib.OpenSSL_add_all_algorithms()
        # registers available SSL/TLS ciphers and digests
        self._lib.SSL_library_init()
        # loads error strings for libcrypto and libssl functions
        self._lib.SSL_load_error_strings()

        self._cipher_registry = {}
        self._register_default_ciphers()
        self.activate_osrandom_engine()

    def activate_builtin_random(self):
        # Obtain a new structural reference.
        e = self._lib.ENGINE_get_default_RAND()
        if e != self._ffi.NULL:
            self._lib.ENGINE_unregister_RAND(e)
            # Reset the RNG to use the new engine.
            self._lib.RAND_cleanup()
            # decrement the structural reference from get_default_RAND
            res = self._lib.ENGINE_finish(e)
            assert res == 1

    def activate_osrandom_engine(self):
        # Unregister and free the current engine.
        self.activate_builtin_random()
        # Fetches an engine by id and returns it. This creates a structural
        # reference.
        e = self._lib.ENGINE_by_id(self._lib.Cryptography_osrandom_engine_id)
        assert e != self._ffi.NULL
        # Initialize the engine for use. This adds a functional reference.
        res = self._lib.ENGINE_init(e)
        assert res == 1
        # Set the engine as the default RAND provider.
        res = self._lib.ENGINE_set_default_RAND(e)
        assert res == 1
        # Decrement the structural ref incremented by ENGINE_by_id.
        res = self._lib.ENGINE_free(e)
        assert res == 1
        # Decrement the functional ref incremented by ENGINE_init.
        res = self._lib.ENGINE_finish(e)
        assert res == 1
        # Reset the RNG to use the new engine.
        self._lib.RAND_cleanup()

    def openssl_version_text(self):
        """
        Friendly string name of linked OpenSSL.

        Example: OpenSSL 1.0.1e 11 Feb 2013
        """
        return self._ffi.string(self._lib.OPENSSL_VERSION_TEXT).decode("ascii")

    def create_hmac_ctx(self, key, algorithm):
        return _HMACContext(self, key, algorithm)

    def hash_supported(self, algorithm):
        digest = self._lib.EVP_get_digestbyname(algorithm.name.encode("ascii"))
        return digest != self._ffi.NULL

    def hmac_supported(self, algorithm):
        return self.hash_supported(algorithm)

    def create_hash_ctx(self, algorithm):
        return _HashContext(self, algorithm)

    def cipher_supported(self, cipher, mode):
        try:
            adapter = self._cipher_registry[type(cipher), type(mode)]
        except KeyError:
            return False
        evp_cipher = adapter(self, cipher, mode)
        return self._ffi.NULL != evp_cipher

    def register_cipher_adapter(self, cipher_cls, mode_cls, adapter):
        if (cipher_cls, mode_cls) in self._cipher_registry:
            raise ValueError("Duplicate registration for: {0} {1}".format(
                cipher_cls, mode_cls)
            )
        self._cipher_registry[cipher_cls, mode_cls] = adapter

    def _register_default_ciphers(self):
        for cipher_cls, mode_cls in itertools.product(
            [AES, Camellia],
            [CBC, CTR, ECB, OFB, CFB],
        ):
            self.register_cipher_adapter(
                cipher_cls,
                mode_cls,
                GetCipherByName("{cipher.name}-{cipher.key_size}-{mode.name}")
            )
        for mode_cls in [CBC, CFB, OFB]:
            self.register_cipher_adapter(
                TripleDES,
                mode_cls,
                GetCipherByName("des-ede3-{mode.name}")
            )
        for mode_cls in [CBC, CFB, OFB, ECB]:
            self.register_cipher_adapter(
                Blowfish,
                mode_cls,
                GetCipherByName("bf-{mode.name}")
            )
        for mode_cls in [CBC, CFB, OFB, ECB]:
            self.register_cipher_adapter(
                CAST5,
                mode_cls,
                GetCipherByName("cast5-{mode.name}")
            )
        self.register_cipher_adapter(
            ARC4,
            type(None),
            GetCipherByName("rc4")
        )
        self.register_cipher_adapter(
            AES,
            GCM,
            GetCipherByName("{cipher.name}-{cipher.key_size}-{mode.name}")
        )

    def create_symmetric_encryption_ctx(self, cipher, mode):
        return _CipherContext(self, cipher, mode, _CipherContext._ENCRYPT)

    def create_symmetric_decryption_ctx(self, cipher, mode):
        return _CipherContext(self, cipher, mode, _CipherContext._DECRYPT)

    def pbkdf2_hmac_supported(self, algorithm):
        if self._lib.Cryptography_HAS_PBKDF2_HMAC:
            return self.hmac_supported(algorithm)
        else:
            # OpenSSL < 1.0.0 has an explicit PBKDF2-HMAC-SHA1 function,
            # so if the PBKDF2_HMAC function is missing we only support
            # SHA1 via PBKDF2_HMAC_SHA1.
            return isinstance(algorithm, hashes.SHA1)

    def derive_pbkdf2_hmac(self, algorithm, length, salt, iterations,
                           key_material):
        buf = self._ffi.new("char[]", length)
        if self._lib.Cryptography_HAS_PBKDF2_HMAC:
            evp_md = self._lib.EVP_get_digestbyname(
                algorithm.name.encode("ascii"))
            assert evp_md != self._ffi.NULL
            res = self._lib.PKCS5_PBKDF2_HMAC(
                key_material,
                len(key_material),
                salt,
                len(salt),
                iterations,
                evp_md,
                length,
                buf
            )
            assert res == 1
        else:
            if not isinstance(algorithm, hashes.SHA1):
                raise UnsupportedAlgorithm(
                    "This version of OpenSSL only supports PBKDF2HMAC with "
                    "SHA1"
                )
            res = self._lib.PKCS5_PBKDF2_HMAC_SHA1(
                key_material,
                len(key_material),
                salt,
                len(salt),
                iterations,
                length,
                buf
            )
            assert res == 1

        return self._ffi.buffer(buf)[:]

    def _err_string(self, code):
        err_buf = self._ffi.new("char[]", 256)
        self._lib.ERR_error_string_n(code, err_buf, 256)
        return self._ffi.string(err_buf, 256)[:]

    def _handle_error(self, mode):
        code = self._lib.ERR_get_error()
        if not code and isinstance(mode, GCM):
            raise InvalidTag
        assert code != 0

        # consume any remaining errors on the stack
        ignored_code = None
        while ignored_code != 0:
            ignored_code = self._lib.ERR_get_error()

        # raise the first error we found
        return self._handle_error_code(code)

    def _handle_error_code(self, code):
        lib = self._lib.ERR_GET_LIB(code)
        func = self._lib.ERR_GET_FUNC(code)
        reason = self._lib.ERR_GET_REASON(code)

        if lib == self._lib.ERR_LIB_EVP:
            if func == self._lib.EVP_F_EVP_ENCRYPTFINAL_EX:
                if reason == self._lib.EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH:
                    raise ValueError(
                        "The length of the provided data is not a multiple of "
                        "the block length"
                    )
            elif func == self._lib.EVP_F_EVP_DECRYPTFINAL_EX:
                if reason == self._lib.EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH:
                    raise ValueError(
                        "The length of the provided data is not a multiple of "
                        "the block length"
                    )

        raise InternalError(
            "Unknown error code {0} from OpenSSL, "
            "you should probably file a bug. {1}".format(
                code, self._err_string(code)
            )
        )

    def _bn_to_int(self, bn):
        hex_cdata = self._lib.BN_bn2hex(bn)
        assert hex_cdata != self._ffi.NULL
        hex_str = self._ffi.string(hex_cdata)
        self._lib.OPENSSL_free(hex_cdata)
        return int(hex_str, 16)

    def generate_rsa_private_key(self, public_exponent, key_size):
        if public_exponent < 3:
            raise ValueError("public_exponent must be >= 3")

        if public_exponent & 1 == 0:
            raise ValueError("public_exponent must be odd")

        if key_size < 512:
            raise ValueError("key_size must be at least 512-bits")

        ctx = backend._lib.RSA_new()
        ctx = backend._ffi.gc(ctx, backend._lib.RSA_free)

        bn = backend._lib.BN_new()
        assert bn != self._ffi.NULL
        bn = backend._ffi.gc(bn, backend._lib.BN_free)

        res = backend._lib.BN_set_word(bn, public_exponent)
        assert res == 1

        res = backend._lib.RSA_generate_key_ex(
            ctx, key_size, bn, backend._ffi.NULL
        )
        assert res == 1

        return rsa.RSAPrivateKey(
            p=self._bn_to_int(ctx.p),
            q=self._bn_to_int(ctx.q),
            dmp1=self._bn_to_int(ctx.dmp1),
            dmq1=self._bn_to_int(ctx.dmq1),
            iqmp=self._bn_to_int(ctx.iqmp),
            private_exponent=self._bn_to_int(ctx.d),
            public_exponent=self._bn_to_int(ctx.e),
            modulus=self._bn_to_int(ctx.n),
        )


class GetCipherByName(object):
    def __init__(self, fmt):
        self._fmt = fmt

    def __call__(self, backend, cipher, mode):
        cipher_name = self._fmt.format(cipher=cipher, mode=mode).lower()
        return backend._lib.EVP_get_cipherbyname(cipher_name.encode("ascii"))


@utils.register_interface(interfaces.CipherContext)
@utils.register_interface(interfaces.AEADCipherContext)
@utils.register_interface(interfaces.AEADEncryptionContext)
class _CipherContext(object):
    _ENCRYPT = 1
    _DECRYPT = 0

    def __init__(self, backend, cipher, mode, operation):
        self._backend = backend
        self._cipher = cipher
        self._mode = mode
        self._operation = operation
        self._tag = None

        if isinstance(self._cipher, interfaces.BlockCipherAlgorithm):
            self._block_size = self._cipher.block_size
        else:
            self._block_size = 1

        ctx = self._backend._lib.EVP_CIPHER_CTX_new()
        ctx = self._backend._ffi.gc(
            ctx, self._backend._lib.EVP_CIPHER_CTX_free
        )

        registry = self._backend._cipher_registry
        try:
            adapter = registry[type(cipher), type(mode)]
        except KeyError:
            raise UnsupportedAlgorithm(
                "cipher {0} in {1} mode is not supported "
                "by this backend".format(
                    cipher.name, mode.name if mode else mode)
            )

        evp_cipher = adapter(self._backend, cipher, mode)
        if evp_cipher == self._backend._ffi.NULL:
            raise UnsupportedAlgorithm(
                "cipher {0} in {1} mode is not supported "
                "by this backend".format(
                    cipher.name, mode.name if mode else mode)
            )

        if isinstance(mode, interfaces.ModeWithInitializationVector):
            iv_nonce = mode.initialization_vector
        elif isinstance(mode, interfaces.ModeWithNonce):
            iv_nonce = mode.nonce
        else:
            iv_nonce = self._backend._ffi.NULL
        # begin init with cipher and operation type
        res = self._backend._lib.EVP_CipherInit_ex(ctx, evp_cipher,
                                                   self._backend._ffi.NULL,
                                                   self._backend._ffi.NULL,
                                                   self._backend._ffi.NULL,
                                                   operation)
        assert res != 0
        # set the key length to handle variable key ciphers
        res = self._backend._lib.EVP_CIPHER_CTX_set_key_length(
            ctx, len(cipher.key)
        )
        assert res != 0
        if isinstance(mode, GCM):
            res = self._backend._lib.EVP_CIPHER_CTX_ctrl(
                ctx, self._backend._lib.EVP_CTRL_GCM_SET_IVLEN,
                len(iv_nonce), self._backend._ffi.NULL
            )
            assert res != 0
            if operation == self._DECRYPT:
                res = self._backend._lib.EVP_CIPHER_CTX_ctrl(
                    ctx, self._backend._lib.EVP_CTRL_GCM_SET_TAG,
                    len(mode.tag), mode.tag
                )
                assert res != 0

        # pass key/iv
        res = self._backend._lib.EVP_CipherInit_ex(
            ctx,
            self._backend._ffi.NULL,
            self._backend._ffi.NULL,
            cipher.key,
            iv_nonce,
            operation
        )
        assert res != 0
        # We purposely disable padding here as it's handled higher up in the
        # API.
        self._backend._lib.EVP_CIPHER_CTX_set_padding(ctx, 0)
        self._ctx = ctx

    def update(self, data):
        buf = self._backend._ffi.new("unsigned char[]",
                                     len(data) + self._block_size - 1)
        outlen = self._backend._ffi.new("int *")
        res = self._backend._lib.EVP_CipherUpdate(self._ctx, buf, outlen, data,
                                                  len(data))
        assert res != 0
        return self._backend._ffi.buffer(buf)[:outlen[0]]

    def finalize(self):
        buf = self._backend._ffi.new("unsigned char[]", self._block_size)
        outlen = self._backend._ffi.new("int *")
        res = self._backend._lib.EVP_CipherFinal_ex(self._ctx, buf, outlen)
        if res == 0:
            self._backend._handle_error(self._mode)

        if (isinstance(self._mode, GCM) and
           self._operation == self._ENCRYPT):
            block_byte_size = self._block_size // 8
            tag_buf = self._backend._ffi.new(
                "unsigned char[]", block_byte_size
            )
            res = self._backend._lib.EVP_CIPHER_CTX_ctrl(
                self._ctx, self._backend._lib.EVP_CTRL_GCM_GET_TAG,
                block_byte_size, tag_buf
            )
            assert res != 0
            self._tag = self._backend._ffi.buffer(tag_buf)[:]

        res = self._backend._lib.EVP_CIPHER_CTX_cleanup(self._ctx)
        assert res == 1
        return self._backend._ffi.buffer(buf)[:outlen[0]]

    def authenticate_additional_data(self, data):
        outlen = self._backend._ffi.new("int *")
        res = self._backend._lib.EVP_CipherUpdate(
            self._ctx, self._backend._ffi.NULL, outlen, data, len(data)
        )
        assert res != 0

    @property
    def tag(self):
        return self._tag


@utils.register_interface(interfaces.HashContext)
class _HashContext(object):
    def __init__(self, backend, algorithm, ctx=None):
        self.algorithm = algorithm

        self._backend = backend

        if ctx is None:
            ctx = self._backend._lib.EVP_MD_CTX_create()
            ctx = self._backend._ffi.gc(ctx,
                                        self._backend._lib.EVP_MD_CTX_destroy)
            evp_md = self._backend._lib.EVP_get_digestbyname(
                algorithm.name.encode("ascii"))
            if evp_md == self._backend._ffi.NULL:
                raise UnsupportedAlgorithm(
                    "{0} is not a supported hash on this backend".format(
                        algorithm.name)
                )
            res = self._backend._lib.EVP_DigestInit_ex(ctx, evp_md,
                                                       self._backend._ffi.NULL)
            assert res != 0

        self._ctx = ctx

    def copy(self):
        copied_ctx = self._backend._lib.EVP_MD_CTX_create()
        copied_ctx = self._backend._ffi.gc(
            copied_ctx, self._backend._lib.EVP_MD_CTX_destroy
        )
        res = self._backend._lib.EVP_MD_CTX_copy_ex(copied_ctx, self._ctx)
        assert res != 0
        return _HashContext(self._backend, self.algorithm, ctx=copied_ctx)

    def update(self, data):
        res = self._backend._lib.EVP_DigestUpdate(self._ctx, data, len(data))
        assert res != 0

    def finalize(self):
        buf = self._backend._ffi.new("unsigned char[]",
                                     self.algorithm.digest_size)
        res = self._backend._lib.EVP_DigestFinal_ex(self._ctx, buf,
                                                    self._backend._ffi.NULL)
        assert res != 0
        res = self._backend._lib.EVP_MD_CTX_cleanup(self._ctx)
        assert res == 1
        return self._backend._ffi.buffer(buf)[:]


@utils.register_interface(interfaces.HashContext)
class _HMACContext(object):
    def __init__(self, backend, key, algorithm, ctx=None):
        self.algorithm = algorithm
        self._backend = backend

        if ctx is None:
            ctx = self._backend._ffi.new("HMAC_CTX *")
            self._backend._lib.HMAC_CTX_init(ctx)
            ctx = self._backend._ffi.gc(
                ctx, self._backend._lib.HMAC_CTX_cleanup
            )
            evp_md = self._backend._lib.EVP_get_digestbyname(
                algorithm.name.encode('ascii'))
            if evp_md == self._backend._ffi.NULL:
                raise UnsupportedAlgorithm(
                    "{0} is not a supported hash on this backend".format(
                        algorithm.name)
                )
            res = self._backend._lib.Cryptography_HMAC_Init_ex(
                ctx, key, len(key), evp_md, self._backend._ffi.NULL
            )
            assert res != 0

        self._ctx = ctx
        self._key = key

    def copy(self):
        copied_ctx = self._backend._ffi.new("HMAC_CTX *")
        self._backend._lib.HMAC_CTX_init(copied_ctx)
        copied_ctx = self._backend._ffi.gc(
            copied_ctx, self._backend._lib.HMAC_CTX_cleanup
        )
        res = self._backend._lib.Cryptography_HMAC_CTX_copy(
            copied_ctx, self._ctx
        )
        assert res != 0
        return _HMACContext(
            self._backend, self._key, self.algorithm, ctx=copied_ctx
        )

    def update(self, data):
        res = self._backend._lib.Cryptography_HMAC_Update(
            self._ctx, data, len(data)
        )
        assert res != 0

    def finalize(self):
        buf = self._backend._ffi.new("unsigned char[]",
                                     self.algorithm.digest_size)
        buflen = self._backend._ffi.new("unsigned int *",
                                        self.algorithm.digest_size)
        res = self._backend._lib.Cryptography_HMAC_Final(
            self._ctx, buf, buflen
        )
        assert res != 0
        self._backend._lib.HMAC_CTX_cleanup(self._ctx)
        return self._backend._ffi.buffer(buf)[:]


backend = Backend()
