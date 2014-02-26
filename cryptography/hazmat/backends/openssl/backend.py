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
    UnsupportedAlgorithm, InvalidTag, InternalError, AlreadyFinalized,
    UnsupportedPadding, InvalidSignature
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

    def _int_to_bn(self, num):
        """
        Converts a python integer to a BIGNUM. The returned BIGNUM will not
        be garbage collected (to support adding them to structs that take
        ownership of the object). Be sure to register it for GC if it will
        be discarded after use.
        """
        hex_num = hex(num).rstrip("L").lstrip("0x").encode("ascii") or b"0"
        bn_ptr = self._ffi.new("BIGNUM **")
        res = self._lib.BN_hex2bn(bn_ptr, hex_num)
        assert res != 0
        assert bn_ptr[0] != self._ffi.NULL
        return bn_ptr[0]

    def generate_rsa_private_key(self, public_exponent, key_size):
        if public_exponent < 3:
            raise ValueError("public_exponent must be >= 3")

        if public_exponent & 1 == 0:
            raise ValueError("public_exponent must be odd")

        if key_size < 512:
            raise ValueError("key_size must be at least 512-bits")

        ctx = self._lib.RSA_new()
        assert ctx != self._ffi.NULL
        ctx = self._ffi.gc(ctx, self._lib.RSA_free)

        bn = self._int_to_bn(public_exponent)
        bn = self._ffi.gc(bn, self._lib.BN_free)

        res = self._lib.RSA_generate_key_ex(
            ctx, key_size, bn, self._ffi.NULL
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

    def _rsa_cdata_from_private_key(self, private_key):
        ctx = self._lib.RSA_new()
        assert ctx != self._ffi.NULL
        ctx = self._ffi.gc(ctx, self._lib.RSA_free)
        ctx.p = self._int_to_bn(private_key.p)
        ctx.q = self._int_to_bn(private_key.q)
        ctx.d = self._int_to_bn(private_key.d)
        ctx.e = self._int_to_bn(private_key.e)
        ctx.n = self._int_to_bn(private_key.n)
        ctx.dmp1 = self._int_to_bn(private_key.dmp1)
        ctx.dmq1 = self._int_to_bn(private_key.dmq1)
        ctx.iqmp = self._int_to_bn(private_key.iqmp)
        return ctx

    def _rsa_cdata_from_public_key(self, public_key):
        ctx = self._lib.RSA_new()
        ctx = self._ffi.gc(ctx, self._lib.RSA_free)
        ctx.e = self._int_to_bn(public_key.e)
        ctx.n = self._int_to_bn(public_key.n)
        return ctx

    def create_rsa_signature_ctx(self, private_key, padding, algorithm):
        return _RSASignatureContext(self, private_key, padding, algorithm)

    def create_rsa_verification_ctx(self, public_key, signature, padding,
                                    algorithm):
        return _RSAVerificationContext(self, public_key, signature, padding,
                                       algorithm)


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


@utils.register_interface(interfaces.AsymmetricSignatureContext)
class _RSASignatureContext(object):
    def __init__(self, backend, private_key, padding, algorithm):
        self._backend = backend
        self._private_key = private_key
        if not isinstance(padding, interfaces.AsymmetricPadding):
            raise TypeError(
                "Expected provider of interfaces.AsymmetricPadding")

        if padding.name == "EMSA-PKCS1-v1_5":
            if self._backend._lib.Cryptography_HAS_PKEY_CTX:
                self._finalize_method = self._finalize_pkey_ctx
                self._padding_enum = self._backend._lib.RSA_PKCS1_PADDING
            else:
                self._finalize_method = self._finalize_pkcs1
        else:
            raise UnsupportedPadding(
                "{0} is not supported by this backend".format(padding.name)
            )

        self._padding = padding
        self._algorithm = algorithm
        self._hash_ctx = _HashContext(backend, self._algorithm)

    def update(self, data):
        if self._hash_ctx is None:
            raise AlreadyFinalized("Context has already been finalized")

        self._hash_ctx.update(data)

    def finalize(self):
        if self._hash_ctx is None:
            raise AlreadyFinalized("Context has already been finalized")
        evp_pkey = self._backend._lib.EVP_PKEY_new()
        assert evp_pkey != self._backend._ffi.NULL
        evp_pkey = backend._ffi.gc(evp_pkey, backend._lib.EVP_PKEY_free)
        rsa_cdata = backend._rsa_cdata_from_private_key(self._private_key)
        res = self._backend._lib.RSA_blinding_on(
            rsa_cdata, self._backend._ffi.NULL)
        assert res == 1
        res = self._backend._lib.EVP_PKEY_set1_RSA(evp_pkey, rsa_cdata)
        assert res == 1
        evp_md = self._backend._lib.EVP_get_digestbyname(
            self._algorithm.name.encode("ascii"))
        assert evp_md != self._backend._ffi.NULL
        pkey_size = self._backend._lib.EVP_PKEY_size(evp_pkey)
        assert pkey_size > 0

        return self._finalize_method(evp_pkey, pkey_size, rsa_cdata, evp_md)

    def _finalize_pkey_ctx(self, evp_pkey, pkey_size, rsa_cdata, evp_md):
        pkey_ctx = self._backend._lib.EVP_PKEY_CTX_new(
            evp_pkey, self._backend._ffi.NULL
        )
        assert pkey_ctx != self._backend._ffi.NULL
        res = self._backend._lib.EVP_PKEY_sign_init(pkey_ctx)
        assert res == 1
        res = self._backend._lib.EVP_PKEY_CTX_set_signature_md(
            pkey_ctx, evp_md)
        assert res > 0

        res = self._backend._lib.EVP_PKEY_CTX_set_rsa_padding(
            pkey_ctx, self._padding_enum)
        assert res > 0
        data_to_sign = self._hash_ctx.finalize()
        self._hash_ctx = None
        buflen = self._backend._ffi.new("size_t *")
        res = self._backend._lib.EVP_PKEY_sign(
            pkey_ctx,
            self._backend._ffi.NULL,
            buflen,
            data_to_sign,
            len(data_to_sign)
        )
        assert res == 1
        buf = self._backend._ffi.new("unsigned char[]", buflen[0])
        res = self._backend._lib.EVP_PKEY_sign(
            pkey_ctx, buf, buflen, data_to_sign, len(data_to_sign))
        assert res == 1
        return self._backend._ffi.buffer(buf)[:]

    def _finalize_pkcs1(self, evp_pkey, pkey_size, rsa_cdata, evp_md):
        sig_buf = self._backend._ffi.new("char[]", pkey_size)
        sig_len = self._backend._ffi.new("unsigned int *")
        res = self._backend._lib.EVP_SignFinal(
            self._hash_ctx._ctx,
            sig_buf,
            sig_len,
            evp_pkey
        )
        self._hash_ctx.finalize()
        self._hash_ctx = None
        assert res == 1
        return self._backend._ffi.buffer(sig_buf)[:sig_len[0]]


@utils.register_interface(interfaces.AsymmetricVerificationContext)
class _RSAVerificationContext(object):
    def __init__(self, backend, public_key, signature, padding, algorithm):
        self._backend = backend
        self._public_key = public_key
        self._signature = signature
        if not isinstance(padding, interfaces.AsymmetricPadding):
            raise TypeError(
                "Expected provider of interfaces.AsymmetricPadding")

        if padding.name == "EMSA-PKCS1-v1_5":
            if self._backend._lib.Cryptography_HAS_PKEY_CTX:
                self._verify_method = self._verify_pkey_ctx
                self._padding_enum = self._backend._lib.RSA_PKCS1_PADDING
            else:
                self._verify_method = self._verify_pkcs1
        else:
            raise UnsupportedPadding

        self._padding = padding
        self._algorithm = algorithm
        self._hash_ctx = _HashContext(backend, self._algorithm)

    def update(self, data):
        if self._hash_ctx is None:
            raise AlreadyFinalized("Context has already been finalized")

        self._hash_ctx.update(data)

    def verify(self):
        if self._hash_ctx is None:
            raise AlreadyFinalized("Context has already been finalized")

        evp_pkey = self._backend._lib.EVP_PKEY_new()
        assert evp_pkey != self._backend._ffi.NULL
        evp_pkey = backend._ffi.gc(evp_pkey, backend._lib.EVP_PKEY_free)
        rsa_cdata = backend._rsa_cdata_from_public_key(self._public_key)
        res = self._backend._lib.RSA_blinding_on(
            rsa_cdata, self._backend._ffi.NULL)
        assert res == 1
        res = self._backend._lib.EVP_PKEY_set1_RSA(evp_pkey, rsa_cdata)
        assert res == 1
        evp_md = self._backend._lib.EVP_get_digestbyname(
            self._algorithm.name.encode("ascii"))
        assert evp_md != self._backend._ffi.NULL

        self._verify_method(rsa_cdata, evp_pkey, evp_md)

    def _verify_pkey_ctx(self, rsa_cdata, evp_pkey, evp_md):
        pkey_ctx = self._backend._lib.EVP_PKEY_CTX_new(
            evp_pkey, self._backend._ffi.NULL
        )
        assert pkey_ctx != self._backend._ffi.NULL
        res = self._backend._lib.EVP_PKEY_verify_init(pkey_ctx)
        assert res == 1
        res = self._backend._lib.EVP_PKEY_CTX_set_signature_md(
            pkey_ctx, evp_md)
        assert res > 0

        res = self._backend._lib.EVP_PKEY_CTX_set_rsa_padding(
            pkey_ctx, self._padding_enum)
        assert res > 0
        data_to_verify = self._hash_ctx.finalize()
        self._hash_ctx = None
        res = self._backend._lib.EVP_PKEY_verify(
            pkey_ctx,
            self._signature,
            len(self._signature),
            data_to_verify,
            len(data_to_verify)
        )
        if res != 1:
            raise InvalidSignature

    def _verify_pkcs1(self, rsa_cdata, evp_pkey, evp_md):
        res = self._backend._lib.EVP_VerifyFinal(
            self._hash_ctx._ctx,
            self._signature,
            len(self._signature),
            evp_pkey
        )
        self._hash_ctx = None
        if res != 1:
            raise InvalidSignature


backend = Backend()
