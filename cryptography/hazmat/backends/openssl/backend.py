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
from cryptography.exceptions import UnsupportedAlgorithm, InvalidTag
from cryptography.hazmat.backends.interfaces import (
    CipherBackend, HashBackend, HMACBackend
)
from cryptography.hazmat.primitives import interfaces
from cryptography.hazmat.primitives.ciphers.algorithms import (
    AES, Blowfish, Camellia, TripleDES, ARC4,
)
from cryptography.hazmat.primitives.ciphers.modes import (
    CBC, CTR, ECB, OFB, CFB, GCM,
)
from cryptography.hazmat.bindings.openssl.binding import Binding


def _is_not_zero(a):
    return a != 0


def _is_one(a):
    return a == 1


@utils.register_interface(CipherBackend)
@utils.register_interface(HashBackend)
@utils.register_interface(HMACBackend)
class Backend(object):
    """
    OpenSSL API binding interfaces.
    """

    def __init__(self):
        self._binding = Binding()
        self._ffi = self._binding.ffi
        self._lib = self._binding.lib

        # adds all ciphers/digests for EVP
        self._lib.OpenSSL_add_all_algorithms()
        # registers available SSL/TLS ciphers and digests
        self._lib.SSL_library_init()
        # loads error strings for libcrypto and libssl functions
        self._lib.SSL_load_error_strings()

        self._error_registry = {}
        self._register_errors()

        self._cipher_registry = {}
        self._register_default_ciphers()

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

    def _check_return(self, check, ret):
        if check(ret):
            return ret
        else:
            return self._handle_error()

    def _register_errors(self):
        not_multiple_of_block_length = (
            ValueError,
            "The length of the provided data is not a multiple of "
            "the block length"
        )

        self._error_registry[(
            self._lib.ERR_LIB_EVP,
            self._lib.EVP_F_EVP_ENCRYPTFINAL_EX,
            self._lib.EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH
        )] = not_multiple_of_block_length

        self._error_registry[(
            self._lib.ERR_LIB_EVP,
            self._lib.EVP_F_EVP_DECRYPTFINAL_EX,
            self._lib.EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH
        )] = not_multiple_of_block_length

        self._error_registry[(
            self._lib.ERR_LIB_EVP,
            self._lib.EVP_F_EVP_CIPHER_CTX_CTRL,
            self._lib.EVP_R_NO_CIPHER_SET
        )] = (
            SystemError,
            "No cipher set, you should probably file a bug."
        )

        self._error_registry[(
            self._lib.ERR_LIB_EVP,
            self._lib.EVP_F_EVP_CIPHER_CTX_CTRL,
            self._lib.EVP_R_CTRL_NOT_IMPLEMENTED,
        )] = (
            SystemError,
            "Cipher doesn't support EVP_CIPHER_CTX_ctrl."
        )

        self._error_registry[(
            self._lib.ERR_LIB_EVP,
            self._lib.EVP_F_EVP_CIPHER_CTX_CTRL,
            self._lib.EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED
        )] = (
            SystemError,
            "CTRL operation not supported by this cipher."
        )

        self._error_registry[(
            self._lib.ERR_LIB_EVP,
            self._lib.EVP_F_EVP_CIPHER_CTX_CTRL,
            self._lib.EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED
        )] = (
            SystemError,
            "CTRL operation not supported by this cipher."
        )

        self._error_registry[(
            self._lib.ERR_LIB_EVP,
            self._lib.EVP_F_AES_INIT_KEY,
            self._lib.EVP_R_AES_KEY_SETUP_FAILED
        )] = (
            SystemError,
            "AES key setup failed"
        )

    def _err_string(self, code):
        err_buf = self._ffi.new("char[]", 1024)
        self._lib.ERR_error_string_n(code, err_buf, 1024)
        return self._ffi.string(err_buf, 1024)[:]

    def _handle_error(self):
        code = self._lib.ERR_get_error()
        if code == 0:
            raise SystemError("Unknown error, you should probably file a bug.")

        exc = self._get_exc_for_error_code(code)
        raise exc[0](*exc[1:])

    def _get_exc_for_error_code(self, code):
        lib = self._lib.ERR_GET_LIB(code)
        func = self._lib.ERR_GET_FUNC(code)
        reason = self._lib.ERR_GET_REASON(code)

        exc = self._error_registry.get((lib, func, reason))
        if not exc:
            exc = (
                SystemError,
                "Unknown error, you should "
                "probably file a bug. {0}".format(
                    self._err_string(code)
                )
            )

        return exc


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
        self._backend._check_return(
            _is_not_zero,
            self._backend._lib.EVP_CipherInit_ex(ctx, evp_cipher,
                                                 self._backend._ffi.NULL,
                                                 self._backend._ffi.NULL,
                                                 self._backend._ffi.NULL,
                                                 operation)
        )

        # set the key length to handle variable key ciphers
        self._backend._check_return(
            _is_not_zero,
            self._backend._lib.EVP_CIPHER_CTX_set_key_length(
                ctx, len(cipher.key)
            )
        )

        if isinstance(mode, GCM):
            self._backend._check_return(
                _is_not_zero,
                self._backend._lib.EVP_CIPHER_CTX_ctrl(
                    ctx, self._backend._lib.EVP_CTRL_GCM_SET_IVLEN,
                    len(iv_nonce), self._backend._ffi.NULL
                )
            )

            if operation == self._DECRYPT:
                self._backend._check_return(
                    _is_not_zero,
                    self._backend._lib.EVP_CIPHER_CTX_ctrl(
                        ctx, self._backend._lib.EVP_CTRL_GCM_SET_TAG,
                        len(mode.tag), mode.tag
                    )
                )

        # pass key/iv
        self._backend._check_return(
            _is_not_zero,
            self._backend._lib.EVP_CipherInit_ex(ctx, self._backend._ffi.NULL,
                                                 self._backend._ffi.NULL,
                                                 cipher.key,
                                                 iv_nonce,
                                                 operation)
        )

        # We purposely disable padding here as it's handled higher up in the
        # API.
        self._backend._lib.EVP_CIPHER_CTX_set_padding(ctx, 0)
        self._ctx = ctx

    def update(self, data):
        buf = self._backend._ffi.new("unsigned char[]",
                                     len(data) + self._block_size - 1)
        outlen = self._backend._ffi.new("int *")
        self._backend._check_return(
            _is_not_zero,
            self._backend._lib.EVP_CipherUpdate(self._ctx, buf, outlen, data,
                                                len(data))
        )
        return self._backend._ffi.buffer(buf)[:outlen[0]]

    def finalize(self):
        buf = self._backend._ffi.new("unsigned char[]", self._block_size)
        outlen = self._backend._ffi.new("int *")
        res = self._backend._lib.EVP_CipherFinal_ex(self._ctx, buf, outlen)

        if isinstance(self._mode, GCM):
            try:
                self._backend._check_return(_is_not_zero, res)
            except SystemError:
                raise InvalidTag
        else:
            self._backend._check_return(_is_not_zero, res)

        if (
            isinstance(self._mode, GCM) and
            self._operation == self._ENCRYPT
        ):
            block_byte_size = self._block_size // 8
            tag_buf = self._backend._ffi.new("unsigned char[]",
                                             block_byte_size)
            self._backend._check_return(
                _is_not_zero,
                self._backend._lib.EVP_CIPHER_CTX_ctrl(
                    self._ctx, self._backend._lib.EVP_CTRL_GCM_GET_TAG,
                    block_byte_size, tag_buf
                )
            )
            self._tag = self._backend._ffi.buffer(tag_buf)[:]

        self._backend._check_return(
            _is_one,
            self._backend._lib.EVP_CIPHER_CTX_cleanup(self._ctx)
        )
        return self._backend._ffi.buffer(buf)[:outlen[0]]

    def authenticate_additional_data(self, data):
        outlen = self._backend._ffi.new("int *")
        self._backend._check_return(
            _is_not_zero,
            self._backend._lib.EVP_CipherUpdate(
                self._ctx, self._backend._ffi.NULL, outlen, data, len(data)
            )
        )

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
            self._backend._check_return(
                _is_not_zero,
                self._backend._lib.EVP_DigestInit_ex(ctx, evp_md,
                                                     self._backend._ffi.NULL)
            )

        self._ctx = ctx

    def copy(self):
        copied_ctx = self._backend._lib.EVP_MD_CTX_create()
        copied_ctx = self._backend._ffi.gc(
            copied_ctx,
            self._backend._lib.EVP_MD_CTX_destroy
        )
        self._backend._check_return(
            _is_not_zero,
            self._backend._lib.EVP_MD_CTX_copy_ex(copied_ctx, self._ctx)
        )
        return _HashContext(self._backend, self.algorithm, ctx=copied_ctx)

    def update(self, data):
        self._backend._check_return(
            _is_not_zero,
            self._backend._lib.EVP_DigestUpdate(self._ctx, data, len(data))
        )

    def finalize(self):
        buf = self._backend._ffi.new("unsigned char[]",
                                     self.algorithm.digest_size)
        self._backend._check_return(
            _is_not_zero,
            self._backend._lib.EVP_DigestFinal_ex(self._ctx, buf,
                                                  self._backend._ffi.NULL)
        )
        self._backend._check_return(
            _is_one,
            self._backend._lib.EVP_MD_CTX_cleanup(self._ctx),
        )
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
            self._backend._check_return(
                _is_not_zero,
                self._backend._lib.Cryptography_HMAC_Init_ex(
                    ctx, key, len(key), evp_md, self._backend._ffi.NULL
                )
            )

        self._ctx = ctx
        self._key = key

    def copy(self):
        copied_ctx = self._backend._ffi.new("HMAC_CTX *")
        self._backend._lib.HMAC_CTX_init(copied_ctx)
        copied_ctx = self._backend._ffi.gc(
            copied_ctx, self._backend._lib.HMAC_CTX_cleanup
        )
        self._backend._check_return(
            _is_not_zero,
            self._backend._lib.Cryptography_HMAC_CTX_copy(
                copied_ctx, self._ctx
            )
        )
        return _HMACContext(
            self._backend, self._key, self.algorithm, ctx=copied_ctx
        )

    def update(self, data):
        self._backend._check_return(
            _is_not_zero,
            self._backend._lib.Cryptography_HMAC_Update(
                self._ctx, data, len(data)
            )
        )

    def finalize(self):
        buf = self._backend._ffi.new("unsigned char[]",
                                     self.algorithm.digest_size)
        buflen = self._backend._ffi.new("unsigned int *",
                                        self.algorithm.digest_size)
        self._backend._check_return(
            _is_not_zero,
            self._backend._lib.Cryptography_HMAC_Final(self._ctx, buf, buflen)
        )
        self._backend._lib.HMAC_CTX_cleanup(self._ctx)
        return self._backend._ffi.buffer(buf)[:]


backend = Backend()
