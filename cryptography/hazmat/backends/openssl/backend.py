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
import sys

import cffi

from cryptography import utils
from cryptography.exceptions import UnsupportedAlgorithm, InvalidTag
from cryptography.hazmat.backends.interfaces import (
    CipherBackend, HashBackend, HMACBackend
)
from cryptography.hazmat.primitives import interfaces
from cryptography.hazmat.primitives.ciphers.algorithms import (
    AES, Blowfish, Camellia, CAST5, TripleDES, ARC4,
)
from cryptography.hazmat.primitives.ciphers.modes import (
    CBC, CTR, ECB, OFB, CFB, GCM,
)

_OSX_PRE_INCLUDE = """
#ifdef __APPLE__
#include <AvailabilityMacros.h>
#define __ORIG_DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER \
    DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#undef DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#define DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#endif
"""

_OSX_POST_INCLUDE = """
#ifdef __APPLE__
#undef DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#define DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER \
    __ORIG_DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#endif
"""


@utils.register_interface(CipherBackend)
@utils.register_interface(HashBackend)
@utils.register_interface(HMACBackend)
class Backend(object):
    """
    OpenSSL API wrapper.
    """
    _modules = [
        "asn1",
        "bignum",
        "bio",
        "conf",
        "crypto",
        "dh",
        "dsa",
        "engine",
        "err",
        "evp",
        "hmac",
        "nid",
        "opensslv",
        "pem",
        "pkcs7",
        "pkcs12",
        "rand",
        "rsa",
        "ssl",
        "x509",
        "x509name",
        "x509v3",
    ]

    ffi = None
    lib = None

    def __init__(self):
        self._ensure_ffi_initialized()

        self._cipher_registry = {}
        self._register_default_ciphers()

    @classmethod
    def _ensure_ffi_initialized(cls):
        if cls.ffi is not None and cls.lib is not None:
            return

        ffi = cffi.FFI()
        includes = []
        functions = []
        macros = []
        customizations = []
        for name in cls._modules:
            module_name = "cryptography.hazmat.backends.openssl." + name
            __import__(module_name)
            module = sys.modules[module_name]

            ffi.cdef(module.TYPES)

            macros.append(module.MACROS)
            functions.append(module.FUNCTIONS)
            includes.append(module.INCLUDES)
            customizations.append(module.CUSTOMIZATIONS)

        # loop over the functions & macros after declaring all the types
        # so we can set interdependent types in different files and still
        # have them all defined before we parse the funcs & macros
        for func in functions:
            ffi.cdef(func)
        for macro in macros:
            ffi.cdef(macro)

        # We include functions here so that if we got any of their definitions
        # wrong, the underlying C compiler will explode. In C you are allowed
        # to re-declare a function if it has the same signature. That is:
        #   int foo(int);
        #   int foo(int);
        # is legal, but the following will fail to compile:
        #   int foo(int);
        #   int foo(short);

        lib = ffi.verify(
            source="\n".join(
                [_OSX_PRE_INCLUDE] +
                includes +
                [_OSX_POST_INCLUDE] +
                functions +
                customizations
            ),
            libraries=["crypto", "ssl"],
        )

        cls.ffi = ffi
        cls.lib = lib
        cls.lib.OpenSSL_add_all_algorithms()
        cls.lib.SSL_load_error_strings()

    def openssl_version_text(self):
        """
        Friendly string name of linked OpenSSL.

        Example: OpenSSL 1.0.1e 11 Feb 2013
        """
        return self.ffi.string(self.lib.OPENSSL_VERSION_TEXT).decode("ascii")

    def create_hmac_ctx(self, key, algorithm):
        return _HMACContext(self, key, algorithm)

    def hash_supported(self, algorithm):
        digest = self.lib.EVP_get_digestbyname(algorithm.name.encode("ascii"))
        return digest != self.ffi.NULL

    def create_hash_ctx(self, algorithm):
        return _HashContext(self, algorithm)

    def cipher_supported(self, cipher, mode):
        try:
            adapter = self._cipher_registry[type(cipher), type(mode)]
        except KeyError:
            return False
        evp_cipher = adapter(self, cipher, mode)
        return self.ffi.NULL != evp_cipher

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
            CAST5,
            ECB,
            GetCipherByName("cast5-ecb")
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

    def _handle_error(self, mode):
        code = self.lib.ERR_get_error()
        if not code and isinstance(mode, GCM):
            raise InvalidTag
        assert code != 0
        lib = self.lib.ERR_GET_LIB(code)
        func = self.lib.ERR_GET_FUNC(code)
        reason = self.lib.ERR_GET_REASON(code)
        return self._handle_error_code(lib, func, reason)

    def _handle_error_code(self, lib, func, reason):
        if lib == self.lib.ERR_LIB_EVP:
            if func == self.lib.EVP_F_EVP_ENCRYPTFINAL_EX:
                if reason == self.lib.EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH:
                    raise ValueError(
                        "The length of the provided data is not a multiple of "
                        "the block length"
                    )
            elif func == self.lib.EVP_F_EVP_DECRYPTFINAL_EX:
                if reason == self.lib.EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH:
                    raise ValueError(
                        "The length of the provided data is not a multiple of "
                        "the block length"
                    )

        raise SystemError(
            "Unknown error code from OpenSSL, you should probably file a bug."
        )


class GetCipherByName(object):
    def __init__(self, fmt):
        self._fmt = fmt

    def __call__(self, backend, cipher, mode):
        cipher_name = self._fmt.format(cipher=cipher, mode=mode).lower()
        return backend.lib.EVP_get_cipherbyname(cipher_name.encode("ascii"))


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

        ctx = self._backend.lib.EVP_CIPHER_CTX_new()
        ctx = self._backend.ffi.gc(ctx, self._backend.lib.EVP_CIPHER_CTX_free)

        registry = self._backend._cipher_registry
        try:
            adapter = registry[type(cipher), type(mode)]
        except KeyError:
            raise UnsupportedAlgorithm

        evp_cipher = adapter(self._backend, cipher, mode)
        if evp_cipher == self._backend.ffi.NULL:
            raise UnsupportedAlgorithm

        if isinstance(mode, interfaces.ModeWithInitializationVector):
            iv_nonce = mode.initialization_vector
        elif isinstance(mode, interfaces.ModeWithNonce):
            iv_nonce = mode.nonce
        else:
            iv_nonce = self._backend.ffi.NULL
        # begin init with cipher and operation type
        res = self._backend.lib.EVP_CipherInit_ex(ctx, evp_cipher,
                                                  self._backend.ffi.NULL,
                                                  self._backend.ffi.NULL,
                                                  self._backend.ffi.NULL,
                                                  operation)
        assert res != 0
        # set the key length to handle variable key ciphers
        res = self._backend.lib.EVP_CIPHER_CTX_set_key_length(
            ctx, len(cipher.key)
        )
        assert res != 0
        if isinstance(mode, GCM):
            res = self._backend.lib.EVP_CIPHER_CTX_ctrl(
                ctx, self._backend.lib.Cryptography_EVP_CTRL_GCM_SET_IVLEN,
                len(iv_nonce), self._backend.ffi.NULL
            )
            assert res != 0
            if operation == self._DECRYPT:
                if not mode.tag:
                    raise ValueError("Authentication tag must be supplied "
                                     "when decrypting")
                res = self._backend.lib.EVP_CIPHER_CTX_ctrl(
                    ctx, self._backend.lib.Cryptography_EVP_CTRL_GCM_SET_TAG,
                    len(mode.tag), mode.tag
                )
                assert res != 0
            else:
                if mode.tag:
                    raise ValueError("Authentication tag must be None when "
                                     "encrypting")

        # pass key/iv
        res = self._backend.lib.EVP_CipherInit_ex(ctx, self._backend.ffi.NULL,
                                                  self._backend.ffi.NULL,
                                                  cipher.key,
                                                  iv_nonce,
                                                  operation)
        assert res != 0
        # We purposely disable padding here as it's handled higher up in the
        # API.
        self._backend.lib.EVP_CIPHER_CTX_set_padding(ctx, 0)
        self._ctx = ctx

    def update(self, data):
        buf = self._backend.ffi.new("unsigned char[]",
                                    len(data) + self._block_size - 1)
        outlen = self._backend.ffi.new("int *")
        res = self._backend.lib.EVP_CipherUpdate(self._ctx, buf, outlen, data,
                                                 len(data))
        assert res != 0
        return self._backend.ffi.buffer(buf)[:outlen[0]]

    def finalize(self):
        buf = self._backend.ffi.new("unsigned char[]", self._block_size)
        outlen = self._backend.ffi.new("int *")
        res = self._backend.lib.EVP_CipherFinal_ex(self._ctx, buf, outlen)
        if res == 0:
            self._backend._handle_error(self._mode)

        if (isinstance(self._mode, GCM) and
           self._operation == self._ENCRYPT):
            block_byte_size = self._block_size // 8
            tag_buf = self._backend.ffi.new("unsigned char[]", block_byte_size)
            res = self._backend.lib.EVP_CIPHER_CTX_ctrl(
                self._ctx, self._backend.lib.Cryptography_EVP_CTRL_GCM_GET_TAG,
                block_byte_size, tag_buf
            )
            assert res != 0
            self._tag = self._backend.ffi.buffer(tag_buf)[:]

        res = self._backend.lib.EVP_CIPHER_CTX_cleanup(self._ctx)
        assert res == 1
        return self._backend.ffi.buffer(buf)[:outlen[0]]

    def authenticate_additional_data(self, data):
        outlen = self._backend.ffi.new("int *")
        res = self._backend.lib.EVP_CipherUpdate(
            self._ctx, self._backend.ffi.NULL, outlen, data, len(data)
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
            ctx = self._backend.lib.EVP_MD_CTX_create()
            ctx = self._backend.ffi.gc(ctx,
                                       self._backend.lib.EVP_MD_CTX_destroy)
            evp_md = self._backend.lib.EVP_get_digestbyname(
                algorithm.name.encode("ascii"))
            assert evp_md != self._backend.ffi.NULL
            res = self._backend.lib.EVP_DigestInit_ex(ctx, evp_md,
                                                      self._backend.ffi.NULL)
            assert res != 0

        self._ctx = ctx

    def copy(self):
        copied_ctx = self._backend.lib.EVP_MD_CTX_create()
        copied_ctx = self._backend.ffi.gc(copied_ctx,
                                          self._backend.lib.EVP_MD_CTX_destroy)
        res = self._backend.lib.EVP_MD_CTX_copy_ex(copied_ctx, self._ctx)
        assert res != 0
        return _HashContext(self._backend, self.algorithm, ctx=copied_ctx)

    def update(self, data):
        res = self._backend.lib.EVP_DigestUpdate(self._ctx, data, len(data))
        assert res != 0

    def finalize(self):
        buf = self._backend.ffi.new("unsigned char[]",
                                    self.algorithm.digest_size)
        res = self._backend.lib.EVP_DigestFinal_ex(self._ctx, buf,
                                                   self._backend.ffi.NULL)
        assert res != 0
        res = self._backend.lib.EVP_MD_CTX_cleanup(self._ctx)
        assert res == 1
        return self._backend.ffi.buffer(buf)[:]


@utils.register_interface(interfaces.HashContext)
class _HMACContext(object):
    def __init__(self, backend, key, algorithm, ctx=None):
        self.algorithm = algorithm
        self._backend = backend

        if ctx is None:
            ctx = self._backend.ffi.new("HMAC_CTX *")
            self._backend.lib.HMAC_CTX_init(ctx)
            ctx = self._backend.ffi.gc(ctx, self._backend.lib.HMAC_CTX_cleanup)
            evp_md = self._backend.lib.EVP_get_digestbyname(
                algorithm.name.encode('ascii'))
            assert evp_md != self._backend.ffi.NULL
            res = self._backend.lib.Cryptography_HMAC_Init_ex(
                ctx, key, len(key), evp_md, self._backend.ffi.NULL
            )
            assert res != 0

        self._ctx = ctx
        self._key = key

    def copy(self):
        copied_ctx = self._backend.ffi.new("HMAC_CTX *")
        self._backend.lib.HMAC_CTX_init(copied_ctx)
        copied_ctx = self._backend.ffi.gc(
            copied_ctx, self._backend.lib.HMAC_CTX_cleanup
        )
        res = self._backend.lib.Cryptography_HMAC_CTX_copy(
            copied_ctx, self._ctx
        )
        assert res != 0
        return _HMACContext(
            self._backend, self._key, self.algorithm, ctx=copied_ctx
        )

    def update(self, data):
        res = self._backend.lib.Cryptography_HMAC_Update(
            self._ctx, data, len(data)
        )
        assert res != 0

    def finalize(self):
        buf = self._backend.ffi.new("unsigned char[]",
                                    self.algorithm.digest_size)
        buflen = self._backend.ffi.new("unsigned int *",
                                       self.algorithm.digest_size)
        res = self._backend.lib.Cryptography_HMAC_Final(self._ctx, buf, buflen)
        assert res != 0
        self._backend.lib.HMAC_CTX_cleanup(self._ctx)
        return self._backend.ffi.buffer(buf)[:]


backend = Backend()
