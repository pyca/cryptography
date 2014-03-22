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

from collections import namedtuple

from cryptography import utils
from cryptography.exceptions import (
    InternalError, InvalidTag, UnsupportedAlgorithm
)
from cryptography.hazmat.backends.interfaces import (
    CipherBackend, HMACBackend, HashBackend, PBKDF2HMACBackend
)
from cryptography.hazmat.bindings.commoncrypto.binding import Binding
from cryptography.hazmat.primitives import constant_time, interfaces
from cryptography.hazmat.primitives.ciphers.algorithms import (
    AES, ARC4, Blowfish, CAST5, TripleDES
)
from cryptography.hazmat.primitives.ciphers.modes import (
    CBC, CFB, CTR, ECB, GCM, OFB
)


HashMethods = namedtuple(
    "HashMethods", ["ctx", "hash_init", "hash_update", "hash_final"]
)


@utils.register_interface(CipherBackend)
@utils.register_interface(HashBackend)
@utils.register_interface(HMACBackend)
@utils.register_interface(PBKDF2HMACBackend)
class Backend(object):
    """
    CommonCrypto API wrapper.
    """
    name = "commoncrypto"

    def __init__(self):
        self._binding = Binding()
        self._ffi = self._binding.ffi
        self._lib = self._binding.lib

        self._cipher_registry = {}
        self._register_default_ciphers()
        self._hash_mapping = {
            "md5": HashMethods(
                "CC_MD5_CTX *", self._lib.CC_MD5_Init,
                self._lib.CC_MD5_Update, self._lib.CC_MD5_Final
            ),
            "sha1": HashMethods(
                "CC_SHA1_CTX *", self._lib.CC_SHA1_Init,
                self._lib.CC_SHA1_Update, self._lib.CC_SHA1_Final
            ),
            "sha224": HashMethods(
                "CC_SHA256_CTX *", self._lib.CC_SHA224_Init,
                self._lib.CC_SHA224_Update, self._lib.CC_SHA224_Final
            ),
            "sha256": HashMethods(
                "CC_SHA256_CTX *", self._lib.CC_SHA256_Init,
                self._lib.CC_SHA256_Update, self._lib.CC_SHA256_Final
            ),
            "sha384": HashMethods(
                "CC_SHA512_CTX *", self._lib.CC_SHA384_Init,
                self._lib.CC_SHA384_Update, self._lib.CC_SHA384_Final
            ),
            "sha512": HashMethods(
                "CC_SHA512_CTX *", self._lib.CC_SHA512_Init,
                self._lib.CC_SHA512_Update, self._lib.CC_SHA512_Final
            ),
        }

        self._supported_hmac_algorithms = {
            "md5": self._lib.kCCHmacAlgMD5,
            "sha1": self._lib.kCCHmacAlgSHA1,
            "sha224": self._lib.kCCHmacAlgSHA224,
            "sha256": self._lib.kCCHmacAlgSHA256,
            "sha384": self._lib.kCCHmacAlgSHA384,
            "sha512": self._lib.kCCHmacAlgSHA512,
        }

        self._supported_pbkdf2_hmac_algorithms = {
            "sha1": self._lib.kCCPRFHmacAlgSHA1,
            "sha224": self._lib.kCCPRFHmacAlgSHA224,
            "sha256": self._lib.kCCPRFHmacAlgSHA256,
            "sha384": self._lib.kCCPRFHmacAlgSHA384,
            "sha512": self._lib.kCCPRFHmacAlgSHA512,
        }

    def hash_supported(self, algorithm):
        return algorithm.name in self._hash_mapping

    def hmac_supported(self, algorithm):
        return algorithm.name in self._supported_hmac_algorithms

    def create_hash_ctx(self, algorithm):
        return _HashContext(self, algorithm)

    def create_hmac_ctx(self, key, algorithm):
        return _HMACContext(self, key, algorithm)

    def cipher_supported(self, cipher, mode):
        return (type(cipher), type(mode)) in self._cipher_registry

    def create_symmetric_encryption_ctx(self, cipher, mode):
        if isinstance(mode, GCM):
            return _GCMCipherContext(
                self, cipher, mode, self._lib.kCCEncrypt
            )
        else:
            return _CipherContext(self, cipher, mode, self._lib.kCCEncrypt)

    def create_symmetric_decryption_ctx(self, cipher, mode):
        if isinstance(mode, GCM):
            return _GCMCipherContext(
                self, cipher, mode, self._lib.kCCDecrypt
            )
        else:
            return _CipherContext(self, cipher, mode, self._lib.kCCDecrypt)

    def pbkdf2_hmac_supported(self, algorithm):
        return algorithm.name in self._supported_pbkdf2_hmac_algorithms

    def derive_pbkdf2_hmac(self, algorithm, length, salt, iterations,
                           key_material):
        alg_enum = self._supported_pbkdf2_hmac_algorithms[algorithm.name]
        buf = self._ffi.new("char[]", length)
        res = self._lib.CCKeyDerivationPBKDF(
            self._lib.kCCPBKDF2,
            key_material,
            len(key_material),
            salt,
            len(salt),
            alg_enum,
            iterations,
            buf,
            length
        )
        self._check_response(res)

        return self._ffi.buffer(buf)[:]

    def _register_cipher_adapter(self, cipher_cls, cipher_const, mode_cls,
                                 mode_const):
        if (cipher_cls, mode_cls) in self._cipher_registry:
            raise ValueError("Duplicate registration for: {0} {1}".format(
                cipher_cls, mode_cls)
            )
        self._cipher_registry[cipher_cls, mode_cls] = (cipher_const,
                                                       mode_const)

    def _register_default_ciphers(self):
        for mode_cls, mode_const in [
            (CBC, self._lib.kCCModeCBC),
            (ECB, self._lib.kCCModeECB),
            (CFB, self._lib.kCCModeCFB),
            (OFB, self._lib.kCCModeOFB),
            (CTR, self._lib.kCCModeCTR),
            (GCM, self._lib.kCCModeGCM),
        ]:
            self._register_cipher_adapter(
                AES,
                self._lib.kCCAlgorithmAES128,
                mode_cls,
                mode_const
            )
        for mode_cls, mode_const in [
            (CBC, self._lib.kCCModeCBC),
            (CFB, self._lib.kCCModeCFB),
            (OFB, self._lib.kCCModeOFB),
        ]:
            self._register_cipher_adapter(
                TripleDES,
                self._lib.kCCAlgorithm3DES,
                mode_cls,
                mode_const
            )
        for mode_cls, mode_const in [
            (CBC, self._lib.kCCModeCBC),
            (ECB, self._lib.kCCModeECB),
            (CFB, self._lib.kCCModeCFB),
            (OFB, self._lib.kCCModeOFB)
        ]:
            self._register_cipher_adapter(
                Blowfish,
                self._lib.kCCAlgorithmBlowfish,
                mode_cls,
                mode_const
            )
        for mode_cls, mode_const in [
            (CBC, self._lib.kCCModeCBC),
            (ECB, self._lib.kCCModeECB),
            (CFB, self._lib.kCCModeCFB),
            (OFB, self._lib.kCCModeOFB),
            (CTR, self._lib.kCCModeCTR)
        ]:
            self._register_cipher_adapter(
                CAST5,
                self._lib.kCCAlgorithmCAST,
                mode_cls,
                mode_const
            )
        self._register_cipher_adapter(
            ARC4,
            self._lib.kCCAlgorithmRC4,
            type(None),
            self._lib.kCCModeRC4
        )

    def _check_response(self, response):
        if response == self._lib.kCCSuccess:
            return
        elif response == self._lib.kCCAlignmentError:
            # This error is not currently triggered due to a bug filed as
            # rdar://15589470
            raise ValueError(
                "The length of the provided data is not a multiple of "
                "the block length"
            )
        else:
            raise InternalError(
                "The backend returned an unknown error, consider filing a bug."
                " Code: {0}.".format(response)
            )


def _release_cipher_ctx(ctx):
    """
    Called by the garbage collector and used to safely dereference and
    release the context.
    """
    if ctx[0] != backend._ffi.NULL:
        res = backend._lib.CCCryptorRelease(ctx[0])
        backend._check_response(res)
        ctx[0] = backend._ffi.NULL


@utils.register_interface(interfaces.CipherContext)
class _CipherContext(object):
    def __init__(self, backend, cipher, mode, operation):
        self._backend = backend
        self._cipher = cipher
        self._mode = mode
        self._operation = operation
        # There is a bug in CommonCrypto where block ciphers do not raise
        # kCCAlignmentError when finalizing if you supply non-block aligned
        # data. To work around this we need to keep track of the block
        # alignment ourselves, but only for alg+mode combos that require
        # block alignment. OFB, CFB, and CTR make a block cipher algorithm
        # into a stream cipher so we don't need to track them (and thus their
        # block size is effectively 1 byte just like OpenSSL/CommonCrypto
        # treat RC4 and other stream cipher block sizes).
        # This bug has been filed as rdar://15589470
        self._bytes_processed = 0
        if (isinstance(cipher, interfaces.BlockCipherAlgorithm) and not
                isinstance(mode, (OFB, CFB, CTR))):
            self._byte_block_size = cipher.block_size // 8
        else:
            self._byte_block_size = 1

        registry = self._backend._cipher_registry
        try:
            cipher_enum, mode_enum = registry[type(cipher), type(mode)]
        except KeyError:
            raise UnsupportedAlgorithm(
                "cipher {0} in {1} mode is not supported "
                "by this backend".format(
                    cipher.name, mode.name if mode else mode)
            )

        ctx = self._backend._ffi.new("CCCryptorRef *")
        ctx = self._backend._ffi.gc(ctx, _release_cipher_ctx)

        if isinstance(mode, interfaces.ModeWithInitializationVector):
            iv_nonce = mode.initialization_vector
        elif isinstance(mode, interfaces.ModeWithNonce):
            iv_nonce = mode.nonce
        else:
            iv_nonce = self._backend._ffi.NULL

        if isinstance(mode, CTR):
            mode_option = self._backend._lib.kCCModeOptionCTR_BE
        else:
            mode_option = 0

        res = self._backend._lib.CCCryptorCreateWithMode(
            operation,
            mode_enum, cipher_enum,
            self._backend._lib.ccNoPadding, iv_nonce,
            cipher.key, len(cipher.key),
            self._backend._ffi.NULL, 0, 0, mode_option, ctx)
        self._backend._check_response(res)

        self._ctx = ctx

    def update(self, data):
        # Count bytes processed to handle block alignment.
        self._bytes_processed += len(data)
        buf = self._backend._ffi.new(
            "unsigned char[]", len(data) + self._byte_block_size - 1)
        outlen = self._backend._ffi.new("size_t *")
        res = self._backend._lib.CCCryptorUpdate(
            self._ctx[0], data, len(data), buf,
            len(data) + self._byte_block_size - 1, outlen)
        self._backend._check_response(res)
        return self._backend._ffi.buffer(buf)[:outlen[0]]

    def finalize(self):
        # Raise error if block alignment is wrong.
        if self._bytes_processed % self._byte_block_size:
            raise ValueError(
                "The length of the provided data is not a multiple of "
                "the block length"
            )
        buf = self._backend._ffi.new("unsigned char[]", self._byte_block_size)
        outlen = self._backend._ffi.new("size_t *")
        res = self._backend._lib.CCCryptorFinal(
            self._ctx[0], buf, len(buf), outlen)
        self._backend._check_response(res)
        _release_cipher_ctx(self._ctx)
        return self._backend._ffi.buffer(buf)[:outlen[0]]


@utils.register_interface(interfaces.AEADCipherContext)
@utils.register_interface(interfaces.AEADEncryptionContext)
class _GCMCipherContext(object):
    def __init__(self, backend, cipher, mode, operation):
        self._backend = backend
        self._cipher = cipher
        self._mode = mode
        self._operation = operation
        self._tag = None

        registry = self._backend._cipher_registry
        try:
            cipher_enum, mode_enum = registry[type(cipher), type(mode)]
        except KeyError:
            raise UnsupportedAlgorithm(
                "cipher {0} in {1} mode is not supported "
                "by this backend".format(
                    cipher.name, mode.name if mode else mode)
            )

        ctx = self._backend._ffi.new("CCCryptorRef *")
        ctx = self._backend._ffi.gc(ctx, _release_cipher_ctx)

        self._ctx = ctx

        res = self._backend._lib.CCCryptorCreateWithMode(
            operation,
            mode_enum, cipher_enum,
            self._backend._lib.ccNoPadding,
            self._backend._ffi.NULL,
            cipher.key, len(cipher.key),
            self._backend._ffi.NULL, 0, 0, 0, self._ctx)
        self._backend._check_response(res)

        res = self._backend._lib.CCCryptorGCMAddIV(
            self._ctx[0],
            mode.initialization_vector,
            len(mode.initialization_vector)
        )
        self._backend._check_response(res)

    def update(self, data):
        buf = self._backend._ffi.new("unsigned char[]", len(data))
        args = (self._ctx[0], data, len(data), buf)
        if self._operation == self._backend._lib.kCCEncrypt:
            res = self._backend._lib.CCCryptorGCMEncrypt(*args)
        else:
            res = self._backend._lib.CCCryptorGCMDecrypt(*args)

        self._backend._check_response(res)
        return self._backend._ffi.buffer(buf)[:]

    def finalize(self):
        tag_size = self._cipher.block_size // 8
        tag_buf = self._backend._ffi.new("unsigned char[]", tag_size)
        tag_len = self._backend._ffi.new("size_t *", tag_size)
        res = backend._lib.CCCryptorGCMFinal(self._ctx[0], tag_buf, tag_len)
        self._backend._check_response(res)
        _release_cipher_ctx(self._ctx)
        self._tag = self._backend._ffi.buffer(tag_buf)[:]
        if (self._operation == self._backend._lib.kCCDecrypt and
                not constant_time.bytes_eq(
                    self._tag[:len(self._mode.tag)], self._mode.tag
                )):
            raise InvalidTag
        return b""

    def authenticate_additional_data(self, data):
        res = self._backend._lib.CCCryptorGCMAddAAD(
            self._ctx[0], data, len(data)
        )
        self._backend._check_response(res)

    @property
    def tag(self):
        return self._tag


@utils.register_interface(interfaces.HashContext)
class _HashContext(object):
    def __init__(self, backend, algorithm, ctx=None):
        self.algorithm = algorithm
        self._backend = backend

        if ctx is None:
            try:
                methods = self._backend._hash_mapping[self.algorithm.name]
            except KeyError:
                raise UnsupportedAlgorithm(
                    "{0} is not a supported hash on this backend".format(
                        algorithm.name)
                )
            ctx = self._backend._ffi.new(methods.ctx)
            res = methods.hash_init(ctx)
            assert res == 1

        self._ctx = ctx

    def copy(self):
        methods = self._backend._hash_mapping[self.algorithm.name]
        new_ctx = self._backend._ffi.new(methods.ctx)
        # CommonCrypto has no APIs for copying hashes, so we have to copy the
        # underlying struct.
        new_ctx[0] = self._ctx[0]

        return _HashContext(self._backend, self.algorithm, ctx=new_ctx)

    def update(self, data):
        methods = self._backend._hash_mapping[self.algorithm.name]
        res = methods.hash_update(self._ctx, data, len(data))
        assert res == 1

    def finalize(self):
        methods = self._backend._hash_mapping[self.algorithm.name]
        buf = self._backend._ffi.new("unsigned char[]",
                                     self.algorithm.digest_size)
        res = methods.hash_final(buf, self._ctx)
        assert res == 1
        return self._backend._ffi.buffer(buf)[:]


@utils.register_interface(interfaces.HashContext)
class _HMACContext(object):
    def __init__(self, backend, key, algorithm, ctx=None):
        self.algorithm = algorithm
        self._backend = backend
        if ctx is None:
            ctx = self._backend._ffi.new("CCHmacContext *")
            try:
                alg = self._backend._supported_hmac_algorithms[algorithm.name]
            except KeyError:
                raise UnsupportedAlgorithm(
                    "{0} is not a supported HMAC hash on this backend".format(
                        algorithm.name)
                )

            self._backend._lib.CCHmacInit(ctx, alg, key, len(key))

        self._ctx = ctx
        self._key = key

    def copy(self):
        copied_ctx = self._backend._ffi.new("CCHmacContext *")
        # CommonCrypto has no APIs for copying HMACs, so we have to copy the
        # underlying struct.
        copied_ctx[0] = self._ctx[0]
        return _HMACContext(
            self._backend, self._key, self.algorithm, ctx=copied_ctx
        )

    def update(self, data):
        self._backend._lib.CCHmacUpdate(self._ctx, data, len(data))

    def finalize(self):
        buf = self._backend._ffi.new("unsigned char[]",
                                     self.algorithm.digest_size)
        self._backend._lib.CCHmacFinal(self._ctx, buf)
        return self._backend._ffi.buffer(buf)[:]


backend = Backend()
