# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from collections import namedtuple

from cryptography import utils
from cryptography.exceptions import InternalError
from cryptography.hazmat.backends.commoncrypto.ciphers import (
    _CipherContext, _GCMCipherContext
)
from cryptography.hazmat.backends.commoncrypto.hashes import _HashContext
from cryptography.hazmat.backends.commoncrypto.hmac import _HMACContext
from cryptography.hazmat.backends.interfaces import (
    AESKeyWrapBackend, CipherBackend, HMACBackend, HashBackend,
    PBKDF2HMACBackend
)
from cryptography.hazmat.bindings.commoncrypto.binding import Binding
from cryptography.hazmat.primitives.ciphers.algorithms import (
    AES, ARC4, Blowfish, CAST5, TripleDES
)
from cryptography.hazmat.primitives.ciphers.modes import (
    CBC, CFB, CFB8, CTR, ECB, GCM, OFB
)
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap


HashMethods = namedtuple(
    "HashMethods", ["ctx", "hash_init", "hash_update", "hash_final"]
)


@utils.register_interface(AESKeyWrapBackend)
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
        self._check_cipher_response(res)

        return self._ffi.buffer(buf)[:]

    def aes_key_wrap(self, wrapping_key, key_to_wrap):
        wraplen = len(wrapping_key)
        assert wraplen == 16 or wraplen == 24 or wraplen == 32
        assert len(key_to_wrap) % 8 == 0
        # This is the iv defined by RFC 3394
        iv = b'\xa6\xa6\xa6\xa6\xa6\xa6\xa6\xa6'
        bufsize = self._lib.CCSymmetricWrappedSize(
            self._lib.kCCWRAPAES, len(key_to_wrap)
        )
        buf = self._ffi.new("uint8_t[]", bufsize)
        buflen = self._ffi.new("size_t *", bufsize)
        res = self._lib.CCSymmetricKeyWrap(
            self._lib.kCCWRAPAES, iv, len(iv), wrapping_key,
            len(wrapping_key), key_to_wrap, len(key_to_wrap), buf, buflen
        )
        assert res == self._lib.kCCSuccess
        assert buflen[0] == bufsize
        return self._ffi.buffer(buf)[:]

    def aes_key_unwrap(self, wrapping_key, wrapped_key):
        wraplen = len(wrapping_key)
        assert wraplen == 16 or wraplen == 24 or wraplen == 32
        assert len(wrapped_key) % 8 == 0
        # This is the iv defined by RFC 3394
        iv = b'\xa6\xa6\xa6\xa6\xa6\xa6\xa6\xa6'
        bufsize = self._lib.CCSymmetricUnwrappedSize(
            self._lib.kCCWRAPAES, len(wrapped_key)
        )
        buf = self._ffi.new("uint8_t[]", bufsize)
        buflen = self._ffi.new("size_t *", bufsize)
        res = self._lib.CCSymmetricKeyUnwrap(
            self._lib.kCCWRAPAES, iv, len(iv), wrapping_key, len(wrapping_key),
            wrapped_key, len(wrapped_key), buf, buflen
        )
        if res != self._lib.kCCSuccess:
            raise InvalidUnwrap

        assert buflen[0] == bufsize
        return self._ffi.buffer(buf)[:]

    def aes_key_wrap_supported(self):
        return True

    def _register_cipher_adapter(self, cipher_cls, cipher_const, mode_cls,
                                 mode_const):
        if (cipher_cls, mode_cls) in self._cipher_registry:
            raise ValueError("Duplicate registration for: {0} {1}.".format(
                cipher_cls, mode_cls)
            )
        self._cipher_registry[cipher_cls, mode_cls] = (cipher_const,
                                                       mode_const)

    def _register_default_ciphers(self):
        for mode_cls, mode_const in [
            (CBC, self._lib.kCCModeCBC),
            (ECB, self._lib.kCCModeECB),
            (CFB, self._lib.kCCModeCFB),
            (CFB8, self._lib.kCCModeCFB8),
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
            (ECB, self._lib.kCCModeECB),
            (CFB, self._lib.kCCModeCFB),
            (CFB8, self._lib.kCCModeCFB8),
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

    def _check_cipher_response(self, response):
        if response == self._lib.kCCSuccess:
            return
        elif response == self._lib.kCCAlignmentError:
            # This error is not currently triggered due to a bug filed as
            # rdar://15589470
            raise ValueError(
                "The length of the provided data is not a multiple of "
                "the block length."
            )
        else:
            raise InternalError(
                "The backend returned an unknown error, consider filing a bug."
                " Code: {0}.".format(response)
            )

    def _release_cipher_ctx(self, ctx):
        """
        Called by the garbage collector and used to safely dereference and
        release the context.
        """
        if ctx[0] != self._ffi.NULL:
            res = self._lib.CCCryptorRelease(ctx[0])
            self._check_cipher_response(res)
            ctx[0] = self._ffi.NULL


backend = Backend()
