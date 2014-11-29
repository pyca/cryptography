# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os
import tempfile
import uuid
from collections import namedtuple

from cryptography import utils
from cryptography.exceptions import InternalError
from cryptography.hazmat.backends.commoncrypto import asn1
from cryptography.hazmat.backends.commoncrypto.ciphers import (
    _CipherContext, _GCMCipherContext
)
from cryptography.hazmat.backends.commoncrypto.hashes import _HashContext
from cryptography.hazmat.backends.commoncrypto.hmac import _HMACContext
from cryptography.hazmat.backends.commoncrypto.rsa import (
    _RSAPrivateKey, _RSAPublicKey
)
from cryptography.hazmat.backends.interfaces import (
    CipherBackend, HMACBackend, HashBackend, PBKDF2HMACBackend, RSABackend
)
from cryptography.hazmat.bindings.commoncrypto.binding import Binding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import (
    MGF1, OAEP, PKCS1v15
)
from cryptography.hazmat.primitives.ciphers.algorithms import (
    AES, ARC4, Blowfish, CAST5, TripleDES
)
from cryptography.hazmat.primitives.ciphers.modes import (
    CBC, CFB, CFB8, CTR, ECB, GCM, OFB
)


HashMethods = namedtuple(
    "HashMethods", ["ctx", "hash_init", "hash_update", "hash_final"]
)


@utils.register_interface(CipherBackend)
@utils.register_interface(HashBackend)
@utils.register_interface(HMACBackend)
@utils.register_interface(PBKDF2HMACBackend)
@utils.register_interface(RSABackend)
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

    # TODO: cover else branch
    def rsa_padding_supported(self, padding):
        if isinstance(padding, PKCS1v15):
            return True
        elif isinstance(padding, OAEP) and isinstance(padding._mgf, MGF1):
            return isinstance(padding._mgf._algorithm, hashes.SHA1)
        else:
            return False

    # TODO: remove this or add it to interface.
    def load_rsa_parameters_supported(self, public_exponent, key_size):
        return (key_size % 8 == 0 and key_size <= 4096)

    def generate_rsa_parameters_supported(self, public_exponent, key_size):
        return (
            public_exponent == 65537 and key_size >= 1024 and
            key_size <= 4096 and key_size % 8 == 0
        )

    def generate_rsa_private_key(self, public_exponent, key_size):
        if public_exponent != 65537:
            raise ValueError("Only 65537 is supported for public exponent")

        if key_size < 1024 or key_size > 4096 or key_size % 8 != 0:
            raise ValueError("key_size must be between 1024 and 4096 bits and "
                             "divisible by 8.")

        filename = os.path.join(tempfile.gettempdir(), str(uuid.uuid4()))
        keycallback = self._ffi.new(
            "CFDictionaryKeyCallBacks *",
            self._lib.kCFTypeDictionaryKeyCallBacks
        )
        valuecallback = self._ffi.new(
            "CFDictionaryValueCallBacks *",
            self._lib.kCFTypeDictionaryValueCallBacks
        )
        keydict = self._lib.CFDictionaryCreateMutable(
            self._lib.kCFAllocatorDefault,
            0,
            keycallback,
            valuecallback
        )
        assert keydict != self._ffi.NULL
        keydict = self._ffi.gc(keydict, self._release_cftyperef)
        self._lib.CFDictionarySetValue(
            keydict,
            self._lib.kSecAttrKeyType,
            self._lib.kSecAttrKeyTypeRSA
        )
        bits = self._lib.CFStringCreateWithCString(
            self._lib.kCFAllocatorDefault,
            str(key_size),
            self._lib.kCFStringEncodingASCII
        )
        assert bits != self._ffi.NULL
        bits = self._ffi.gc(bits, self._release_cftyperef)
        self._lib.CFDictionarySetValue(
            keydict,
            self._lib.kSecAttrKeySizeInBits,
            bits
        )
        keychain = self._ffi.new("SecKeychainRef *")
        keychain = self._ffi.gc(keychain, self._release_cftyperef_ptr)
        res = self._lib.SecKeychainCreate(
            filename, 1, "", False, self._ffi.NULL, keychain
        )
        assert res == 0
        self._lib.CFDictionarySetValue(
            keydict,
            self._lib.kSecUseKeychain,
            keychain[0]
        )
        public_key = self._ffi.new("SecKeyRef *")
        public_key = self._ffi.gc(public_key, self._release_cftyperef_ptr)
        private_key = self._ffi.new("SecKeyRef *")
        private_key = self._ffi.gc(private_key, self._release_cftyperef_ptr)
        res = self._lib.SecKeyGeneratePair(
            self._ffi.cast("CFDictionaryRef", keydict),
            public_key,
            private_key
        )
        assert res == 0
        res = self._lib.SecKeychainDelete(keychain[0])
        assert res == 0

        return _RSAPrivateKey(self, private_key, key_size)

    def _keyref_from_der(self, der):
        dataref = self._lib.CFDataCreate(
            self._lib.kCFAllocatorDefault,
            der,
            len(der)
        )
        dataref = self._ffi.gc(dataref, self._release_cftyperef)
        keyparams = self._ffi.new("SecItemImportExportKeyParameters *")
        keyparams.flags = 0
        secitemtype = self._ffi.new("SecExternalItemType *",
                                    self._lib.kSecItemTypeUnknown)
        secformat = self._ffi.new("SecExternalFormat *",
                                  self._lib.kSecFormatOpenSSL)
        outitems = self._ffi.new("CFArrayRef *")
        outitems = self._ffi.gc(outitems, self._release_cftyperef_ptr)
        res = self._lib.SecItemImport(
            dataref,
            self._ffi.NULL,
            secformat,
            secitemtype,
            0,
            keyparams,
            self._ffi.NULL,
            outitems
        )
        assert res == 0
        assert outitems[0] != self._ffi.NULL
        keyref = self._lib.CFArrayGetValueAtIndex(outitems[0], 0)
        keyref = self._ffi.cast("SecKeyRef", self._lib.CFRetain(keyref))
        keyref = self._ffi.gc(keyref, self._release_cftyperef)
        return keyref

    def _create_cfnumber(self, number):
        num = self._ffi.new("int *", number)
        cfnumber = self._lib.CFNumberCreate(
            self._lib.kCFAllocatorDefault, self._lib.kCFNumberIntType, num
        )
        return self._ffi.gc(cfnumber, self._release_cftyperef)

    def load_rsa_private_numbers(self, numbers):
        rsa._check_private_key_components(
            numbers.p,
            numbers.q,
            numbers.d,
            numbers.dmp1,
            numbers.dmq1,
            numbers.iqmp,
            numbers.public_numbers.e,
            numbers.public_numbers.n
        )
        der = asn1.build_private_pkcs1(numbers)
        keyref = self._keyref_from_der(der)
        return _RSAPrivateKey(
            self, keyref, utils.bit_length(numbers.public_numbers.n)
        )

    def load_rsa_public_numbers(self, numbers):
        rsa._check_public_key_components(numbers.e, numbers.n)
        der = asn1.build_public_pkcs1(numbers)
        keyref = self._keyref_from_der(der)
        return _RSAPublicKey(self, keyref, utils.bit_length(numbers.n))

    def _release_cipher_ctx(self, ctx):
        """
        Called by the garbage collector and used to safely dereference and
        release the context.
        """
        if ctx[0] != self._ffi.NULL:
            res = self._lib.CCCryptorRelease(ctx[0])
            self._check_cipher_response(res)
            ctx[0] = self._ffi.NULL

    def _release_cftyperef(self, ref):
        """
        Called by the garbage collector and used to safely dereference and
        release a CFTypeRef type. This can be CFArrayRef, CFStringRef, etc
        """
        self._lib.CFRelease(self._ffi.cast("CFTypeRef", ref))

    def _release_cftyperef_ptr(self, ptr):
        """
        Called by the garbage collector and used to safely dereference and
        release a CFTypeRef * type. This can be CFArrayRef *, CFStringRef *,
        etc
        """
        if ptr[0] != self._ffi.NULL:
            self._lib.CFRelease(self._ffi.cast("CFTypeRef", ptr[0]))
            ptr[0] = self._ffi.NULL


backend = Backend()
