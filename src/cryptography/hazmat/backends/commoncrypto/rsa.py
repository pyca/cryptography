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

import math

from pyasn1.codec.der import decoder
from pyasn1.type import namedtype, namedval, univ

from cryptography import utils
from cryptography.exceptions import (
    AlreadyFinalized, InvalidSignature, UnsupportedAlgorithm, _Reasons
)
from cryptography.hazmat.backends.commoncrypto.asn1 import build_public_pkcs1
from cryptography.hazmat.backends.commoncrypto.hashes import _HashContext
from cryptography.hazmat.primitives import hashes, interfaces
from cryptography.hazmat.primitives.asymmetric.padding import (
    MGF1, OAEP, PKCS1v15
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.interfaces import (
    RSAPrivateKey, RSAPublicKey
)


@utils.register_interface(interfaces.AsymmetricVerificationContext)
class _RSAVerificationContext(object):
    def __init__(self, backend, public_key, signature, padding, algorithm):
        self._backend = backend
        self._public_key = public_key
        self._signature = self._backend._lib.CFDataCreate(
            self._backend._lib.kCFAllocatorDefault,
            signature,
            len(signature)
        )
        self._signature = self._backend._ffi.gc(
            self._signature, self._backend._release_cftyperef
        )

        if not isinstance(padding, interfaces.AsymmetricPadding):
            raise TypeError(
                "Expected provider of interfaces.AsymmetricPadding.")

        if not isinstance(padding, PKCS1v15):
            raise UnsupportedAlgorithm(
                "{0} is not supported by this backend.".format(padding.name),
                _Reasons.UNSUPPORTED_PADDING
            )

        self._padding = padding
        self._algorithm = algorithm
        self._hash_ctx = _HashContext(backend, self._algorithm)

        if isinstance(self._algorithm, hashes.MD5):
            self._digestenum = self._backend._lib.kSecDigestMD5
            self._digestlen = self._backend._create_cfnumber(128)
        elif isinstance(self._algorithm, hashes.SHA1):
            self._digestenum = self._backend._lib.kSecDigestSHA1
            self._digestlen = self._backend._create_cfnumber(160)
        elif isinstance(self._algorithm, hashes.SHA224):
            self._digestenum = self._backend._lib.kSecDigestSHA2
            self._digestlen = self._backend._create_cfnumber(224)
        elif isinstance(self._algorithm, hashes.SHA256):
            self._digestenum = self._backend._lib.kSecDigestSHA2
            self._digestlen = self._backend._create_cfnumber(256)
        elif isinstance(self._algorithm, hashes.SHA384):
            self._digestenum = self._backend._lib.kSecDigestSHA2
            self._digestlen = self._backend._create_cfnumber(384)
        elif isinstance(self._algorithm, hashes.SHA512):
            self._digestenum = self._backend._lib.kSecDigestSHA2
            self._digestlen = self._backend._create_cfnumber(512)

    def update(self, data):
        if self._hash_ctx is None:
            raise AlreadyFinalized("Context has already been finalized.")

        self._hash_ctx.update(data)

    def verify(self):
        if self._hash_ctx is None:
            raise AlreadyFinalized("Context has already been finalized.")

        digest = self._hash_ctx.finalize()
        dataref = self._backend._lib.CFDataCreate(
            self._backend._lib.kCFAllocatorDefault,
            digest,
            len(digest)
        )
        assert dataref != self._backend._ffi.NULL
        dataref = self._backend._ffi.gc(
            dataref, self._backend._release_cftyperef
        )
        self._hash_ctx = None
        error = self._backend._ffi.new("CFErrorRef *")
        error = self._backend._ffi.gc(
            error, self._backend._release_cftyperef_ptr
        )
        verifier = self._backend._lib.SecVerifyTransformCreate(
            self._public_key._keyref, self._signature, error
        )
        assert error[0] == self._backend._ffi.NULL
        assert verifier != self._backend._ffi.NULL
        verifier = self._backend._ffi.gc(
            verifier, self._backend._release_cftyperef
        )
        res = self._backend._lib.SecTransformSetAttribute(
            verifier,
            self._backend._lib.kSecTransformInputAttributeName,
            self._backend._ffi.cast("CFTypeRef", dataref),
            error
        )
        assert error[0] == self._backend._ffi.NULL
        assert res == 1
        res = self._backend._lib.SecTransformSetAttribute(
            verifier,
            self._backend._lib.kSecInputIsAttributeName,
            self._backend._ffi.cast(
                "CFTypeRef", self._backend._lib.kSecInputIsDigest
            ),
            error
        )
        assert error[0] == self._backend._ffi.NULL
        assert res == 1
        res = self._backend._lib.SecTransformSetAttribute(
            verifier,
            self._backend._lib.kSecDigestTypeAttribute,
            self._backend._ffi.cast("CFTypeRef", self._digestenum),
            error
        )
        assert error[0] == self._backend._ffi.NULL
        assert res == 1
        res = self._backend._lib.SecTransformSetAttribute(
            verifier,
            self._backend._lib.kSecDigestLengthAttribute,
            self._backend._ffi.cast("CFTypeRef", self._digestlen),
            error
        )
        assert error[0] == self._backend._ffi.NULL
        assert res == 1
        verified = self._backend._lib.SecTransformExecute(verifier, error)
        if error[0] != self._backend._ffi.NULL:
            raise InvalidSignature
        else:
            verified = self._backend._ffi.gc(
                verified, self._backend._release_cftyperef
            )
            result = self._backend._lib.CFBooleanGetValue(
                self._backend._ffi.cast("CFBooleanRef", verified)
            )
            if not result:
                raise InvalidSignature


@utils.register_interface(interfaces.AsymmetricSignatureContext)
class _RSASignatureContext(object):
    def __init__(self, backend, private_key, padding, algorithm):
        self._backend = backend
        self._private_key = private_key

        if not isinstance(padding, interfaces.AsymmetricPadding):
            raise TypeError(
                "Expected provider of interfaces.AsymmetricPadding.")

        if not isinstance(padding, PKCS1v15):
            raise UnsupportedAlgorithm(
                "{0} is not supported by this backend.".format(padding.name),
                _Reasons.UNSUPPORTED_PADDING
            )

        self._padding = padding
        self._algorithm = algorithm
        if isinstance(self._algorithm, hashes.MD5):
            self._digestenum = self._backend._lib.kSecDigestMD5
            self._digestlen = self._backend._create_cfnumber(128)
        elif isinstance(self._algorithm, hashes.SHA1):
            self._digestenum = self._backend._lib.kSecDigestSHA1
            self._digestlen = self._backend._create_cfnumber(160)
        elif isinstance(self._algorithm, hashes.SHA224):
            self._digestenum = self._backend._lib.kSecDigestSHA2
            self._digestlen = self._backend._create_cfnumber(224)
        elif isinstance(self._algorithm, hashes.SHA256):
            self._digestenum = self._backend._lib.kSecDigestSHA2
            self._digestlen = self._backend._create_cfnumber(256)
        elif isinstance(self._algorithm, hashes.SHA384):
            self._digestenum = self._backend._lib.kSecDigestSHA2
            self._digestlen = self._backend._create_cfnumber(384)
        elif isinstance(self._algorithm, hashes.SHA512):
            self._digestenum = self._backend._lib.kSecDigestSHA2
            self._digestlen = self._backend._create_cfnumber(512)
        else:
            raise UnsupportedAlgorithm("TODO")

        self._hash_ctx = _HashContext(backend, self._algorithm)

    def update(self, data):
        if self._hash_ctx is None:
            raise AlreadyFinalized("Context has already been finalized.")

        self._hash_ctx.update(data)

    def finalize(self):
        if self._hash_ctx is None:
            raise AlreadyFinalized("Context has already been finalized.")

        digest = self._hash_ctx.finalize()
        dataref = self._backend._lib.CFDataCreate(
            self._backend._lib.kCFAllocatorDefault,
            digest,
            len(digest)
        )
        assert dataref != self._backend._ffi.NULL
        dataref = self._backend._ffi.gc(
            dataref, self._backend._release_cftyperef
        )
        self._hash_ctx = None
        error = self._backend._ffi.new("CFErrorRef *")
        error = self._backend._ffi.gc(
            error, self._backend._release_cftyperef_ptr
        )
        signer = self._backend._lib.SecSignTransformCreate(
            self._private_key._keyref, error
        )
        assert error[0] == self._backend._ffi.NULL
        assert signer != self._backend._ffi.NULL
        signer = self._backend._ffi.gc(
            signer, self._backend._release_cftyperef
        )
        res = self._backend._lib.SecTransformSetAttribute(
            signer,
            self._backend._lib.kSecTransformInputAttributeName,
            self._backend._ffi.cast("CFTypeRef", dataref),
            error
        )
        assert error[0] == self._backend._ffi.NULL
        assert res == 1
        res = self._backend._lib.SecTransformSetAttribute(
            signer,
            self._backend._lib.kSecInputIsAttributeName,
            self._backend._ffi.cast(
                "CFTypeRef", self._backend._lib.kSecInputIsDigest
            ),
            error
        )
        assert error[0] == self._backend._ffi.NULL
        assert res == 1
        res = self._backend._lib.SecTransformSetAttribute(
            signer,
            self._backend._lib.kSecDigestTypeAttribute,
            self._backend._ffi.cast("CFTypeRef", self._digestenum),
            error
        )
        assert error[0] == self._backend._ffi.NULL
        assert res == 1
        res = self._backend._lib.SecTransformSetAttribute(
            signer,
            self._backend._lib.kSecDigestLengthAttribute,
            self._backend._ffi.cast("CFTypeRef", self._digestlen),
            error
        )
        assert error[0] == self._backend._ffi.NULL
        assert res == 1
        sigref = self._backend._lib.SecTransformExecute(signer, error)
        if error[0] != self._backend._ffi.NULL:
            # TODO: think more about whether this is safe
            raise ValueError("Digest too large for key size. Use a larger "
                             "key.")

        assert sigref != self._backend._ffi.NULL
        sigref = self._backend._ffi.cast("CFDataRef", sigref)
        sigref = self._backend._ffi.gc(
            sigref, self._backend._release_cftyperef
        )
        siglen = self._backend._lib.CFDataGetLength(sigref)
        buf = self._backend._ffi.new("UInt8 []", siglen)
        self._backend._lib.CFDataGetBytes(
            sigref,
            self._backend._lib.CFRangeMake(0, siglen),  # TODO: verify this
            buf
        )
        return self._backend._ffi.buffer(buf)[:]


@utils.register_interface(RSAPrivateKey)
class _RSAPrivateKey(object):
    def __init__(self, backend, keyref, key_size):
        self._backend = backend
        self._keyref = keyref
        self._key_size = key_size

    key_size = utils.read_only_property("_key_size")

    def public_key(self):
        dataref_ptr = self._backend._ffi.new("CFDataRef *")
        keyparams = self._backend._ffi.new(
            "SecItemImportExportKeyParameters *"
        )
        keyparams.flags = 0
        stringref = self._backend._lib.CFStringCreateWithCString(
            self._backend._lib.kCFAllocatorDefault,
            b"temppass",
            self._backend._lib.kCFStringEncodingASCII
        )
        stringref = self._backend._ffi.gc(
            stringref, self._backend._release_cftyperef
        )
        keyparams.passphrase = self._backend._ffi.cast("CFTypeRef", stringref)
        res = self._backend._lib.SecItemExport(
            self._backend._ffi.cast("CFTypeRef", self._keyref),
            self._backend._lib.kSecFormatWrappedOpenSSL,
            1,
            keyparams,
            dataref_ptr
        )
        assert res == 0
        assert dataref_ptr[0] != self._backend._ffi.NULL
        dataref_ptr = self._backend._ffi.gc(
            dataref_ptr, self._backend._release_cftyperef_ptr
        )
        dataref = dataref_ptr[0]

        datalen = self._backend._lib.CFDataGetLength(dataref)
        buf = self._backend._ffi.new("UInt8 []", datalen)
        self._backend._lib.CFDataGetBytes(
            dataref, self._backend._lib.CFRangeMake(0, datalen), buf
        )
        encrypted_pem = self._backend._ffi.buffer(buf)[:]
        split = encrypted_pem.splitlines()
        dek = split[2]
        split.pop()
        split.pop(0)
        split.pop(0)
        split.pop(0)
        split.pop(0)
        keydata = "".join(split)
        derdata = base64.b64decode(keydata)
        iv = binascii.unhexlify(dek.split(",")[1])

        cipher = _PEMCipher(TripleDES, CBC, 192 // 8)
        derdata = cipher.decrypt(derdata, "temppass", iv, self._backend)

        parsed = decoder.decode(derdata, asn1Spec=_PyASN1RSAPrivateKey())
        numbers = RSAPublicNumbers(
            n=int(parsed[0].getComponentByName("modulus")),
            e=int(parsed[0].getComponentByName("publicExponent"))
        )
        pubder = build_public_pkcs1(numbers)
        dataref = self._backend._lib.CFDataCreate(
            self._backend._lib.kCFAllocatorDefault,
            pubder,
            len(pubder)
        )

        secformat = self._backend._ffi.new(
            "SecExternalFormat *", self._backend._lib.kSecFormatOpenSSL
        )
        secitemtype = self._backend._ffi.new(
            "SecExternalItemType *", self._backend._lib.kSecItemTypePublicKey
        )
        outitems = self._backend._ffi.new("CFArrayRef *")
        outitems = self._backend._ffi.gc(
            outitems, self._backend._release_cftyperef_ptr
        )
        res = self._backend._lib.SecItemImport(
            dataref,
            self._backend._ffi.NULL,
            secformat,
            secitemtype,
            0,
            keyparams,
            self._backend._ffi.NULL,
            outitems
        )
        assert res == 0
        assert outitems[0] != self._backend._ffi.NULL
        keyref = self._backend._lib.CFArrayGetValueAtIndex(outitems[0], 0)
        keyref = self._backend._ffi.cast(
            "SecKeyRef", self._backend._lib.CFRetain(keyref)
        )
        keyref = self._backend._ffi.gc(
            keyref, self._backend._release_cftyperef
        )

        return _RSAPublicKey(self._backend, keyref, self._key_size)

    def signer(self, padding, algorithm):
        return _RSASignatureContext(self._backend, self, padding, algorithm)

    def decrypt(self, ciphertext, padding):
        if not isinstance(padding, interfaces.AsymmetricPadding):
            raise TypeError(
                "Padding must be an instance of AsymmetricPadding."
            )

        key_size_bytes = int(math.ceil(self.key_size / 8.0))
        if key_size_bytes != len(ciphertext):
            raise ValueError("Ciphertext length must be equal to key size.")

        dataref = self._backend._lib.CFDataCreate(
            self._backend._lib.kCFAllocatorDefault,
            ciphertext,
            len(ciphertext)
        )
        assert dataref != self._backend._ffi.NULL
        dataref = self._backend._ffi.gc(
            dataref, self._backend._release_cftyperef
        )
        decryptor = self._backend._lib.SecDecryptTransformCreate(
            self._keyref, self._backend._ffi.NULL
        )
        assert decryptor != self._backend._ffi.NULL
        decryptor = self._backend._ffi.gc(
            decryptor, self._backend._release_cftyperef
        )
        error = self._backend._ffi.new("CFErrorRef *")
        error = self._backend._ffi.gc(
            error, self._backend._release_cftyperef_ptr
        )
        res = self._backend._lib.SecTransformSetAttribute(
            decryptor,
            self._backend._lib.kSecTransformInputAttributeName,
            self._backend._ffi.cast("CFTypeRef", dataref),
            error
        )
        assert res == 1
        assert error[0] == self._backend._ffi.NULL
        if isinstance(padding, PKCS1v15):
            res = self._backend._lib.SecTransformSetAttribute(
                decryptor,
                self._backend._lib.kSecPaddingKey,
                self._backend._ffi.NULL,
                error
            )
        elif isinstance(padding, OAEP):
            if not isinstance(padding._mgf, MGF1):
                raise UnsupportedAlgorithm(
                    "Only MGF1 is supported by this backend.",
                    _Reasons.UNSUPPORTED_MGF
                )

            res = self._backend._lib.SecTransformSetAttribute(
                decryptor,
                self._backend._lib.kSecPaddingKey,
                self._backend._ffi.cast(
                    "CFTypeRef", self._backend._lib.kSecPaddingOAEPKey
                ),
                error
            )
        else:
            raise UnsupportedAlgorithm(
                "{0} is not supported by this backend.".format(
                    padding.name
                ),
                _Reasons.UNSUPPORTED_PADDING
            )

        assert error[0] == self._backend._ffi.NULL
        assert res == 1
        ptref = self._backend._lib.SecTransformExecute(decryptor, error)
        if error[0] != self._backend._ffi.NULL:
            raise ValueError("Decryption failed.")

        assert ptref != self._backend._ffi.NULL
        ptref = self._backend._ffi.cast("CFDataRef", ptref)
        ptref = self._backend._ffi.gc(ptref, self._backend._release_cftyperef)

        ptlen = self._backend._lib.CFDataGetLength(ptref)
        buf = self._backend._ffi.new("UInt8 []", ptlen)
        self._backend._lib.CFDataGetBytes(
            ptref,
            self._backend._lib.CFRangeMake(0, ptlen),
            buf
        )
        return self._backend._ffi.buffer(buf)[:]


@utils.register_interface(RSAPublicKey)
class _RSAPublicKey(object):
    def __init__(self, backend, keyref, key_size):
        self._backend = backend
        self._keyref = keyref
        self._key_size = key_size

    key_size = utils.read_only_property("_key_size")

    def verifier(self, signature, padding, algorithm):
        return _RSAVerificationContext(
            self._backend, self, signature, padding, algorithm
        )

    def encrypt(self, plaintext, padding):
        if not isinstance(padding, interfaces.AsymmetricPadding):
            raise TypeError(
                "Padding must be an instance of AsymmetricPadding."
            )

        dataref = self._backend._lib.CFDataCreate(
            self._backend._lib.kCFAllocatorDefault,
            plaintext,
            len(plaintext)
        )
        assert dataref != self._backend._ffi.NULL
        dataref = self._backend._ffi.gc(
            dataref, self._backend._release_cftyperef
        )
        encryptor = self._backend._lib.SecEncryptTransformCreate(
            self._keyref, self._backend._ffi.NULL
        )
        assert encryptor != self._backend._ffi.NULL
        encryptor = self._backend._ffi.gc(
            encryptor, self._backend._release_cftyperef
        )
        error = self._backend._ffi.new("CFErrorRef *")
        error = self._backend._ffi.gc(
            error, self._backend._release_cftyperef_ptr
        )
        res = self._backend._lib.SecTransformSetAttribute(
            encryptor,
            self._backend._lib.kSecTransformInputAttributeName,
            self._backend._ffi.cast("CFTypeRef", dataref),
            error
        )
        assert res == 1
        assert error[0] == self._backend._ffi.NULL
        if isinstance(padding, PKCS1v15):
            if len(plaintext) > math.ceil(self.key_size / 8.0) - 11:
                raise ValueError("Data too long for key size. Encrypt less "
                                 "data or use a larger key size.")

            res = self._backend._lib.SecTransformSetAttribute(
                encryptor,
                self._backend._lib.kSecPaddingKey,
                self._backend._ffi.NULL,
                error
            )
        elif isinstance(padding, OAEP):
            if not isinstance(padding._mgf, MGF1):
                raise UnsupportedAlgorithm(
                    "Only MGF1 is supported by this backend.",
                    _Reasons.UNSUPPORTED_MGF
                )

            if (
                len(plaintext) > math.ceil(
                    self.key_size / 8.0
                ) - 2 * padding._mgf._algorithm.digest_size - 2
            ):
                raise ValueError("Data too long for key size. Encrypt less "
                                 "data or use a larger key size.")

            res = self._backend._lib.SecTransformSetAttribute(
                encryptor,
                self._backend._lib.kSecPaddingKey,
                self._backend._ffi.cast(
                    "CFTypeRef", self._backend._lib.kSecPaddingOAEPKey
                ),
                error
            )
        else:
            raise UnsupportedAlgorithm(
                "{0} is not supported by this backend.".format(
                    padding.name
                ),
                _Reasons.UNSUPPORTED_PADDING
            )

        assert error[0] == self._backend._ffi.NULL
        assert res == 1
        ctref = self._backend._lib.SecTransformExecute(encryptor, error)
        assert error[0] == self._backend._ffi.NULL
        assert ctref != self._backend._ffi.NULL
        ctref = self._backend._ffi.cast("CFDataRef", ctref)
        ctref = self._backend._ffi.gc(ctref, self._backend._release_cftyperef)
        ctlen = self._backend._lib.CFDataGetLength(ctref)
        buf = self._backend._ffi.new("UInt8 []", ctlen)
        self._backend._lib.CFDataGetBytes(
            ctref,
            self._backend._lib.CFRangeMake(0, ctlen),
            buf
        )
        return self._backend._ffi.buffer(buf)[:]


class _PyASN1RSAPrivateKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "version",
            univ.Integer(
                namedValues=namedval.NamedValues(
                    ("two-prime", 0),
                    ("multi", 1),
                )
            )
        ),
        namedtype.NamedType("modulus", univ.Integer()),
        namedtype.NamedType("publicExponent", univ.Integer()),
        namedtype.NamedType("privateExponent", univ.Integer()),
        namedtype.NamedType("prime1", univ.Integer()),
        namedtype.NamedType("prime2", univ.Integer()),
        namedtype.NamedType("exponent1", univ.Integer()),
        namedtype.NamedType("exponent2", univ.Integer()),
        namedtype.NamedType("coefficient", univ.Integer()),
    )



import base64
import binascii

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers.base import Cipher
from cryptography.hazmat.primitives.ciphers.modes import CBC


class _PEMCipher(object):
    def __init__(self, algorithm_cls, mode_cls, key_size):
        self._algorithm_cls = algorithm_cls
        self._mode_cls = mode_cls
        self._key_size = key_size

    def _derive_key(self, password, salt, backend):
        key = b""
        while len(key) < self._key_size:
            hasher = hashes.Hash(hashes.MD5(), backend=backend)
            hasher.update(key)
            hasher.update(password)
            hasher.update(salt)
            key += hasher.finalize()
        return key[:self._key_size]

    def decrypt(self, data, password, iv, backend):
        key = self._derive_key(password, iv[:8], backend)
        decryptor = Cipher(
            self._algorithm_cls(key),
            self._mode_cls(iv),
            backend=backend
        ).decryptor()
        decrypted_data = decryptor.update(data) + decryptor.finalize()
        unpadder = padding.PKCS7(self._algorithm_cls.block_size).unpadder()
        return unpadder.update(decrypted_data) + unpadder.finalize()
