# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import base64
import binascii
import io
import re
import warnings

from pyasn1.codec.der import decoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import namedtype, namedval, tag, univ

import six

from cryptography import utils
from cryptography.exceptions import UnsupportedAlgorithm, _Reasons
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def load_pem_traditional_openssl_private_key(data, password, backend):
    warnings.warn(
        "load_pem_traditional_openssl_private_key is deprecated and will be "
        "removed in a future version, use load_pem_private_key instead.",
        utils.DeprecatedIn06,
        stacklevel=2
    )

    return load_pem_private_key(data, password, backend)


def load_pem_pkcs8_private_key(data, password, backend):
    warnings.warn(
        "load_pem_pkcs8_private_key is deprecated and will be removed in a "
        "future version, use load_pem_private_key instead.",
        utils.DeprecatedIn06,
        stacklevel=2
    )

    return load_pem_private_key(data, password, backend)


class _PasswordStorage(object):
    def __init__(self, password):
        self._password = password
        self.used = False

    def get(self):
        self.used = True
        return self._password


def load_pem_private_key(data, password, backend):
    if password:
        password = _PasswordStorage(password)
    pem = _PEMObject.find_pem(data)
    pem = pem.handle_encrypted(password, backend)
    parser_type = _PRIVATE_KEY_PARSERS[pem._object_type]
    result = parser_type(backend).load_object(pem._body, password)
    if password and not password.used:
        raise TypeError("password provided but not used")
    return result


def load_pem_public_key(data, backend):
    return backend.load_pem_public_key(data)


# RFC 3447, section A.1.2
class _OtherPrimeInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedTypes("prime", univ.Integer()),
        namedtype.NamedTypes("exponent", univ.Integer()),
        namedtype.NamedTypes("coefficient", univ.Integer()),
    )


# RFC 3447, section A.1.2
class _OtherPrimeInfos(univ.SequenceOf):
    componentType = _OtherPrimeInfo()


# RFC 3447, section A.1.2
class _RSAPrivateKey(univ.Sequence):
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
        namedtype.OptionalNamedType("otherPrimeInfos", _OtherPrimeInfos())
    )


class _RSAPrivateKeyParser(object):
    def __init__(self, backend):
        self._backend = backend

    def load_object(self, body, password):
        try:
            asn1_private_key, _ = decoder.decode(
                body, asn1Spec=_RSAPrivateKey()
            )
        except PyAsn1Error:
            raise ValueError("Could not unserialize key data.")

        assert asn1_private_key.getComponentByName("version") == 0
        return rsa.RSAPrivateNumbers(
            int(asn1_private_key.getComponentByName("prime1")),
            int(asn1_private_key.getComponentByName("prime2")),
            int(asn1_private_key.getComponentByName("privateExponent")),
            int(asn1_private_key.getComponentByName("exponent1")),
            int(asn1_private_key.getComponentByName("exponent2")),
            int(asn1_private_key.getComponentByName("coefficient")),
            rsa.RSAPublicNumbers(
                int(asn1_private_key.getComponentByName("publicExponent")),
                int(asn1_private_key.getComponentByName("modulus")),
            )
        ).private_key(self._backend)


class _DSAPrivateKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("version", univ.Integer()),
        namedtype.NamedType("p", univ.Integer()),
        namedtype.NamedType("q", univ.Integer()),
        namedtype.NamedType("g", univ.Integer()),
        namedtype.NamedType("pub_key", univ.Integer()),
        namedtype.NamedType("priv_key", univ.Integer()),
    )


class _DSAPrivateKeyParser(object):
    def __init__(self, backend):
        self._backend = backend

    def load_object(self, body, password):
        asn1_private_key, _ = decoder.decode(
            body, asn1Spec=_DSAPrivateKey()
        )
        return dsa.DSAPrivateNumbers(
            int(asn1_private_key.getComponentByName("priv_key")),
            dsa.DSAPublicNumbers(
                int(asn1_private_key.getComponentByName("pub_key")),
                dsa.DSAParameterNumbers(
                    int(asn1_private_key.getComponentByName("p")),
                    int(asn1_private_key.getComponentByName("q")),
                    int(asn1_private_key.getComponentByName("g")),
                )
            )
        ).private_key(self._backend)


# RFC 5480, section 2.1.1
class _ECParameters(univ.Choice):
    # TODO: There are a few more options for this choice I think, the RFC says
    # not to use them though...
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("namedCurve", univ.ObjectIdentifier()),
    )


# RFC 5915, Appendix A
class _ECPrivateKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "version",
            univ.Integer(
                namedValues=namedval.NamedValues(
                    ("ecPrivkeyVer1", 1),
                )
            ),
        ),
        namedtype.NamedType("privateKey", univ.OctetString()),
        namedtype.OptionalNamedType("parameters", _ECParameters().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0),
        )),
        namedtype.OptionalNamedType("publicKey", univ.BitString().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1),
        )),
    )


def bytes_to_int(b):
    return sum(c << (i * 8) for i, c in enumerate(reversed(b)))


def int_to_bytes(x, width):
    b = b""
    while x:
        b = six.int2byte(x & 255) + b
        x >>= 8
    if len(b) < width:
        b = (b"\x00" * (width - len(b))) + b
    return b


def bits_to_int(b):
    return sum(c << i for i, c in enumerate(b))


def bits_to_bytes(b):
    return [
        bits_to_int(reversed(b[i:i + 8]))
        for i in xrange(0, len(b), 8)
    ]


class _ECDSAPrivateKeyParser(object):
    def __init__(self, backend):
        self._backend = backend

    def load_object(self, body, password):
        asn1_private_key, _ = decoder.decode(
            body, asn1Spec=_ECPrivateKey()
        )

        private_value = bytes_to_int(
            map(ord, asn1_private_key.getComponentByName("privateKey"))
        )
        public_key = bits_to_bytes(
            asn1_private_key.getComponentByName("publicKey")
        )
        if public_key[0] != 4:
            raise ValueError

        curve_oid = asn1_private_key.getComponentByName(
            "parameters"
        ).getComponentByName("namedCurve").asTuple()
        curve = ec._OID_TO_CURVE[curve_oid]()

        x = bytes_to_int(public_key[1:(curve.key_size // 8) + 1])
        y = bytes_to_int(public_key[(curve.key_size // 8) + 1:])

        return ec.EllipticCurvePrivateNumbers(
            private_value,
            ec.EllipticCurvePublicNumbers(
                x, y, curve
            )
        ).private_key(self._backend)


# RFC 5280, section 4.1.1.2
class _AlgorithmIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("algorithm", univ.ObjectIdentifier()),
        namedtype.OptionalNamedType("parameters", univ.Any()),
    )


# RFC 5208, section 6
class _EncryptedPrivateKeyInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("encryptionAlgorithm", _AlgorithmIdentifier()),
        namedtype.NamedType("encryptedData", univ.OctetString()),
    )


class _EncryptedPKCS8Parser(object):
    def __init__(self, backend):
        self._backend = backend

    def load_object(self, body, password):
        try:
            asn1_encrypted_private_key_info, _ = decoder.decode(
                body, asn1Spec=_EncryptedPrivateKeyInfo()
            )
        except PyAsn1Error:
            raise ValueError("Could not unserialize key data.")

        if not password:
            raise TypeError(
                "Password was not given but private key is encrypted."
            )

        encryption_algorithm = (
            asn1_encrypted_private_key_info.getComponentByName(
                "encryptionAlgorithm"
            )
        )
        algorithm_oid = encryption_algorithm.getComponentByName(
            "algorithm"
        ).asTuple()
        try:
            pkcs8_cipher = _PKCS8_CIPHERS[algorithm_oid]
        except KeyError:
            raise UnsupportedAlgorithm(
                "PKCS8 data is encrypted with an unsupported cipher",
                _Reasons.UNSUPPORTED_CIPHER
            )

        contents = pkcs8_cipher.decrypt(
            bytes(encryption_algorithm.getComponentByName("parameters")),
            bytes(
                asn1_encrypted_private_key_info.getComponentByName(
                    "encryptedData"
                )
            ),
            password.get(),
            self._backend
        )
        return _PKCS8Parser(self._backend).load_object(contents, None)


# RFC 2898, appendix A.3
class _PBEParameter(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("salt", univ.OctetString()),
        namedtype.NamedType("iterationCount", univ.Integer())
    )


class _PKCS12Cipher(object):
    def __init__(self, algorithm_cls, hash_cls, key_size):
        self._algorithm_cls = algorithm_cls
        self._hash_cls = hash_cls
        self._key_size = key_size

    def _encode_password(self, password):
        result = bytearray(len(password) * 2 + 2)
        for i, c in enumerate(password):
            result[i * 2] = 0
            result[i * 2 + 1] = c
        return bytes(result)

    def _make_block(self, data):
        assert data
        v = self._hash_cls.block_size
        size = ((len(data) + v - 1) // v) * v
        return bytearray((((size + len(data) - 1)) // len(data)) * data)[:size]

    def _kdf(self, encoded_password, salt, iterations, desired_length,
             identifier, backend):
        v = self._hash_cls.block_size
        D = v * six.int2byte(identifier)
        I = (
            self._make_block(salt) +
            self._make_block(encoded_password + b"\x00\x00")
        )

        key = b""
        while len(key) < desired_length:
            A = bytes(D + I)
            for i in range(iterations):
                h = hashes.Hash(self._hash_cls(), backend)
                h.update(A)
                A = h.finalize()

            B = bytes_to_int(self._make_block(A))
            for i in range(0, len(I), v):
                x = (bytes_to_int(I[i:i + v]) + B + 1) % (1 << (v * 8))
                I[i:i + v] = int_to_bytes(x, v)
            key += A
        return key[:desired_length]

    def decrypt(self, parameters, data, password, backend):
        asn1_params, _ = decoder.decode(parameters, _PBEParameter())
        encoded_password = password.encode("utf-16be")
        salt = bytes(asn1_params.getComponentByName("salt"))
        iterations = int(asn1_params.getComponentByName("iterationCount"))

        key = self._kdf(
            encoded_password, salt, iterations,
            identifier=1,
            desired_length=self._key_size,
            backend=backend
        )
        iv = self._kdf(
            encoded_password, salt, iterations,
            identifier=2,
            desired_length=self._algorithm_cls.block_size // 8,
            backend=backend
        )
        decryptor = Cipher(
            self._algorithm_cls(key), modes.CBC(iv), backend=backend
        ).decryptor()
        unpadder = padding.PKCS7(self._algorithm_cls.block_size).unpadder()
        plaintext = unpadder.update(decryptor.update(data))
        plaintext += unpadder.update(decryptor.finalize())
        return plaintext + unpadder.finalize()


# RFC 2898, appendix A.4
class _PBES2Params(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("keyDerivationFunc", _AlgorithmIdentifier()),
        namedtype.NamedType("encryptionScheme", _AlgorithmIdentifier()),
    )


# RFC 2898, appendix A.2
class _PBKDF2Salt(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("specified", univ.OctetString()),
        namedtype.NamedType("otherSource", _AlgorithmIdentifier()),
    )


class _PBKDF2ParamsDefaultPRF(object):
    def clone(self):
        return _AlgorithmIdentifier().setComponentByName(
            "algorithm", univ.ObjectIdentifier("1.2.840.113549.2.7")
        )


# RFC 2898, appendix A.2
class _PBKDF2Params(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("salt", _PBKDF2Salt()),
        namedtype.NamedType("iterationCount", univ.Integer()),
        namedtype.OptionalNamedType("keyLength", univ.Integer()),
        # TODO: is this the correct way to set the default?
        namedtype.DefaultedNamedType("prf", _PBKDF2ParamsDefaultPRF()),
    )



class _PBES2(object):
    def decrypt(self, parameters, data, password, backend):
        asn1_pbes2_parameters_asn1, _ = decoder.decode(parameters, asn1Spec=_PBES2Params())
        kdf = asn1_pbes2_parameters_asn1.getComponentByName("keyDerivationFunc")
        kdf_oid = kdf.getComponentByName("algorithm").asTuple()
        # PBKDF2
        assert kdf_oid == (1, 2, 840, 113549, 1, 5, 12)
        asn1_pbkdf2_params, _ = decoder.decode(
            kdf.getComponentByName("parameters"), asn1Spec=_PBKDF2Params()
        )
        asn1_salt = asn1_pbkdf2_params.getComponentByName("salt").getComponentByName("specified")
        assert asn1_salt is not None
        salt = bytes(asn1_salt)
        iterations = int(asn1_pbkdf2_params.getComponentByName("iterationCount"))
        # TODO: support explicit key length and just assert it matches the one from the cipher
        assert asn1_pbkdf2_params.getComponentByName("keyLength") is None
        prf_algorithm = asn1_pbkdf2_params.getComponentByName("prf").getComponentByName("algorithm")
        # HMAC-SHA1 PRF
        assert prf_algorithm.asTuple() == (1, 2, 840, 113549, 2, 7)

        encryption = asn1_pbes2_parameters_asn1.getComponentByName("encryptionScheme")
        # AES-128-CBC
        assert encryption.getComponentByName("algorithm").asTuple() == (2, 16, 840, 1, 101, 3, 4, 1, 2)
        iv, _ = decoder.decode(encryption.getComponentByName("parameters"), asn1Spec=univ.OctetString())

        key = PBKDF2HMAC(hashes.SHA1(), 128 // 8, salt, iterations, backend=backend).derive(password)
        decryptor = Cipher(algorithms.AES(key), modes.CBC(bytes(iv)), backend=backend).decryptor()
        plaintext = decryptor.update(data) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        return unpadder.update(plaintext) + unpadder.finalize()


_PKCS8_CIPHERS = {
    (1, 2, 840, 113549, 1, 12, 1, 3): _PKCS12Cipher(
        algorithms.TripleDES, hashes.SHA1, 192 // 8
    ),
    (1, 2, 840, 113549, 1, 5, 13): _PBES2(),
}


# RFC 5208, section 5
class _PrivateKeyInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("version", univ.Integer()),
        namedtype.NamedType("privateKeyAlgorithm", _AlgorithmIdentifier()),
        namedtype.NamedType("privateKey", univ.OctetString()),
        # The "attributes" field is ignored.
    )


class _DSAAlgorithmIdentifierParameters(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("p", univ.Integer()),
        namedtype.NamedType("q", univ.Integer()),
        namedtype.NamedType("g", univ.Integer()),
    )


class _PKCS8Parser(object):
    def __init__(self, backend):
        self._backend = backend

    def load_object(self, body, password):
        try:
            asn1_private_key_info, _ = decoder.decode(
                body, asn1Spec=_PrivateKeyInfo()
            )
        except PyAsn1Error:
            raise ValueError("Could not unserialize key data.")

        assert asn1_private_key_info.getComponentByName("version") == 0

        private_key_algorithm = asn1_private_key_info.getComponentByName(
            "privateKeyAlgorithm"
        )
        algorithm = private_key_algorithm.getComponentByName("algorithm")
        if algorithm.asTuple() == (1, 2, 840, 10040, 4, 1):
            # DSA
            asn1_parameters, _ = decoder.decode(
                private_key_algorithm.getComponentByName("parameters"),
                asn1Spec=_DSAAlgorithmIdentifierParameters()
            )
            x, _ = decoder.decode(
                asn1_private_key_info.getComponentByName('privateKey'),
                asn1Spec=univ.Integer()
            )

            x = int(x)
            p = int(asn1_parameters.getComponentByName("p"))
            q = int(asn1_parameters.getComponentByName("q"))
            g = int(asn1_parameters.getComponentByName("g"))
            return dsa.DSAPrivateNumbers(
                x,
                dsa.DSAPublicNumbers(
                    pow(g, x, p),
                    dsa.DSAParameterNumbers(p, q, g)
                )
            ).private_key(self._backend)
        elif algorithm.asTuple() == (1, 2, 840, 113549, 1, 1, 1):
            # RSA
            asn1_rsa, _ = decoder.decode(
                asn1_private_key_info.getComponentByName("privateKey"),
                asn1Spec=_RSAPrivateKey()
            )
            return rsa.RSAPrivateNumbers(
                int(asn1_rsa.getComponentByName("prime1")),
                int(asn1_rsa.getComponentByName("prime2")),
                int(asn1_rsa.getComponentByName("privateExponent")),
                int(asn1_rsa.getComponentByName("exponent1")),
                int(asn1_rsa.getComponentByName("exponent2")),
                int(asn1_rsa.getComponentByName("coefficient")),
                rsa.RSAPublicNumbers(
                    int(asn1_rsa.getComponentByName("publicExponent")),
                    int(asn1_rsa.getComponentByName("modulus")),
                )
            ).private_key(self._backend)
        elif algorithm.asTuple() == (1, 2, 840, 10045, 2, 1):
            curve_oid, _ = decoder.decode(private_key_algorithm.getComponentByName("parameters"), asn1Spec=univ.ObjectIdentifier())
            asn1_private_key, _ = decoder.decode(
                asn1_private_key_info.getComponentByName("privateKey"), asn1Spec=_ECPrivateKey()
            )

            private_value = bytes_to_int(
                map(ord, asn1_private_key.getComponentByName("privateKey"))
            )
            public_key = bits_to_bytes(
                asn1_private_key.getComponentByName("publicKey")
            )
            if public_key[0] != 4:
                raise ValueError

            curve = ec._OID_TO_CURVE[curve_oid]()

            x = bytes_to_int(public_key[1:(curve.key_size // 8) + 1])
            y = bytes_to_int(public_key[(curve.key_size // 8) + 1:])

            return ec.EllipticCurvePrivateNumbers(
                private_value,
                ec.EllipticCurvePublicNumbers(
                    x, y, curve
                )
            ).private_key(self._backend)

        else:
            raise UnsupportedAlgorithm(
                "%s" % algorithm, _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
            )


_PRIVATE_KEY_PARSERS = {
    b"DSA PRIVATE KEY": _DSAPrivateKeyParser,
    b"EC PRIVATE KEY": _ECDSAPrivateKeyParser,
    b"RSA PRIVATE KEY": _RSAPrivateKeyParser,
    b"ENCRYPTED PRIVATE KEY": _EncryptedPKCS8Parser,
    b"PRIVATE KEY": _PKCS8Parser,
}


_PEM_BEGIN_RE = re.compile(b"-----BEGIN ([\w ]+?)-----")


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


_PEM_CIPHERS = {
    "AES-128-CBC": _PEMCipher(algorithms.AES, modes.CBC, 128 // 8),
    "AES-256-CBC": _PEMCipher(algorithms.AES, modes.CBC, 256 // 8),
    "DES-EDE3-CBC": _PEMCipher(algorithms.TripleDES, modes.CBC, 192 // 8),
}


class _PEMObject(object):
    def __init__(self, object_type, headers, body):
        self._object_type = object_type
        self._headers = headers
        self._body = body

    @classmethod
    def find_pem(cls, data):
        data = io.BytesIO(data)
        for line in data:
            match = _PEM_BEGIN_RE.match(line)
            if match is not None:
                break
        else:
            raise ValueError("no PEM object")

        object_type = match.group(1)
        body_lines = []
        headers = []
        for line in data:
            line = line.strip()
            if b":" in line:
                # TODO: line continuations :-()
                name, value = line.split(b":", 1)
                headers.append((name, value.strip()))
            elif line == b"-----END " + object_type + b"-----":
                break
            else:
                body_lines.append(line)
        else:
            raise ValueError("No end marker")

        return cls(
            object_type, headers, base64.b64decode(b"".join(body_lines))
        )

    def handle_encrypted(self, password, backend):
        encrypted = False
        dek_info = None
        for key, value in self._headers:
            if key == "Proc-Type" and value == "4,ENCRYPTED":
                encrypted = True
            elif key == "DEK-Info":
                dek_info = value

        if not encrypted:
            return self
        elif dek_info is None:
            raise ValueError("Missing DEK-INFO")
        elif not password:
            raise TypeError(
                "Password was not given but private key is encrypted."
            )

        algorithm_name, hex_iv = dek_info.split(",", 1)
        iv = binascii.unhexlify(hex_iv)
        try:
            pem_cipher = _PEM_CIPHERS[algorithm_name]
        except KeyError:
            raise UnsupportedAlgorithm(
                "PEM data is encrypted with an unsupported cipher",
                _Reasons.UNSUPPORTED_CIPHER
            )

        body = pem_cipher.decrypt(self._body, password.get(), iv, backend)
        return _PEMObject(self._object_type, [], body)
