# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import abc

import six

from cryptography import utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.hazmat.primitives.interfaces.ciphers import (
    BlockCipherAlgorithm, CipherAlgorithm, Mode,
    ModeWithAuthenticationTag, ModeWithInitializationVector, ModeWithNonce
)

__all__ = [
    "BlockCipherAlgorithm",
    "CipherAlgorithm",
    "Mode",
    "ModeWithAuthenticationTag",
    "ModeWithInitializationVector",
    "ModeWithNonce"
]


EllipticCurve = utils.deprecated(
    ec.EllipticCurve,
    __name__,
    (
        "The EllipticCurve interface has moved to the "
        "cryptography.hazmat.primitives.asymmetric.ec module"
    ),
    utils.DeprecatedIn08
)


EllipticCurvePrivateKey = utils.deprecated(
    ec.EllipticCurvePrivateKey,
    __name__,
    (
        "The EllipticCurvePrivateKey interface has moved to the "
        "cryptography.hazmat.primitives.asymmetric.ec module"
    ),
    utils.DeprecatedIn08
)


EllipticCurvePrivateKeyWithNumbers = utils.deprecated(
    ec.EllipticCurvePrivateKeyWithNumbers,
    __name__,
    (
        "The EllipticCurvePrivateKeyWithNumbers interface has moved to the "
        "cryptography.hazmat.primitives.asymmetric.ec module"
    ),
    utils.DeprecatedIn08
)


EllipticCurvePublicKey = utils.deprecated(
    ec.EllipticCurvePublicKey,
    __name__,
    (
        "The EllipticCurvePublicKey interface has moved to the "
        "cryptography.hazmat.primitives.asymmetric.ec module"
    ),
    utils.DeprecatedIn08
)


EllipticCurvePublicKeyWithNumbers = utils.deprecated(
    ec.EllipticCurvePublicKeyWithNumbers,
    __name__,
    (
        "The EllipticCurvePublicKeyWithNumbers interface has moved to the "
        "cryptography.hazmat.primitives.asymmetric.ec module"
    ),
    utils.DeprecatedIn08
)


EllipticCurveSignatureAlgorithm = utils.deprecated(
    ec.EllipticCurveSignatureAlgorithm,
    __name__,
    (
        "The EllipticCurveSignatureAlgorithm interface has moved to the "
        "cryptography.hazmat.primitives.asymmetric.ec module"
    ),
    utils.DeprecatedIn08
)


DSAParameters = utils.deprecated(
    dsa.DSAParameters,
    __name__,
    (
        "The DSAParameters interface has moved to the "
        "cryptography.hazmat.primitives.asymmetric.dsa.module"
    ),
    utils.DeprecatedIn08
)

DSAParametersWithNumbers = utils.deprecated(
    dsa.DSAParametersWithNumbers,
    __name__,
    (
        "The DSAParametersWithNumbers interface has moved to the "
        "cryptography.hazmat.primitives.asymmetric.dsa.module"
    ),
    utils.DeprecatedIn08
)

DSAPrivateKey = utils.deprecated(
    dsa.DSAPrivateKey,
    __name__,
    (
        "The DSAPrivateKey interface has moved to the "
        "cryptography.hazmat.primitives.asymmetric.dsa.module"
    ),
    utils.DeprecatedIn08
)

DSAPrivateKeyWithNumbers = utils.deprecated(
    dsa.DSAPrivateKeyWithNumbers,
    __name__,
    (
        "The DSAPrivateKeyWithNumbers interface has moved to the "
        "cryptography.hazmat.primitives.asymmetric.dsa.module"
    ),
    utils.DeprecatedIn08
)

DSAPublicKey = utils.deprecated(
    dsa.DSAPublicKey,
    __name__,
    (
        "The DSAPublicKeyWithNumbers interface has moved to the "
        "cryptography.hazmat.primitives.asymmetric.dsa.module"
    ),
    utils.DeprecatedIn08
)

DSAPublicKeyWithNumbers = utils.deprecated(
    dsa.DSAPublicKeyWithNumbers,
    __name__,
    (
        "The DSAPublicKeyWithNumbers interface has moved to the "
        "cryptography.hazmat.primitives.asymmetric.dsa.module"
    ),
    utils.DeprecatedIn08
)


@six.add_metaclass(abc.ABCMeta)
class CipherContext(object):
    @abc.abstractmethod
    def update(self, data):
        """
        Processes the provided bytes through the cipher and returns the results
        as bytes.
        """

    @abc.abstractmethod
    def finalize(self):
        """
        Returns the results of processing the final block as bytes.
        """


@six.add_metaclass(abc.ABCMeta)
class AEADCipherContext(object):
    @abc.abstractmethod
    def authenticate_additional_data(self, data):
        """
        Authenticates the provided bytes.
        """


@six.add_metaclass(abc.ABCMeta)
class AEADEncryptionContext(object):
    @abc.abstractproperty
    def tag(self):
        """
        Returns tag bytes. This is only available after encryption is
        finalized.
        """


@six.add_metaclass(abc.ABCMeta)
class PaddingContext(object):
    @abc.abstractmethod
    def update(self, data):
        """
        Pads the provided bytes and returns any available data as bytes.
        """

    @abc.abstractmethod
    def finalize(self):
        """
        Finalize the padding, returns bytes.
        """


HashContext = utils.deprecated(
    hashes.HashContext,
    __name__,
    (
        "The HashContext interface has moved to the "
        "cryptography.hazmat.primitives.hashes module"
    ),
    utils.DeprecatedIn08
)


HashAlgorithm = utils.deprecated(
    hashes.HashAlgorithm,
    __name__,
    (
        "The HashAlgorithm interface has moved to the "
        "cryptography.hazmat.primitives.hashes module"
    ),
    utils.DeprecatedIn08
)


RSAPrivateKey = utils.deprecated(
    rsa.RSAPrivateKey,
    __name__,
    (
        "The RSAPrivateKey interface has moved to the "
        "cryptography.hazmat.primitives.asymmetric.rsa module"
    ),
    utils.DeprecatedIn08
)

RSAPrivateKeyWithNumbers = utils.deprecated(
    rsa.RSAPrivateKeyWithNumbers,
    __name__,
    (
        "The RSAPrivateKeyWithNumbers interface has moved to the "
        "cryptography.hazmat.primitives.asymmetric.rsa module"
    ),
    utils.DeprecatedIn08
)

RSAPublicKey = utils.deprecated(
    rsa.RSAPublicKey,
    __name__,
    (
        "The RSAPublicKeyWithNumbers interface has moved to the "
        "cryptography.hazmat.primitives.asymmetric.rsa module"
    ),
    utils.DeprecatedIn08
)

RSAPublicKeyWithNumbers = utils.deprecated(
    rsa.RSAPublicKeyWithNumbers,
    __name__,
    (
        "The RSAPublicKeyWithNumbers interface has moved to the "
        "cryptography.hazmat.primitives.asymmetric.rsa module"
    ),
    utils.DeprecatedIn08
)


@six.add_metaclass(abc.ABCMeta)
class AsymmetricSignatureContext(object):
    @abc.abstractmethod
    def update(self, data):
        """
        Processes the provided bytes and returns nothing.
        """

    @abc.abstractmethod
    def finalize(self):
        """
        Returns the signature as bytes.
        """


@six.add_metaclass(abc.ABCMeta)
class AsymmetricVerificationContext(object):
    @abc.abstractmethod
    def update(self, data):
        """
        Processes the provided bytes and returns nothing.
        """

    @abc.abstractmethod
    def verify(self):
        """
        Raises an exception if the bytes provided to update do not match the
        signature or the signature does not match the public key.
        """


@six.add_metaclass(abc.ABCMeta)
class AsymmetricPadding(object):
    @abc.abstractproperty
    def name(self):
        """
        A string naming this padding (e.g. "PSS", "PKCS1").
        """


@six.add_metaclass(abc.ABCMeta)
class KeyDerivationFunction(object):
    @abc.abstractmethod
    def derive(self, key_material):
        """
        Deterministically generates and returns a new key based on the existing
        key material.
        """

    @abc.abstractmethod
    def verify(self, key_material, expected_key):
        """
        Checks whether the key generated by the key material matches the
        expected derived key. Raises an exception if they do not match.
        """


@six.add_metaclass(abc.ABCMeta)
class MACContext(object):
    @abc.abstractmethod
    def update(self, data):
        """
        Processes the provided bytes.
        """

    @abc.abstractmethod
    def finalize(self):
        """
        Returns the message authentication code as bytes.
        """

    @abc.abstractmethod
    def copy(self):
        """
        Return a MACContext that is a copy of the current context.
        """

    @abc.abstractmethod
    def verify(self, signature):
        """
        Checks if the generated message authentication code matches the
        signature.
        """

# DeprecatedIn07
CMACContext = MACContext
