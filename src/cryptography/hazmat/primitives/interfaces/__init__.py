# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import abc

import six

from cryptography.hazmat.primitives.interfaces.asymmetric.dsa import (
    DSAParameters, DSAParametersWithNumbers, DSAPrivateKey,
    DSAPrivateKeyWithNumbers, DSAPublicKey, DSAPublicKeyWithNumbers
)
from cryptography.hazmat.primitives.interfaces.asymmetric.ec import (
    EllipticCurve, EllipticCurvePrivateKey, EllipticCurvePrivateKeyWithNumbers,
    EllipticCurvePublicKey, EllipticCurvePublicKeyWithNumbers,
    EllipticCurveSignatureAlgorithm
)
from cryptography.hazmat.primitives.interfaces.asymmetric.rsa import (
    RSAPrivateKey, RSAPrivateKeyWithNumbers, RSAPublicKey,
    RSAPublicKeyWithNumbers
)
from cryptography.hazmat.primitives.interfaces.ciphers import (
    BlockCipherAlgorithm, CipherAlgorithm, Mode,
    ModeWithAuthenticationTag, ModeWithInitializationVector, ModeWithNonce
)

__all__ = [
    "BlockCipherAlgorithm",
    "CipherAlgorithm",
    "DSAParameters",
    "DSAParametersWithNumbers",
    "DSAPrivateKey",
    "DSAPrivateKeyWithNumbers",
    "DSAPublicKey",
    "DSAPublicKeyWithNumbers",
    "EllipticCurve",
    "EllipticCurvePrivateKey",
    "EllipticCurvePrivateKeyWithNumbers",
    "EllipticCurvePublicKey",
    "EllipticCurvePublicKeyWithNumbers",
    "EllipticCurveSignatureAlgorithm",
    "Mode",
    "ModeWithAuthenticationTag",
    "ModeWithInitializationVector",
    "ModeWithNonce",
    "RSAPrivateKey",
    "RSAPrivateKeyWithNumbers",
    "RSAPublicKey",
    "RSAPublicKeyWithNumbers"
]


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


@six.add_metaclass(abc.ABCMeta)
class HashAlgorithm(object):
    @abc.abstractproperty
    def name(self):
        """
        A string naming this algorithm (e.g. "sha256", "md5").
        """

    @abc.abstractproperty
    def digest_size(self):
        """
        The size of the resulting digest in bytes.
        """

    @abc.abstractproperty
    def block_size(self):
        """
        The internal block size of the hash algorithm in bytes.
        """


@six.add_metaclass(abc.ABCMeta)
class HashContext(object):
    @abc.abstractproperty
    def algorithm(self):
        """
        A HashAlgorithm that will be used by this context.
        """

    @abc.abstractmethod
    def update(self, data):
        """
        Processes the provided bytes through the hash.
        """

    @abc.abstractmethod
    def finalize(self):
        """
        Finalizes the hash context and returns the hash digest as bytes.
        """

    @abc.abstractmethod
    def copy(self):
        """
        Return a HashContext that is a copy of the current context.
        """


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


@six.add_metaclass(abc.ABCMeta)
class X509Certificate(object):
    @abc.abstractmethod
    def fingerprint(self, algorithm):
        """
        Returns bytes using digest passed.
        """

    @abc.abstractproperty
    def serial(self):
        """
        Returns certificate serial number
        """

    @abc.abstractproperty
    def version(self):
        """
        Returns the certificate version
        """

    @abc.abstractmethod
    def public_key(self):
        """
        Returns the public key
        """

    @abc.abstractproperty
    def not_valid_before(self):
        """
        Not before time (represented as UTC datetime)
        """

    @abc.abstractproperty
    def not_valid_after(self):
        """
        Not after time (represented as UTC datetime)
        """
