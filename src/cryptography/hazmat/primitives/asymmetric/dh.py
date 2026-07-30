# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import abc

from cryptography import utils
from cryptography.hazmat.bindings._rust import openssl as rust_openssl
from cryptography.hazmat.primitives import _serialization

_FFDH_DEPRECATION_MSG = (
    "Diffie-Hellman over finite fields (FFDH) is deprecated and support "
    "will be removed in a future release. Use a more modern key exchange "
    "algorithm."
)

generate_parameters = rust_openssl.dh.generate_parameters


DHPrivateNumbers = rust_openssl.dh.DHPrivateNumbers
DHPublicNumbers = rust_openssl.dh.DHPublicNumbers
DHParameterNumbers = rust_openssl.dh.DHParameterNumbers


class DHParameters(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def generate_private_key(self) -> DHPrivateKey:
        """
        Generates and returns a DHPrivateKey.
        """

    @abc.abstractmethod
    def parameter_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.ParameterFormat,
    ) -> bytes:
        """
        Returns the parameters serialized as bytes.
        """

    @abc.abstractmethod
    def parameter_numbers(self) -> DHParameterNumbers:
        """
        Returns a DHParameterNumbers.
        """


DHParametersWithSerialization = DHParameters
DHParameters.register(rust_openssl.dh.DHParameters)


class DHPublicKey(metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def key_size(self) -> int:
        """
        The bit length of the prime modulus.
        """

    @abc.abstractmethod
    def parameters(self) -> DHParameters:
        """
        The DHParameters object associated with this public key.
        """

    @abc.abstractmethod
    def public_numbers(self) -> DHPublicNumbers:
        """
        Returns a DHPublicNumbers.
        """

    @abc.abstractmethod
    def public_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PublicFormat,
    ) -> bytes:
        """
        Returns the key serialized as bytes.
        """

    @abc.abstractmethod
    def __eq__(self, other: object) -> bool:
        """
        Checks equality.
        """

    @abc.abstractmethod
    def __copy__(self) -> DHPublicKey:
        """
        Returns a copy.
        """

    @abc.abstractmethod
    def __deepcopy__(self, memo: dict) -> DHPublicKey:
        """
        Returns a deep copy.
        """


DHPublicKeyWithSerialization = DHPublicKey
DHPublicKey.register(rust_openssl.dh.DHPublicKey)


class DHPrivateKey(metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def key_size(self) -> int:
        """
        The bit length of the prime modulus.
        """

    @abc.abstractmethod
    def public_key(self) -> DHPublicKey:
        """
        The DHPublicKey associated with this private key.
        """

    @abc.abstractmethod
    def parameters(self) -> DHParameters:
        """
        The DHParameters object associated with this private key.
        """

    @abc.abstractmethod
    def exchange(self, peer_public_key: DHPublicKey) -> bytes:
        """
        Given peer's DHPublicKey, carry out the key exchange and
        return shared key as bytes.
        """

    @abc.abstractmethod
    def private_numbers(self) -> DHPrivateNumbers:
        """
        Returns a DHPrivateNumbers.
        """

    @abc.abstractmethod
    def private_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PrivateFormat,
        encryption_algorithm: _serialization.KeySerializationEncryption,
    ) -> bytes:
        """
        Returns the key serialized as bytes.
        """

    @abc.abstractmethod
    def __copy__(self) -> DHPrivateKey:
        """
        Returns a copy.
        """

    @abc.abstractmethod
    def __deepcopy__(self, memo: dict) -> DHPrivateKey:
        """
        Returns a deep copy.
        """


DHPrivateKeyWithSerialization = DHPrivateKey
DHPrivateKey.register(rust_openssl.dh.DHPrivateKey)

# Aliases that do not emit the deprecation warning on attribute access, for
# internal use (e.g. the unions in
# cryptography.hazmat.primitives.asymmetric.types, which are evaluated at
# import time).
_DHPublicKey = DHPublicKey
_DHPrivateKey = DHPrivateKey

utils.deprecated(
    generate_parameters,
    __name__,
    _FFDH_DEPRECATION_MSG,
    utils.DeprecatedIn50,
    name="generate_parameters",
)

utils.deprecated(
    DHPrivateNumbers,
    __name__,
    _FFDH_DEPRECATION_MSG,
    utils.DeprecatedIn50,
    name="DHPrivateNumbers",
)

utils.deprecated(
    DHPublicNumbers,
    __name__,
    _FFDH_DEPRECATION_MSG,
    utils.DeprecatedIn50,
    name="DHPublicNumbers",
)

utils.deprecated(
    DHParameterNumbers,
    __name__,
    _FFDH_DEPRECATION_MSG,
    utils.DeprecatedIn50,
    name="DHParameterNumbers",
)

utils.deprecated(
    DHParameters,
    __name__,
    _FFDH_DEPRECATION_MSG,
    utils.DeprecatedIn50,
    name="DHParameters",
)

utils.deprecated(
    DHParameters,
    __name__,
    _FFDH_DEPRECATION_MSG,
    utils.DeprecatedIn50,
    name="DHParametersWithSerialization",
)

utils.deprecated(
    DHPublicKey,
    __name__,
    _FFDH_DEPRECATION_MSG,
    utils.DeprecatedIn50,
    name="DHPublicKey",
)

utils.deprecated(
    DHPublicKey,
    __name__,
    _FFDH_DEPRECATION_MSG,
    utils.DeprecatedIn50,
    name="DHPublicKeyWithSerialization",
)

utils.deprecated(
    DHPrivateKey,
    __name__,
    _FFDH_DEPRECATION_MSG,
    utils.DeprecatedIn50,
    name="DHPrivateKey",
)

utils.deprecated(
    DHPrivateKey,
    __name__,
    _FFDH_DEPRECATION_MSG,
    utils.DeprecatedIn50,
    name="DHPrivateKeyWithSerialization",
)
