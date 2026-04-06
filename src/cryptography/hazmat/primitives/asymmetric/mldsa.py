# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import abc

from cryptography.exceptions import UnsupportedAlgorithm, _Reasons
from cryptography.hazmat.bindings._rust import openssl as rust_openssl
from cryptography.hazmat.primitives import _serialization
from cryptography.utils import Buffer


class MlDsa65PublicKey(metaclass=abc.ABCMeta):
    @classmethod
    def from_public_bytes(cls, data: bytes) -> MlDsa65PublicKey:
        from cryptography.hazmat.backends.openssl.backend import backend

        if not backend.mldsa_supported():
            raise UnsupportedAlgorithm(
                "ML-DSA-65 is not supported by this backend.",
                _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
            )

        return rust_openssl.mldsa.from_mldsa65_public_bytes(data)

    @abc.abstractmethod
    def public_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PublicFormat,
    ) -> bytes:
        """
        The serialized bytes of the public key.
        """

    @abc.abstractmethod
    def public_bytes_raw(self) -> bytes:
        """
        The raw bytes of the public key.
        Equivalent to public_bytes(Raw, Raw).

        The public key is 1,952 bytes for MLDSA-65.
        """

    @abc.abstractmethod
    def verify(
        self,
        signature: Buffer,
        data: Buffer,
        context: Buffer | None = None,
    ) -> None:
        """
        Verify the signature.
        """

    @abc.abstractmethod
    def __eq__(self, other: object) -> bool:
        """
        Checks equality.
        """

    @abc.abstractmethod
    def __copy__(self) -> MlDsa65PublicKey:
        """
        Returns a copy.
        """

    @abc.abstractmethod
    def __deepcopy__(self, memo: dict) -> MlDsa65PublicKey:
        """
        Returns a deep copy.
        """


if hasattr(rust_openssl, "mldsa"):
    MlDsa65PublicKey.register(rust_openssl.mldsa.MlDsa65PublicKey)


class MlDsa65PrivateKey(metaclass=abc.ABCMeta):
    @classmethod
    def generate(cls) -> MlDsa65PrivateKey:
        from cryptography.hazmat.backends.openssl.backend import backend

        if not backend.mldsa_supported():
            raise UnsupportedAlgorithm(
                "ML-DSA-65 is not supported by this backend.",
                _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
            )

        return rust_openssl.mldsa.generate_mldsa65_key()

    @classmethod
    def from_seed_bytes(cls, data: Buffer) -> MlDsa65PrivateKey:
        from cryptography.hazmat.backends.openssl.backend import backend

        if not backend.mldsa_supported():
            raise UnsupportedAlgorithm(
                "ML-DSA-65 is not supported by this backend.",
                _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
            )

        return rust_openssl.mldsa.from_mldsa65_seed_bytes(data)

    @abc.abstractmethod
    def public_key(self) -> MlDsa65PublicKey:
        """
        The MlDsa65PublicKey derived from the private key.
        """

    @abc.abstractmethod
    def private_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PrivateFormat,
        encryption_algorithm: _serialization.KeySerializationEncryption,
    ) -> bytes:
        """
        The serialized bytes of the private key.

        This method only returns the serialization of the seed form of the
        private key, never the expanded one.
        """

    @abc.abstractmethod
    def private_bytes_raw(self) -> bytes:
        """
        The raw bytes of the private key.
        Equivalent to private_bytes(Raw, Raw, NoEncryption()).

        This method only returns the seed form of the private key (32 bytes).
        """

    @abc.abstractmethod
    def sign(self, data: Buffer, context: Buffer | None = None) -> bytes:
        """
        Signs the data.
        """

    @abc.abstractmethod
    def __copy__(self) -> MlDsa65PrivateKey:
        """
        Returns a copy.
        """

    @abc.abstractmethod
    def __deepcopy__(self, memo: dict) -> MlDsa65PrivateKey:
        """
        Returns a deep copy.
        """


if hasattr(rust_openssl, "mldsa"):
    MlDsa65PrivateKey.register(rust_openssl.mldsa.MlDsa65PrivateKey)
