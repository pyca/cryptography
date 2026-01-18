# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import abc

from cryptography.exceptions import UnsupportedAlgorithm, _Reasons
from cryptography.hazmat.bindings._rust import openssl as rust_openssl
from cryptography.hazmat.primitives import _serialization
from cryptography.utils import Buffer


class MlDsa44PublicKey(metaclass=abc.ABCMeta):
    @classmethod
    def from_public_bytes(cls, data: bytes) -> MlDsa44PublicKey:
        from cryptography.hazmat.backends.openssl.backend import backend

        if not backend.mldsa44_supported():
            raise UnsupportedAlgorithm(
                "ML-DSA-44 is not supported by this version of OpenSSL.",
                _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
            )
        mldsa44 = getattr(rust_openssl, "mldsa44")
        return mldsa44.from_public_bytes(data)

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
        """

    @abc.abstractmethod
    def verify(self, signature: Buffer, data: Buffer) -> None:
        """
        Verify the signature.
        """

    @abc.abstractmethod
    def verify_with_context(
        self, signature: Buffer, data: Buffer, context: Buffer
    ) -> None:
        """
        Verify the signature with context.
        """

    @abc.abstractmethod
    def __eq__(self, other: object) -> bool:
        """
        Checks equality.
        """

    @abc.abstractmethod
    def __copy__(self) -> MlDsa44PublicKey:
        """
        Returns a copy.
        """

    @abc.abstractmethod
    def __deepcopy__(self, memo: dict) -> MlDsa44PublicKey:
        """
        Returns a deep copy.
        """


if hasattr(rust_openssl, "mldsa44"):
    MlDsa44PublicKey.register(rust_openssl.mldsa44.MlDsa44PublicKey)


class MlDsa44PrivateKey(metaclass=abc.ABCMeta):
    @classmethod
    def generate(cls) -> MlDsa44PrivateKey:
        from cryptography.hazmat.backends.openssl.backend import backend

        if not backend.mldsa44_supported():
            raise UnsupportedAlgorithm(
                "ML-DSA-44 is not supported by this version of OpenSSL.",
                _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
            )

        mldsa44 = getattr(rust_openssl, "mldsa44")
        return mldsa44.generate_key()

    @classmethod
    def from_seed_bytes(cls, data: Buffer) -> MlDsa44PrivateKey:
        from cryptography.hazmat.backends.openssl.backend import backend

        if not backend.mldsa44_supported():
            raise UnsupportedAlgorithm(
                "ML-DSA-44 is not supported by this version of OpenSSL.",
                _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
            )

        mldsa44 = getattr(rust_openssl, "mldsa44")
        return mldsa44.from_seed_bytes(data)

    @abc.abstractmethod
    def public_key(self) -> MlDsa44PublicKey:
        """
        The MlDsa44PublicKey derived from the private key.
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
        """

    @abc.abstractmethod
    def seed_bytes(self) -> bytes:
        """
        The 32-byte seed used to generate this private key.
        """

    @abc.abstractmethod
    def sign(self, data: Buffer) -> bytes:
        """
        Signs the data.
        """

    @abc.abstractmethod
    def sign_with_context(self, data: Buffer, context: Buffer) -> bytes:
        """
        Signs the data with context.
        """

    @abc.abstractmethod
    def __copy__(self) -> MlDsa44PrivateKey:
        """
        Returns a copy.
        """

    @abc.abstractmethod
    def __deepcopy__(self, memo: dict) -> MlDsa44PrivateKey:
        """
        Returns a deep copy.
        """


if hasattr(rust_openssl, "mldsa44"):
    MlDsa44PrivateKey.register(rust_openssl.mldsa44.MlDsa44PrivateKey)
