# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import abc

from cryptography.exceptions import UnsupportedAlgorithm, _Reasons
from cryptography.hazmat.primitives import _serialization


class X448PublicKey(metaclass=abc.ABCMeta):
    @classmethod
    def from_public_bytes(cls, data: bytes) -> "X448PublicKey":
        from cryptography.hazmat.backends.openssl.backend import backend

        if not backend.x448_supported():
            raise UnsupportedAlgorithm(
                "X448 is not supported by this version of OpenSSL.",
                _Reasons.UNSUPPORTED_EXCHANGE_ALGORITHM,
            )

        return backend.x448_load_public_bytes(data)

    @abc.abstractmethod
    def public_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PublicFormat,
    ) -> bytes:
        """
        The serialized bytes of the public key.
        """

    def public_bytes_raw(self) -> bytes:
        """
        The raw bytes of the public key.
        Equivalent to public_bytes(Raw, Raw).
        """
        return self.public_bytes(
            _serialization.Encoding.Raw, _serialization.PublicFormat.Raw
        )


class X448PrivateKey(metaclass=abc.ABCMeta):
    @classmethod
    def generate(cls) -> "X448PrivateKey":
        from cryptography.hazmat.backends.openssl.backend import backend

        if not backend.x448_supported():
            raise UnsupportedAlgorithm(
                "X448 is not supported by this version of OpenSSL.",
                _Reasons.UNSUPPORTED_EXCHANGE_ALGORITHM,
            )
        return backend.x448_generate_key()

    @classmethod
    def from_private_bytes(cls, data: bytes) -> "X448PrivateKey":
        from cryptography.hazmat.backends.openssl.backend import backend

        if not backend.x448_supported():
            raise UnsupportedAlgorithm(
                "X448 is not supported by this version of OpenSSL.",
                _Reasons.UNSUPPORTED_EXCHANGE_ALGORITHM,
            )

        return backend.x448_load_private_bytes(data)

    @abc.abstractmethod
    def public_key(self) -> X448PublicKey:
        """
        Returns the public key associated with this private key
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

    def private_bytes_raw(self) -> bytes:
        """
        The raw bytes of the private key.
        Equivalent to private_bytes(Raw, Raw, NoEncryption()).
        """
        return self.private_bytes(
            _serialization.Encoding.Raw,
            _serialization.PrivateFormat.Raw,
            _serialization.NoEncryption(),
        )

    @abc.abstractmethod
    def exchange(self, peer_public_key: X448PublicKey) -> bytes:
        """
        Performs a key exchange operation using the provided peer's public key.
        """
