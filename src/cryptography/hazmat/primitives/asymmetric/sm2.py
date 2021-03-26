# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import abc

from cryptography.exceptions import UnsupportedAlgorithm, _Reasons
from cryptography.hazmat.primitives import _serialization
from cryptography.hazmat.primitives.asymmetric.ec import SM2P256V1


SM2_DEFAULT_USER_ID = b'1234567812345678'
_SM2_MAX_KEY_SIZE = 72
_SM2_MAX_SIG_SIZE = 72


class SM2PublicKey(metaclass=abc.ABCMeta):
    @classmethod
    def from_public_bytes(cls, data: bytes) -> "SM2PublicKey":
        from cryptography.hazmat.backends.openssl.backend import backend

        if not backend.sm2_supported():
            raise UnsupportedAlgorithm(
                "SM2 is not supported by this version of OpenSSL.",
                _Reasons.UNSUPPORTED_EXCHANGE_ALGORITHM,
            )

        return backend.sm2_load_public_bytes(SM2P256V1(), data)

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
    def verify(self, signature: bytes, data: bytes, user_id: bytes) -> None:
        """
        Verify the signature.
        """


class SM2PrivateKey(metaclass=abc.ABCMeta):
    @classmethod
    def generate(cls) -> "SM2PrivateKey":
        from cryptography.hazmat.backends.openssl.backend import backend

        if not backend.sm2_supported():
            raise UnsupportedAlgorithm(
                "SM2 is not supported by this version of OpenSSL.",
                _Reasons.UNSUPPORTED_EXCHANGE_ALGORITHM,
            )

        return backend.sm2_generate_key(SM2P256V1())

    @classmethod
    def from_private_bytes(cls, data: bytes) -> "SM2PrivateKey":
        from cryptography.hazmat.backends.openssl.backend import backend

        if not backend.sm2_supported():
            raise UnsupportedAlgorithm(
                "SM2 is not supported by this version of OpenSSL.",
                _Reasons.UNSUPPORTED_EXCHANGE_ALGORITHM,
            )

        return backend.sm2_load_private_bytes(data)

    @abc.abstractmethod
    def public_key(self) -> SM2PublicKey:
        """
        The serialized bytes of the public key.
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
    def sign(self, data: bytes, user_id: bytes) -> bytes:
        """
        Signs the data.
        """
