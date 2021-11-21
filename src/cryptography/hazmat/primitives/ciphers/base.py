# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import abc
import typing

from cryptography.hazmat.primitives._cipheralgorithm import CipherAlgorithm
from cryptography.hazmat.primitives.ciphers import modes


class CipherContext(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def update(self, data: bytes) -> bytes:
        """
        Processes the provided bytes through the cipher and returns the results
        as bytes.
        """

    @abc.abstractmethod
    def update_into(self, data: bytes, buf) -> int:
        """
        Processes the provided bytes and writes the resulting data into the
        provided buffer. Returns the number of bytes written.
        """

    @abc.abstractmethod
    def finalize(self) -> bytes:
        """
        Returns the results of processing the final block as bytes.
        """

    @abc.abstractmethod
    def authenticate_additional_data(self, data: bytes) -> None:
        """
        Authenticates the provided bytes. This method is only relevant for
        AEAD cipher/mode combinations.
        """

    @abc.abstractmethod
    def finalize_with_tag(self, tag: bytes) -> bytes:
        """
        Returns the results of processing the final block as bytes and allows
        delayed passing of the authentication tag. This method is only
        relevant for AEAD cipher/mode combinations.
        """

    @abc.abstractproperty
    def tag(self) -> bytes:
        """
        Returns tag bytes. This is only available after encryption is
        finalized. This property is only relevant for AEAD cipher/mode
        combinations.
        """


# Prior to 36.0 cryptography returned different interfaces based on the
# cipher/mode combination returned. This resulted in a significant amount
# of (slow) indirection and made typing very difficult. All methods have
# now been added to the CipherContext itself and the previous context names
# are just aliases for compatibility.
AEADCipherContext = CipherContext
AEADDecryptionContext = CipherContext
AEADEncryptionContext = CipherContext


class Cipher(object):
    def __init__(
        self,
        algorithm: CipherAlgorithm,
        mode: typing.Optional[modes.Mode],
        backend: typing.Any = None,
    ):

        if not isinstance(algorithm, CipherAlgorithm):
            raise TypeError("Expected interface of CipherAlgorithm.")

        if mode is not None:
            mode.validate_for_algorithm(algorithm)

        self.algorithm = algorithm
        self.mode = mode

    def encryptor(self) -> CipherContext:
        if isinstance(self.mode, modes.ModeWithAuthenticationTag):
            if self.mode.tag is not None:
                raise ValueError(
                    "Authentication tag must be None when encrypting."
                )
        from cryptography.hazmat.backends.openssl.backend import backend

        return backend.create_symmetric_encryption_ctx(
            self.algorithm, self.mode
        )

    def decryptor(self) -> CipherContext:
        from cryptography.hazmat.backends.openssl.backend import backend

        return backend.create_symmetric_decryption_ctx(
            self.algorithm, self.mode
        )
