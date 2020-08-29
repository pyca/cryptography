# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
"""Contains encryption primitives and helper functions."""
import logging

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher

from ..structures import EncryptedData

_LOGGER = logging.getLogger(__name__)


class Encryptor(object):
    """Abstract encryption handler.

    :param algorithm: Algorithm used to encrypt this body
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param bytes key: Encryption key
    :param bytes associated_data: Associated Data to send to encryption subsystem
    :param bytes iv: IV to use when encrypting message
    """

    def __init__(self, algorithm, key, associated_data, iv):
        """Prepares initial values."""
        self.source_key = key

        # Construct an encryptor object with the given key and a provided IV.
        # This is intentionally generic to leave an option for non-Cipher encryptor types in the future.
        self.iv = iv
        self._encryptor = Cipher(
            algorithm.encryption_algorithm(key), algorithm.encryption_mode(self.iv), backend=default_backend()
        ).encryptor()

        # associated_data will be authenticated but not encrypted,
        # it must also be passed in on decryption.
        self._encryptor.authenticate_additional_data(associated_data)

    def update(self, plaintext):
        """Updates _encryptor with provided plaintext.

        :param bytes plaintext: Plaintext to encrypt
        :returns: Encrypted ciphertext
        :rtype: bytes
        """
        return self._encryptor.update(plaintext)

    def finalize(self):
        """Finalizes and closes _encryptor.

        :returns: Final encrypted ciphertext
        :rtype: bytes
        """
        return self._encryptor.finalize()

    @property
    def tag(self):
        """Returns the _encryptor tag from the encryption subsystem.

        :returns: Encryptor tag
        :rtype: bytes
        """
        return self._encryptor.tag


def encrypt(algorithm, key, plaintext, associated_data, iv):
    """Encrypts a frame body.

    :param algorithm: Algorithm used to encrypt this body
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param bytes key: Encryption key
    :param bytes plaintext: Body plaintext
    :param bytes associated_data: Body AAD Data
    :param bytes iv: IV to use when encrypting message
    :returns: Deserialized object containing encrypted body
    :rtype: aws_encryption_sdk.internal.structures.EncryptedData
    """
    encryptor = Encryptor(algorithm, key, associated_data, iv)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return EncryptedData(encryptor.iv, ciphertext, encryptor.tag)


class Decryptor(object):
    """Abstract decryption handler.

    :param algorithm: Algorithm used to encrypt this body
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param bytes key: Raw source key
    :param bytes associated_data: Associated Data to send to decryption subsystem
    :param bytes iv: IV value with which to initialize decryption subsystem
    :param bytes tag: Tag with which to validate ciphertext
    """

    def __init__(self, algorithm, key, associated_data, iv, tag):
        """Prepares initial values."""
        self.source_key = key

        # Construct a decryptor object with the given key and a provided IV.
        # This is intentionally generic to leave an option for non-Cipher decryptor types in the future.
        self._decryptor = Cipher(
            algorithm.encryption_algorithm(key), algorithm.encryption_mode(iv, tag), backend=default_backend()
        ).decryptor()

        # Put associated_data back in or the tag will fail to verify when the _decryptor is finalized.
        self._decryptor.authenticate_additional_data(associated_data)

    def update(self, ciphertext):
        """Updates _decryptor with provided ciphertext.

        :param bytes ciphertext: Ciphertext to decrypt
        :returns: Decrypted plaintext
        :rtype: bytes
        """
        return self._decryptor.update(ciphertext)

    def finalize(self):
        """Finalizes and closes _decryptor.

        :returns: Final decrypted plaintext
        :rtype: bytes
        """
        return self._decryptor.finalize()


def decrypt(algorithm, key, encrypted_data, associated_data):
    """Decrypts a frame body.

    :param algorithm: Algorithm used to encrypt this body
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param bytes key: Plaintext data key
    :param encrypted_data: EncryptedData containing body data
    :type encrypted_data: :class:`aws_encryption_sdk.internal.structures.EncryptedData`,
        :class:`aws_encryption_sdk.internal.structures.FrameBody`,
        or :class:`aws_encryption_sdk.internal.structures.MessageNoFrameBody`
    :param bytes associated_data: AAD string generated for body
    :type associated_data: bytes
    :returns: Plaintext of body
    :rtype: bytes
    """
    decryptor = Decryptor(algorithm, key, associated_data, encrypted_data.iv, encrypted_data.tag)
    return decryptor.update(encrypted_data.ciphertext) + decryptor.finalize()
