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
"""Contains wrapping key primitives."""
import logging
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from ...exceptions import IncorrectMasterKeyError, InvalidDataKeyError
from ...identifiers import EncryptionKeyType, EncryptionType
from ..formatting.encryption_context import serialize_encryption_context
from ..structures import EncryptedData
from .data_keys import derive_data_encryption_key
from .encryption import decrypt, encrypt

_LOGGER = logging.getLogger(__name__)


class WrappingKey(object):
    """Creates a wrapping encryption key object to encrypt and decrypt data keys.

    For use inside :class:`aws_encryption_sdk.key_providers.raw.RawMasterKeyProvider` objects.

    :param wrapping_algorithm: Wrapping Algorithm with which to wrap plaintext_data_key
    :type wrapping_algorithm: aws_encryption_sdk.identifiers.WrappingAlgorithm
    :param bytes wrapping_key: Encryption key with which to wrap plaintext_data_key
    :param wrapping_key_type: Type of encryption key with which to wrap plaintext_data_key
    :type wrapping_key_type: aws_encryption_sdk.identifiers.EncryptionKeyType
    :param bytes password: Password to decrypt wrapping_key (optional, currently only relevant for RSA)
    """

    def __init__(self, wrapping_algorithm, wrapping_key, wrapping_key_type, password=None):
        """Prepares initial values."""
        self.wrapping_algorithm = wrapping_algorithm
        self.wrapping_key_type = wrapping_key_type
        if wrapping_key_type is EncryptionKeyType.PRIVATE:
            self._wrapping_key = serialization.load_pem_private_key(
                data=wrapping_key, password=password, backend=default_backend()
            )
        elif wrapping_key_type is EncryptionKeyType.PUBLIC:
            self._wrapping_key = serialization.load_pem_public_key(data=wrapping_key, backend=default_backend())
        elif wrapping_key_type is EncryptionKeyType.SYMMETRIC:
            self._wrapping_key = wrapping_key
            self._derived_wrapping_key = derive_data_encryption_key(
                source_key=self._wrapping_key, algorithm=self.wrapping_algorithm.algorithm, message_id=None
            )
        else:
            raise InvalidDataKeyError("Invalid wrapping_key_type: {}".format(wrapping_key_type))

    def encrypt(self, plaintext_data_key, encryption_context):
        """Encrypts a data key using a direct wrapping key.

        :param bytes plaintext_data_key: Data key to encrypt
        :param dict encryption_context: Encryption context to use in encryption
        :returns: Deserialized object containing encrypted key
        :rtype: aws_encryption_sdk.internal.structures.EncryptedData
        """
        if self.wrapping_algorithm.encryption_type is EncryptionType.ASYMMETRIC:
            if self.wrapping_key_type is EncryptionKeyType.PRIVATE:
                encrypted_key = self._wrapping_key.public_key().encrypt(
                    plaintext=plaintext_data_key, padding=self.wrapping_algorithm.padding
                )
            else:
                encrypted_key = self._wrapping_key.encrypt(
                    plaintext=plaintext_data_key, padding=self.wrapping_algorithm.padding
                )
            return EncryptedData(iv=None, ciphertext=encrypted_key, tag=None)
        serialized_encryption_context = serialize_encryption_context(encryption_context=encryption_context)
        iv = os.urandom(self.wrapping_algorithm.algorithm.iv_len)
        return encrypt(
            algorithm=self.wrapping_algorithm.algorithm,
            key=self._derived_wrapping_key,
            plaintext=plaintext_data_key,
            associated_data=serialized_encryption_context,
            iv=iv,
        )

    def decrypt(self, encrypted_wrapped_data_key, encryption_context):
        """Decrypts a wrapped, encrypted, data key.

        :param encrypted_wrapped_data_key: Encrypted, wrapped, data key
        :type encrypted_wrapped_data_key: aws_encryption_sdk.internal.structures.EncryptedData
        :param dict encryption_context: Encryption context to use in decryption
        :returns: Plaintext of data key
        :rtype: bytes
        """
        if self.wrapping_key_type is EncryptionKeyType.PUBLIC:
            raise IncorrectMasterKeyError("Public key cannot decrypt")
        if self.wrapping_key_type is EncryptionKeyType.PRIVATE:
            return self._wrapping_key.decrypt(
                ciphertext=encrypted_wrapped_data_key.ciphertext, padding=self.wrapping_algorithm.padding
            )
        serialized_encryption_context = serialize_encryption_context(encryption_context=encryption_context)
        return decrypt(
            algorithm=self.wrapping_algorithm.algorithm,
            key=self._derived_wrapping_key,
            encrypted_data=encrypted_wrapped_data_key,
            associated_data=serialized_encryption_context,
        )
