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
"""Resources required for Raw Master Keys."""
import abc
import logging
import os

import attr
import six

import aws_encryption_sdk.internal.formatting.deserialize
import aws_encryption_sdk.internal.formatting.serialize
from aws_encryption_sdk.identifiers import EncryptionType
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.key_providers.base import MasterKey, MasterKeyConfig, MasterKeyProvider, MasterKeyProviderConfig
from aws_encryption_sdk.structures import DataKey, RawDataKey

_LOGGER = logging.getLogger(__name__)


@attr.s(hash=True)
class RawMasterKeyConfig(MasterKeyConfig):
    """Configuration object for RawMasterKey objects.

    :param bytes key_id: Key ID for Master Key
    :param str provider_id: String defining provider ID
    :param wrapping_key: Encryption key with which to wrap plaintext_data_key
    :type wrapping_key: aws_encryption_sdk.internal.crypto.WrappingKey
    """

    provider_id = attr.ib(
        hash=True,
        validator=attr.validators.instance_of((six.string_types, bytes)),
        converter=aws_encryption_sdk.internal.str_ops.to_str,
    )
    wrapping_key = attr.ib(hash=True, validator=attr.validators.instance_of(WrappingKey))


class RawMasterKey(MasterKey):
    """Raw Master Key.

    :param config: Configuration object (config or individual parameters required)
    :type config: aws_encryption_sdk.key_providers.raw.RawMasterKeyConfig
    :param bytes key_id: Key ID for Master Key
    :param str provider_id: String defining provider ID
    :param wrapping_key: Encryption key with which to wrap plaintext_data_key
    :type wrapping_key: aws_encryption_sdk.internal.crypto.WrappingKey
    """

    provider_id = None
    _config_class = RawMasterKeyConfig

    def __new__(cls, **kwargs):
        """Inject registration of the new Raw Master Key Provider into the creation of each instance.

        .. note::
            Overloaded here to allow definition of _key_info_prefix on instantiation.
        """
        instance = super(RawMasterKey, cls).__new__(cls, **kwargs)
        instance._key_info_prefix = aws_encryption_sdk.internal.formatting.serialize.serialize_raw_master_key_prefix(  # noqa pylint: disable=protected-access
            raw_master_key=instance
        )
        return instance

    def owns_data_key(self, data_key):
        """Determines if data_key object is owned by this RawMasterKey.

        :param data_key: Data key to evaluate
        :type data_key: :class:`aws_encryption_sdk.structures.DataKey`,
            :class:`aws_encryption_sdk.structures.RawDataKey`,
            or :class:`aws_encryption_sdk.structures.EncryptedDataKey`
        :returns: Boolean statement of ownership
        :rtype: bool
        """
        expected_key_info_len = -1
        if (
            self.config.wrapping_key.wrapping_algorithm.encryption_type is EncryptionType.ASYMMETRIC
            and data_key.key_provider == self.key_provider
        ):
            return True
        elif self.config.wrapping_key.wrapping_algorithm.encryption_type is EncryptionType.SYMMETRIC:
            expected_key_info_len = (
                len(self._key_info_prefix) + self.config.wrapping_key.wrapping_algorithm.algorithm.iv_len
            )
            if (
                data_key.key_provider.provider_id == self.provider_id
                and len(data_key.key_provider.key_info) == expected_key_info_len
                and data_key.key_provider.key_info.startswith(self._key_info_prefix)
            ):
                return True
        _LOGGER.debug(
            (
                "RawMasterKey does not own data_key: %s\n"
                "Expected provider_id: %s\n"
                "Expected key_info len: %s\n"
                "Expected key_info prefix: %s"
            ),
            data_key,
            self.provider_id,
            expected_key_info_len,
            self._key_info_prefix,
        )
        return False

    def _generate_data_key(self, algorithm, encryption_context):
        """Generates data key and returns :class:`aws_encryption_sdk.structures.DataKey`.

        :param algorithm: Algorithm on which to base data key
        :type algorithm: aws_encryption_sdk.identifiers.Algorithm
        :param dict encryption_context: Encryption context to use in encryption
        :returns: Generated data key
        :rtype: aws_encryption_sdk.structures.DataKey
        """
        plaintext_data_key = os.urandom(algorithm.kdf_input_len)
        encrypted_data_key = self._encrypt_data_key(
            data_key=RawDataKey(key_provider=self.key_provider, data_key=plaintext_data_key),
            algorithm=algorithm,
            encryption_context=encryption_context,
        )
        return DataKey(
            key_provider=encrypted_data_key.key_provider,
            data_key=plaintext_data_key,
            encrypted_data_key=encrypted_data_key.encrypted_data_key,
        )

    def _encrypt_data_key(self, data_key, algorithm, encryption_context):
        """Performs the provider-specific key encryption actions.

        :param data_key: Unencrypted data key
        :type data_key: :class:`aws_encryption_sdk.structures.RawDataKey`
            or :class:`aws_encryption_sdk.structures.DataKey`
        :param algorithm: Algorithm object which directs how this Master Key will encrypt the data key
        :type algorithm: aws_encryption_sdk.identifiers.Algorithm
        :param dict encryption_context: Encryption context to use in encryption
        :returns: Decrypted data key
        :rtype: aws_encryption_sdk.structures.EncryptedDataKey
        :raises EncryptKeyError: if Master Key is unable to encrypt data key
        """
        # Raw key string to EncryptedData
        encrypted_wrapped_key = self.config.wrapping_key.encrypt(
            plaintext_data_key=data_key.data_key, encryption_context=encryption_context
        )
        # EncryptedData to EncryptedDataKey
        return aws_encryption_sdk.internal.formatting.serialize.serialize_wrapped_key(
            key_provider=self.key_provider,
            wrapping_algorithm=self.config.wrapping_key.wrapping_algorithm,
            wrapping_key_id=self.key_id,
            encrypted_wrapped_key=encrypted_wrapped_key,
        )

    def _decrypt_data_key(self, encrypted_data_key, algorithm, encryption_context):
        """Decrypts an encrypted data key and returns the plaintext.

        :param data_key: Encrypted data key
        :type data_key: aws_encryption_sdk.structures.EncryptedDataKey
        :param algorithm: Algorithm object which directs how this Master Key will encrypt the data key
        :type algorithm: aws_encryption_sdk.identifiers.Algorithm
        :param dict encryption_context: Encryption context to use in decryption
        :returns: Data key containing decrypted data key
        :rtype: aws_encryption_sdk.structures.DataKey
        :raises DecryptKeyError: if Master Key is unable to decrypt data key
        """
        # Wrapped EncryptedDataKey to deserialized EncryptedData
        encrypted_wrapped_key = aws_encryption_sdk.internal.formatting.deserialize.deserialize_wrapped_key(
            wrapping_algorithm=self.config.wrapping_key.wrapping_algorithm,
            wrapping_key_id=self.key_id,
            wrapped_encrypted_key=encrypted_data_key,
        )
        # EncryptedData to raw key string
        plaintext_data_key = self.config.wrapping_key.decrypt(
            encrypted_wrapped_data_key=encrypted_wrapped_key, encryption_context=encryption_context
        )
        # Raw key string to DataKey
        return DataKey(
            key_provider=encrypted_data_key.key_provider,
            data_key=plaintext_data_key,
            encrypted_data_key=encrypted_data_key.encrypted_data_key,
        )


@six.add_metaclass(abc.ABCMeta)
class RawMasterKeyProvider(MasterKeyProvider):
    """Raw Master Key Provider.

    :param config: Configuration object (optional)
    :type config: aws_encryption_sdk.key_providers.base.MasterKeyProviderConfig
    """

    #: Used to override the class MasterKey class returned by a RawMasterKeyProvider.
    _master_key_class = RawMasterKey
    _config_class = MasterKeyProviderConfig

    #: Determines whether a MasterKeyProvider attempts to add a MasterKey on decrypt_data_key call.
    vend_masterkey_on_decrypt = False

    @abc.abstractmethod
    def _get_raw_key(self, key_id):
        """Retrieves a raw key from some source.

        :param bytes key_id: Key ID to use
        :returns: Wrapping Key
        :rtype: aws_encryption_sdk.internal.crypto.WrappingKey
        """

    def _new_master_key(self, key_id):
        """Retrieves a wrapping key and builds a RawMasterKey using that wrapping key.

        :param bytes key_id: Key ID to use
        :returns: RawMasterKey based on retrieved wrapping key
        :rtype: aws_encryption_sdk.key_providers.raw.RawMasterKey
        """
        _LOGGER.debug("Retrieving wrapping key with id: %s", key_id)
        wrapping_key = self._get_raw_key(key_id)
        return self._master_key_class(
            config=RawMasterKeyConfig(key_id=key_id, provider_id=self.provider_id, wrapping_key=wrapping_key)
        )
