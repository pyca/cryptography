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
"""Base class interface for Master Key Providers."""
import abc
import logging

import attr
import six

import aws_encryption_sdk.internal.utils
from aws_encryption_sdk.exceptions import (
    ConfigMismatchError,
    DecryptKeyError,
    IncorrectMasterKeyError,
    InvalidKeyIdError,
    MasterKeyProviderError,
)
from aws_encryption_sdk.internal.str_ops import to_bytes
from aws_encryption_sdk.structures import MasterKeyInfo

_LOGGER = logging.getLogger(__name__)


@attr.s(hash=True)
class MasterKeyProviderConfig(object):
    """Provides a common ancestor for MasterKeyProvider configuration objects
    and a stand-in point if common params are needed later.
    """


@six.add_metaclass(abc.ABCMeta)
class MasterKeyProvider(object):
    """Parent interface for Master Key Provider classes.

    :param config: Configuration object
    :type config: aws_encryption_sdk.key_providers.base.MasterKeyProviderConfig
    """

    #: Determines whether a MasterKeyProvider attempts to add a MasterKey on decrypt_data_key call.
    vend_masterkey_on_decrypt = True

    @abc.abstractproperty
    def provider_id(self):
        """String defining provider ID.

        .. note::
            Must be implemented by specific MasterKeyProvider implementations.
        """

    @abc.abstractproperty
    def _config_class(self):
        """Configuration class to use when setting up this class.

        .. note::
            Must be implemented by specific MasterKeyProvider implementations.
        """

    def __new__(cls, **kwargs):
        """Set key index and member set for all new instances here
        to avoid requiring child classes to call super init.
        """
        instance = super(MasterKeyProvider, cls).__new__(cls)
        config = kwargs.pop("config", None)
        if not isinstance(config, instance._config_class):  # pylint: disable=protected-access
            config = instance._config_class(**kwargs)  # pylint: disable=protected-access
        instance.config = config
        #: Index matching key IDs to existing MasterKey objects.
        instance._encrypt_key_index = {}  # pylint: disable=protected-access
        #: Set of all member entities of this Provider (both Master Keys and other Providers).
        instance._members = []  # pylint: disable=protected-access
        #: Index of matching key IDs to existing MasterKey objects ONLY for decrypt.
        instance._decrypt_key_index = {}  # pylint: disable=protected-access
        return instance

    def __repr__(self):
        """Builds the proper repr string."""
        return "{name}({kwargs})".format(
            name=self.__class__.__name__,
            kwargs=", ".join(
                "{key}={value}".format(key=key, value=value)
                for key, value in sorted(attr.asdict(self.config, recurse=True).items(), key=lambda x: x[0])
            ),
        )

    def master_keys_for_encryption(self, encryption_context, plaintext_rostream, plaintext_length=None):
        """Returns a set containing all Master Keys added to this Provider, or any member Providers,
        which should be used to encrypt data keys for the specified data.

        .. note::
            This does not necessarily include all Master Keys accessible from this Provider.

        .. note::
            The Primary Master Key is the first Master Key added to this Master Key Provider
            and is the Master Key which will be used to generate the data key.

        .. warning::
            If plaintext_rostream seek position is modified, it must be returned before leaving method.

        :param dict encryption_context: Encryption context passed to client
        :param plaintext_rostream: Source plaintext read-only stream
        :type plaintext_rostream: aws_encryption_sdk.internal.utils.streams.ROStream
        :param int plaintext_length: Length of source plaintext (optional)
        :returns: Tuple containing Primary Master Key and List of all Master Keys added to
            this Provider and any member Providers
        :rtype: tuple containing :class:`aws_encryption_sdk.key_providers.base.MasterKey`
            and list of :class:`aws_encryption_sdk.key_providers.base.MasterKey`
        """
        primary = None
        master_keys = []
        for member_provider in self._members:
            _primary, _master_keys = member_provider.master_keys_for_encryption(
                encryption_context, plaintext_rostream, plaintext_length
            )
            if primary is None:
                primary = _primary
            master_keys.extend(_master_keys)
        if not master_keys:
            raise MasterKeyProviderError("No Master Keys available from Master Key Provider")
        return primary, master_keys

    @abc.abstractmethod
    def _new_master_key(self, key_id):
        """Returns a Master Key based on the specified key_id.

        .. note::
            Must be implemented by specific MasterKeyProvider implementations.

        :param bytes key_id: Key ID with which to create MasterKey
        :returns: Master Key based on key_id
        :rtype: aws_encryption_sdk.key_providers.base.MasterKey
        :raises MasterKeyProviderError: if invalid key id format
        """

    def add_master_key(self, key_id):
        """Adds a single Master Key to this provider.

        :param bytes key_id: Key ID with which to create MasterKey
        """
        key_id = to_bytes(key_id)
        if key_id not in self._encrypt_key_index:
            master_key = self._new_master_key(key_id)
            self._members.append(master_key)
            self._encrypt_key_index[key_id] = master_key

    def add_master_keys_from_list(self, key_ids):
        """Adds multiple Master Keys to this provider.

        :param list key_ids: List of Master Key IDs
        """
        for key_id in key_ids:
            self.add_master_key(key_id)

    def add_master_key_provider(self, key_provider):
        """Adds a single Master Key Provider to this provider.

        :param key_provider: Master Key Provider to add to this provider
        :type key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
        """
        self._members.append(key_provider)

    def add_master_key_providers_from_list(self, key_providers):
        """Adds multiple Master Key Providers to this provider.

        :param key_provider: List of Master Key Providers to add to this provider
        :type key_provider: list of :class:`aws_encryption_sdk.key_providers.base.MasterKeyProvider`
        """
        for key_provider in key_providers:
            self.add_master_key_provider(key_provider)

    def master_key_for_encrypt(self, key_id):
        """Returns a master key for encrypt based on the specified key_id,
        adding it to this provider if not already present.

        :param bytes key_id:  Key ID with which to find or create Master Key
        :returns: Master Key based on key_id
        :rtype: aws_encryption_sdk.key_providers.base.MasterKey
        """
        key_id = to_bytes(key_id)
        self.add_master_key(key_id)
        return self._encrypt_key_index[key_id]

    master_key = master_key_for_encrypt

    def master_key_for_decrypt(self, key_info):
        """Returns a master key for decrypt based on the specified key_info.
        This is only added to this master key provider for the decrypt path.

        :param bytes key_info:  Key info from encrypted data key
        :returns: Master Key based on key_info
        :rtype: aws_encryption_sdk.key_providers.base.MasterKey
        """
        key_info = to_bytes(key_info)
        try:
            return self._encrypt_key_index[key_info]
        except KeyError:
            pass  # Not found in encrypt key index
        try:
            return self._decrypt_key_index[key_info]
        except KeyError:
            pass  # Not found in decrypt key index
        decrypt_master_key = self._new_master_key(key_info)
        self._decrypt_key_index[key_info] = decrypt_master_key
        return decrypt_master_key

    def decrypt_data_key(self, encrypted_data_key, algorithm, encryption_context):
        """Iterates through all currently added Master Keys and Master Key Providers
        to attempt to decrypt data key.

        :param encrypted_data_key: Encrypted data key to decrypt
        :type encrypted_data_key: aws_encryption_sdk.structures.EncryptedDataKey
        :param algorithm: Algorithm object which directs how this Master Key will encrypt the data key
        :type algorithm: aws_encryption_sdk.identifiers.Algorithm
        :param dict encryption_context: Encryption context to use in encryption
        :returns: Decrypted data key
        :rtype: aws_encryption_sdk.structures.DataKey
        :raises DecryptKeyError: if unable to decrypt encrypted data key
        """
        data_key = None
        master_key = None
        _LOGGER.debug("starting decrypt data key attempt")
        for member in [self] + self._members:
            if member.provider_id == encrypted_data_key.key_provider.provider_id:
                _LOGGER.debug("attempting to locate master key from key provider: %s", member.provider_id)
                if isinstance(member, MasterKey):
                    _LOGGER.debug("using existing master key")
                    master_key = member
                elif self.vend_masterkey_on_decrypt:
                    try:
                        _LOGGER.debug("attempting to add master key: %s", encrypted_data_key.key_provider.key_info)
                        master_key = member.master_key_for_decrypt(encrypted_data_key.key_provider.key_info)
                    except InvalidKeyIdError:
                        _LOGGER.debug(
                            "master key %s not available in provider", encrypted_data_key.key_provider.key_info
                        )
                        continue
                else:
                    continue
                try:
                    _LOGGER.debug(
                        "attempting to decrypt data key with provider %s", encrypted_data_key.key_provider.key_info
                    )
                    data_key = master_key.decrypt_data_key(encrypted_data_key, algorithm, encryption_context)
                except (IncorrectMasterKeyError, DecryptKeyError) as error:
                    _LOGGER.debug(
                        "%s raised when attempting to decrypt data key with master key %s",
                        repr(error),
                        master_key.key_provider,
                    )
                    continue
                break  # If this point is reached without throwing any errors, the data key has been decrypted
        if not data_key:
            raise DecryptKeyError("Unable to decrypt data key")
        return data_key

    def decrypt_data_key_from_list(self, encrypted_data_keys, algorithm, encryption_context):
        """Receives a list of encrypted data keys and returns the first one which this provider is able to decrypt.

        :param encrypted_data_keys: List of encrypted data keys
        :type encrypted_data_keys: list of :class:`aws_encryption_sdk.structures.EncryptedDataKey`
        :param algorithm: Algorithm object which directs how this Master Key will encrypt the data key
        :type algorithm: aws_encryption_sdk.identifiers.Algorithm
        :param dict encryption_context: Encryption context to use in encryption
        :returns: Decrypted data key
        :rtype: aws_encryption_sdk.structures.DataKey
        :raises DecryptKeyError: if unable to decrypt any of the supplied encrypted data keys
        """
        data_key = None
        for encrypted_data_key in encrypted_data_keys:
            try:
                data_key = self.decrypt_data_key(encrypted_data_key, algorithm, encryption_context)
            # MasterKeyProvider.decrypt_data_key throws DecryptKeyError
            # but MasterKey.decrypt_data_key throws IncorrectMasterKeyError
            except (DecryptKeyError, IncorrectMasterKeyError):
                continue
            else:
                break
        if not data_key:
            raise DecryptKeyError("Unable to decrypt any data key")
        return data_key


@attr.s(hash=True)
class MasterKeyConfig(object):
    """Configuration object for MasterKey objects.

    :param bytes key_id: Key ID for Master Key
    """

    key_id = attr.ib(hash=True, validator=attr.validators.instance_of((six.string_types, bytes)), converter=to_bytes)

    def __attrs_post_init__(self):
        """Verify that children of this class define a "provider_id" attribute."""
        if not hasattr(self, "provider_id"):
            raise TypeError('Instances of MasterKeyConfig must have a "provider_id" attribute defined.')


@six.add_metaclass(abc.ABCMeta)
class MasterKey(MasterKeyProvider):
    """Parent interface for Master Key classes.

    :param bytes key_id: Key ID for Master Key
    :param config: Configuration object
    :type config: aws_encryption_sdk.key_providers.base.MasterKeyConfig
    """

    def __new__(cls, **kwargs):
        """Performs universal prep work for all MasterKeys."""
        instance = super(MasterKey, cls).__new__(cls, **kwargs)

        if not hasattr(instance.config, "provider_id"):
            raise TypeError('MasterKey config classes must have a "provider_id" attribute defined.')

        if instance.config.provider_id is not None:
            # Only allow override if provider_id is NOT set to non-None for the class
            if instance.provider_id is None:
                instance.provider_id = instance.config.provider_id
            elif instance.provider_id != instance.config.provider_id:
                raise ConfigMismatchError(
                    "Config provider_id does not match MasterKey provider_id: {config} != {instance}".format(
                        config=instance.config.provider_id, instance=instance.provider_id
                    )
                )
        instance.key_id = instance.config.key_id
        instance._encrypt_key_index = {instance.key_id: instance}  # pylint: disable=protected-access
        # We cannot make any general statements about key_info, so specifically enforce that decrypt index is empty.
        instance._decrypt_key_index = {}  # pylint: disable=protected-access
        instance._members = [instance]  # pylint: disable=protected-access
        return instance

    @property
    def key_provider(self):
        """Provides the MasterKeyInfo object identifying this MasterKey.

        :returns: This MasterKey's Identifying Information
        :rtype: aws_encryption_sdk.structures.MasterKeyInfo
        """
        return MasterKeyInfo(self.provider_id, self.key_id)

    def owns_data_key(self, data_key):
        """Determines if data_key object is owned by this MasterKey.

        :param data_key: Data key to evaluate
        :type data_key: :class:`aws_encryption_sdk.structures.DataKey`,
            :class:`aws_encryption_sdk.structures.RawDataKey`,
            or :class:`aws_encryption_sdk.structures.EncryptedDataKey`
        :returns: Boolean statement of ownership
        :rtype: bool
        """
        if data_key.key_provider == self.key_provider:
            return True
        return False

    def master_keys_for_encryption(self, encryption_context, plaintext_rostream, plaintext_length=None):
        """Returns self and a list containing self, to match the format of output for a Master Key Provider.

        .. warning::
            If plaintext_stream seek position is modified, it must be returned before leaving method.

        :param dict encryption_context: Encryption context passed to client
        :param plaintext_rostream: Source plaintext read-only stream
        :type plaintext_rostream: aws_encryption_sdk.internal.utils.streams.ROStream
        :param int plaintext_length: Length of source plaintext (optional)
        :returns: Tuple containing self and a list of self
        :rtype: tuple containing :class:`aws_encryption_sdk.key_providers.base.MasterKey`
            and list of :class:`aws_encryption_sdk.key_providers.base.MasterKey`
        """
        return self, [self]

    def _new_master_key(self, key_id):
        """Returns self as master key instance.

        :param bytes key_id: ID of key to return
        :returns: self
        :raises InvalidKeyIdError: if key_id is not ID for self
        """
        if key_id != self.key_id:
            raise InvalidKeyIdError(
                "MasterKeys can only provide themselves.  Requested {requested} but only {key} is available".format(
                    requested=key_id, key=self.key_id
                )
            )
        return self

    def _key_check(self, data_key):
        """Verifies that supplied Data Key's key provider matches this Master Key.

        :param data_key: Data Key to verify
        :type data_key: :class:`aws_encryption_sdk.structures.RawDataKey`,
            :class:`aws_encryption_sdk.structures.DataKey`,
            or :class:`aws_encryption_sdk.structures.EncryptedDataKey`
        :raises IncorrectMasterKeyError: if Data Key's key provider does not match this Master Key
        """
        if not self.owns_data_key(data_key):
            raise IncorrectMasterKeyError(
                "Provided data key provider {key} does not match Master Key provider {master}".format(
                    key=data_key.key_provider, master=self.key_provider
                )
            )

    def generate_data_key(self, algorithm, encryption_context):
        """Generates and returns data key for use encrypting message.

        :param algorithm: Algorithm on which to base data key
        :type algorithm: aws_encryption_sdk.identifiers.Algorithm
        :param dict encryption_context: Encryption context to use in encryption
        :returns: Generated data key
        :rtype: aws_encryption_sdk.structures.DataKey
        """
        _LOGGER.info("generating data key with encryption context: %s", encryption_context)
        generated_data_key = self._generate_data_key(algorithm=algorithm, encryption_context=encryption_context)
        aws_encryption_sdk.internal.utils.source_data_key_length_check(
            source_data_key=generated_data_key, algorithm=algorithm
        )
        return generated_data_key

    @abc.abstractmethod
    def _generate_data_key(self, algorithm, encryption_context):
        """Performs the provider-specific data key generation task.

        .. note::
            Must be implemented by specific MasterKey implementations.

        :param algorithm: Algorithm on which to base data key
        :type algorithm: aws_encryption_sdk.identifiers.Algorithm
        :param dict encryption_context: Encryption context to use in encryption
        :returns: Generated data key
        :rtype: aws_encryption_sdk.structures.DataKey
        """

    def encrypt_data_key(self, data_key, algorithm, encryption_context):
        """Encrypts a supplied data key.

        :param data_key: Unencrypted data key
        :type data_key: :class:`aws_encryption_sdk.structures.RawDataKey`
            or :class:`aws_encryption_sdk.structures.DataKey`
        :param algorithm: Algorithm object which directs how this Master Key will encrypt the data key
        :type algorithm: aws_encryption_sdk.identifiers.Algorithm
        :param dict encryption_context: Encryption context to use in encryption
        :returns: Data key containing encrypted data key
        :rtype: aws_encryption_sdk.structures.EncryptedDataKey
        :raises IncorrectMasterKeyError: if Data Key's key provider does not match this Master Key
        """
        _LOGGER.info("encrypting data key with encryption context: %s", encryption_context)
        return self._encrypt_data_key(data_key=data_key, algorithm=algorithm, encryption_context=encryption_context)

    @abc.abstractmethod
    def _encrypt_data_key(self, data_key, algorithm, encryption_context):
        """Performs the provider-specific data key encryption actions.

        .. note::
            Must be implemented by specific MasterKey implementations.

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

    def decrypt_data_key(self, encrypted_data_key, algorithm, encryption_context):
        """Decrypts an encrypted data key and returns the plaintext.

        :param data_key: Encrypted data key
        :type data_key: aws_encryption_sdk.structures.EncryptedDataKey
        :param algorithm: Algorithm object which directs how this Master Key will encrypt the data key
        :type algorithm: aws_encryption_sdk.identifiers.Algorithm
        :param dict encryption_context: Encryption context to use in decryption
        :returns: Decrypted data key
        :rtype: aws_encryption_sdk.structures.DataKey
        :raises IncorrectMasterKeyError: if Data Key's key provider does not match this Master Key
        """
        _LOGGER.info("decrypting data key with encryption context: %s", encryption_context)
        self._key_check(encrypted_data_key)
        decrypted_data_key = self._decrypt_data_key(
            encrypted_data_key=encrypted_data_key, algorithm=algorithm, encryption_context=encryption_context
        )
        aws_encryption_sdk.internal.utils.source_data_key_length_check(
            source_data_key=decrypted_data_key, algorithm=algorithm
        )
        return decrypted_data_key

    @abc.abstractmethod
    def _decrypt_data_key(self, encrypted_data_key, algorithm, encryption_context):
        """Decrypts an encrypted data key and returns the plaintext.

        .. note::
            Must be implemented by specific MasterKey implementations.

        :param data_key: Encrypted data key
        :type data_key: aws_encryption_sdk.structures.EncryptedDataKey
        :param algorithm: Algorithm object which directs how this Master Key will encrypt the data key
        :type algorithm: aws_encryption_sdk.identifiers.Algorithm
        :param dict encryption_context: Encryption context to use in decryption
        :returns: Data key containing decrypted data key
        :rtype: aws_encryption_sdk.structures.DataKey
        :raises DecryptKeyError: if Master Key is unable to decrypt data key
        """
