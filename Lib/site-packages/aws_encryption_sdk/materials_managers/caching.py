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
"""Caching crypto material manager."""
import logging
import uuid

import attr
import six

from ..caches import (
    CryptoMaterialsCacheEntryHints,
    build_decryption_materials_cache_key,
    build_encryption_materials_cache_key,
)
from ..caches.base import CryptoMaterialsCache
from ..exceptions import CacheKeyError
from ..internal.defaults import MAX_BYTES_PER_KEY, MAX_MESSAGES_PER_KEY
from ..internal.str_ops import to_bytes
from ..key_providers.base import MasterKeyProvider
from . import EncryptionMaterialsRequest
from .base import CryptoMaterialsManager
from .default import DefaultCryptoMaterialsManager

_LOGGER = logging.getLogger(__name__)


@attr.s(hash=False)
class CachingCryptoMaterialsManager(CryptoMaterialsManager):
    """Crypto material manager which caches results from an underlying material manager.

    .. versionadded:: 1.3.0

    >>> import aws_encryption_sdk
    >>> kms_key_provider = aws_encryption_sdk.KMSMasterKeyProvider(key_ids=[
    ...     'arn:aws:kms:us-east-1:2222222222222:key/22222222-2222-2222-2222-222222222222',
    ...     'arn:aws:kms:us-east-1:3333333333333:key/33333333-3333-3333-3333-333333333333'
    ... ])
    >>> local_cache = aws_encryption_sdk.LocalCryptoMaterialsCache(capacity=100)
    >>> caching_materials_manager = aws_encryption_sdk.CachingCryptoMaterialsManager(
    ...     master_key_provider=kms_key_provider,
    ...     cache=local_cache,
    ...     max_age=600.0,
    ...     max_messages_encrypted=10
    ... )

    .. note::
        The partition name is used to enable a single cache instance to be used by multiple
        material manager instances by partitioning the entries in that cache based on this
        value.  If no partition name is provided, a random UUID will be used.

    .. note::
        Either `backing_materials_manager` or `master_key_provider` must be provided.
        `backing_materials_manager` will always be used if present.

    :param cache: Crypto cache to use with material manager
    :type cache: aws_encryption_sdk.caches.base.CryptoMaterialsCache
    :param backing_materials_manager: Crypto material manager to back this caching material manager
        (either `backing_materials_manager` or `master_key_provider` required)
    :type backing_materials_manager: aws_encryption_sdk.materials_managers.base.CryptoMaterialsManager
    :param master_key_provider: Master key provider to use (either `backing_materials_manager` or
        `master_key_provider` required)
    :type master_key_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    :param float max_age: Maximum time in seconds that a cache entry may be kept in the cache
    :param int max_messages_encrypted: Maximum number of messages that may be encrypted under
        a cache entry (optional)
    :param int max_bytes_encrypted: Maximum number of bytes that a cache entry may be used
        to process (optional)
    :param bytes partition_name: Partition name to use for this instance (optional)
    """

    cache = attr.ib(validator=attr.validators.instance_of(CryptoMaterialsCache))
    max_age = attr.ib(validator=attr.validators.instance_of(float))
    max_messages_encrypted = attr.ib(
        default=MAX_MESSAGES_PER_KEY, validator=attr.validators.instance_of(six.integer_types)
    )
    max_bytes_encrypted = attr.ib(default=MAX_BYTES_PER_KEY, validator=attr.validators.instance_of(six.integer_types))
    partition_name = attr.ib(
        default=None, converter=to_bytes, validator=attr.validators.optional(attr.validators.instance_of(bytes))
    )
    master_key_provider = attr.ib(
        default=None, validator=attr.validators.optional(attr.validators.instance_of(MasterKeyProvider))
    )
    backing_materials_manager = attr.ib(
        default=None, validator=attr.validators.optional(attr.validators.instance_of(CryptoMaterialsManager))
    )

    def __attrs_post_init__(self):
        """Applies post-processing which cannot be handled by attrs."""
        if self.max_messages_encrypted < 1:
            raise ValueError("max_messages_encrypted cannot be less than 1")

        if self.max_bytes_encrypted < 0:
            raise ValueError("max_bytes_encrypted cannot be less than 0")

        if self.max_messages_encrypted > MAX_MESSAGES_PER_KEY:
            raise ValueError("max_messages_encrypted cannot exceed {}".format(MAX_MESSAGES_PER_KEY))

        if self.max_bytes_encrypted > MAX_BYTES_PER_KEY:
            raise ValueError("max_bytes_encrypted cannot exceed {}".format(MAX_BYTES_PER_KEY))

        if self.max_age <= 0.0:
            raise ValueError("max_age cannot be less than or equal to 0")

        if self.backing_materials_manager is None:
            if self.master_key_provider is None:
                raise TypeError("Either backing_materials_manager or master_key_provider must be defined")
            self.backing_materials_manager = DefaultCryptoMaterialsManager(self.master_key_provider)

        if self.partition_name is None:
            self.partition_name = to_bytes(str(uuid.uuid4()))

    def _cache_entry_has_encrypted_too_many_bytes(self, entry):
        """Determines if a cache entry has exceeded the max allowed bytes encrypted.

        :param entry: Entry to evaluate
        :type entry: aws_encryption_sdk.caches.CryptoCacheEntry
        :rtype: bool
        """
        return entry.bytes_encrypted > self.max_bytes_encrypted

    def _cache_entry_has_encrypted_too_many_messages(self, entry):
        """Determines if a cache entry has exceeded the max allowed messages encrypted.

        :param entry: Entry to evaluate
        :type entry: aws_encryption_sdk.caches.CryptoCacheEntry
        :rtype: bool
        """
        return entry.messages_encrypted > self.max_messages_encrypted

    def _cache_entry_is_too_old(self, entry):
        """Determines if a cache entry has exceeded the max allowed age.

        :param entry: Entry to evaluate
        :type entry: aws_encryption_sdk.caches.CryptoCacheEntry
        :rtype: bool
        """
        return entry.age > self.max_age

    def _cache_entry_has_exceeded_limits(self, entry):
        """Determines if a cache entry has exceeded any security limits.

        :param entry: Entry to evaluate
        :type entry: aws_encryption_sdk.caches.CryptoCacheEntry
        :rtype: bool
        """
        return (
            self._cache_entry_is_too_old(entry)
            or self._cache_entry_has_encrypted_too_many_messages(entry)
            or self._cache_entry_has_encrypted_too_many_bytes(entry)
        )

    def _should_cache_encryption_request(self, request):
        """Determines whether the encryption materials request should be cached.

        :param request: Encryption materials request
        :type request: aws_encryption_sdk.materials_managers.EncryptionMaterialsRequest
        :rtype: bool
        """
        if request.plaintext_length is None:
            _LOGGER.debug("Encryption materials request not cached because plaintext length is unknown")
            return False

        if request.algorithm is not None and not request.algorithm.safe_to_cache():
            _LOGGER.debug("Encryption materials request not cached because algorithm suite is not safe to cache")
            return False

        return True

    def get_encryption_materials(self, request):
        """Provides encryption materials appropriate for the request.

        :param request: Encryption materials request
        :type request: aws_encryption_sdk.materials_managers.EncryptionMaterialsRequest
        :returns: encryption materials
        :rtype: aws_encryption_sdk.materials_managers.EncryptionMaterials
        """
        if not self._should_cache_encryption_request(request):
            return self.backing_materials_manager.get_encryption_materials(request)

        # Inner request strips any information about the plaintext from the actual request.
        # This is done because the resulting encryption materials may be used to encrypt
        #  multiple plaintexts.
        inner_request = EncryptionMaterialsRequest(
            encryption_context=request.encryption_context,
            frame_length=request.frame_length,
            algorithm=request.algorithm,
        )
        cache_key = build_encryption_materials_cache_key(partition=self.partition_name, request=inner_request)

        # Attempt to retrieve from cache
        try:
            cache_entry = self.cache.get_encryption_materials(
                cache_key=cache_key, plaintext_length=request.plaintext_length
            )
        except CacheKeyError:
            pass
        else:
            if self._cache_entry_has_exceeded_limits(cache_entry):
                self.cache.remove(cache_entry)
            else:
                return cache_entry.value

        # Nothing found in cache: try the material manager
        new_result = self.backing_materials_manager.get_encryption_materials(inner_request)

        if not new_result.algorithm.safe_to_cache() or request.plaintext_length >= self.max_bytes_encrypted:
            return new_result

        # Add results into cache
        self.cache.put_encryption_materials(
            cache_key=cache_key,
            encryption_materials=new_result,
            plaintext_length=request.plaintext_length,
            entry_hints=CryptoMaterialsCacheEntryHints(lifetime=self.max_age),
        )
        return new_result

    def decrypt_materials(self, request):
        """Provides decryption materials appropriate for the request.

        :param request: decrypt materials request
        :type request: aws_encryption_sdk.materials_managers.DecryptionMaterialsRequest
        :returns: decryption materials
        :rtype: aws_encryption_sdk.materials_managers.DecryptionMaterials
        """
        cache_key = build_decryption_materials_cache_key(partition=self.partition_name, request=request)

        # Attempt to retrieve from cache
        try:
            cache_entry = self.cache.get_decryption_materials(cache_key)
        except CacheKeyError:
            pass
        else:
            if self._cache_entry_is_too_old(cache_entry):
                self.cache.remove(cache_entry)
            else:
                return cache_entry.value

        # Nothing found in cache: try the material manager
        new_result = self.backing_materials_manager.decrypt_materials(request)

        # Add results into cache
        self.cache.put_decryption_materials(cache_key=cache_key, decryption_materials=new_result)
        return new_result
