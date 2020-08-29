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
"""Base class interface for caches for use with caching crypto material managers."""
import abc

import six


@six.add_metaclass(abc.ABCMeta)
class CryptoMaterialsCache(object):
    """Parent interface for crypto materials caches.

    .. versionadded:: 1.3.0
    """

    @abc.abstractmethod
    def put_encryption_materials(self, cache_key, encryption_materials, plaintext_length, entry_hints=None):
        """Adds encryption materials to the cache.

        :param bytes cache_key: Identifier for entries in cache
        :param encryption_materials: Encryption materials to add to cache
        :type encryption_materials: aws_encryption_sdk.materials_managers.EncryptionMaterials
        :param int plaintext_length: Length of plaintext associated with this request to the cache
        :param entry_hints: Metadata to associate with entry (optional)
        :type entry_hints: aws_encryption_sdk.caches.CryptoCacheEntryHints
        :rtype: aws_encryption_sdk.caches.CryptoCacheEntry
        """

    @abc.abstractmethod
    def put_decryption_materials(self, cache_key, decryption_materials):
        """Adds decryption materials to the cache

        :param bytes cache_key: Identifier for entries in cache
        :param decryption_materials: Decryption materials to add to cache
        :type decryption_materials: aws_encryption_sdk.materials_managers.DecryptionMaterials
        :rtype: aws_encryption_sdk.caches.CryptoCacheEntry
        """

    @abc.abstractmethod
    def get_encryption_materials(self, cache_key, plaintext_length):
        """Locates exactly one available encryption materials cache entry for the specified cache_key,
        incrementing the entry's usage stats prior to returning it to the caller.

        :param bytes cache_key: Cache ID for which to locate cache entries
        :param int plaintext_length: Bytes to be encrypted by the encryption materials
        :rtype: aws_encryption_sdk.caches.CryptoCacheEntry
        :raises CacheKeyError: if no values found in cache for cache_key
        """

    @abc.abstractmethod
    def get_decryption_materials(self, cache_key):
        """Locates exactly one available decryption materials cache entry for the specified cache_key.

        :param bytes cache_key: Cache ID for which to locate cache entries
        :rtype: aws_encryption_sdk.caches.CryptoCacheEntry
        :raises CacheKeyError: if no values found in cache for cache_key
        """
