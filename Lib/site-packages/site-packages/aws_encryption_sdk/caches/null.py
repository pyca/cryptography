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
"""Null cache: a cache which does not cache."""
from ..exceptions import CacheKeyError
from . import CryptoMaterialsCacheEntry
from .base import CryptoMaterialsCache


class NullCryptoMaterialsCache(CryptoMaterialsCache):
    """Null cache: a cache which does not cache.

    .. versionadded:: 1.3.0
    """

    def put_encryption_materials(self, cache_key, encryption_materials, plaintext_length, entry_hints=None):
        """Does not add encryption materials to the cache since there is no cache to which to add them.

        :param bytes cache_key: Identifier for entries in cache
        :param encryption_materials: Encryption materials to add to cache
        :type encryption_materials: aws_encryption_sdk.materials_managers.EncryptionMaterials
        :param int plaintext_length: Length of plaintext associated with this request to the cache
        :param entry_hints: Metadata to associate with entry (optional)
        :type entry_hints: aws_encryption_sdk.caches.CryptoCacheEntryHints
        :rtype: aws_encryption_sdk.caches.CryptoMaterialsCacheEntry
        """
        return CryptoMaterialsCacheEntry(cache_key=cache_key, value=encryption_materials)

    def put_decryption_materials(self, cache_key, decryption_materials):
        """Does not add decryption materials to the cache since there is no cache to which to add them.

        :param bytes cache_key: Identifier for entries in cache
        :param decryption_materials: Decryption materials to add to cache
        :type decryption_materials: aws_encryption_sdk.materials_managers.DecryptionMaterials
        :rtype: aws_encryption_sdk.caches.CryptoMaterialsCacheEntry
        """
        return CryptoMaterialsCacheEntry(cache_key=cache_key, value=decryption_materials)

    def get_encryption_materials(self, cache_key, plaintext_length):
        """Always raises a CacheKeyError.

        :param bytes cache_key: Cache ID for which to locate cache entries
        :param int plaintext_length: Bytes to be encrypted by the encryption materials
        :rtype: aws_encryption_sdk.caches.CryptoCacheEntry
        :raises CacheKeyError: when called
        """
        raise CacheKeyError("Key not found in cache")

    def get_decryption_materials(self, cache_key):
        """Always raises a CacheKeyError.

        :param bytes cache_key: Cache ID for which to locate cache entries
        :rtype: aws_encryption_sdk.caches.CryptoCacheEntry
        :raises CacheKeyError: when called
        """
        raise CacheKeyError("Key not found in cache")
