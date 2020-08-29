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
"""Local, in-memory, LRU, cryptographic materials cache for use with caching cryptographic materials providers."""
import logging
import weakref
from collections import OrderedDict, deque
from threading import RLock

import attr
import six

from ..exceptions import CacheKeyError, NotSupportedError
from . import CryptoMaterialsCacheEntry
from .base import CryptoMaterialsCache

_OPPORTUNISTIC_EVICTION_ROUNDS = 10
_LOGGER = logging.getLogger(__name__)


@attr.s(hash=False)
class LocalCryptoMaterialsCache(CryptoMaterialsCache):
    """Local, in-memory, LRU, cache for use with caching cryptographic materials providers.

    .. versionadded:: 1.3.0

    :param int capacity: Maximum number of entries to retain in cache at once
    """

    capacity = attr.ib(validator=attr.validators.instance_of(six.integer_types))

    def __attrs_post_init__(self):
        """Prepares initial values not handled by attrs."""
        if self.capacity < 1:
            raise ValueError("LocalCryptoMaterialsCache capacity cannot be less than 1")
        self._cache_lock = RLock()
        self._cache = OrderedDict()  # Maps each cache key to the active entry for that key
        self._lre_deque = deque()  # Tracks references to recently evaluated entries
        # The LRE deque is a rotating index of references to entries in the internal cache.
        #  _OPPORTUNISTIC_EVICTION_ROUNDS of these references are evaluated on each read/
        #  write operation to the cache.

        # Enables setattr whitelist restriction
        # Must always be the final line in this method
        self._init_completed = True

    def __setattr__(self, name, value):
        """Disable setting of capacity after __attrs_post_init__ has run."""
        if hasattr(self, "_init_completed") and name == "capacity":
            raise NotSupportedError("capacity may not be modified on LocalCryptoMaterialsCache instances")
        return super(LocalCryptoMaterialsCache, self).__setattr__(name, value)

    def _try_to_evict_one_entry(self):
        """Checks the least recently evaluated entry and evicts it from the cache if it is expired."""
        with self._cache_lock:
            try:
                entry_ref = self._lre_deque.pop()
            except IndexError:
                # LRE deque is empty
                return
            actual_entry = entry_ref()
            if actual_entry is None:
                # actual entry has already been removed
                return
            if not actual_entry.valid or actual_entry.is_too_old():
                # remove from cache
                actual_entry.invalidate()
                try:
                    del self._cache[actual_entry.cache_key]
                except KeyError:
                    # Catches a race condition where entries removed by _prune
                    # may not be garbage collected as quickly as manually removed
                    # entries
                    pass
                return
            # entry is still active and valid: add back to start of LRE
            self._lre_deque.appendleft(entry_ref)

    def _try_to_evict_some_entries(self):
        """Tries to evict a set number of the least recently evaluated cache entries."""
        for _ in range(_OPPORTUNISTIC_EVICTION_ROUNDS):
            self._try_to_evict_one_entry()

    def _prune(self):
        """Prunes internal cache until internal cache is within the defined limit."""
        while len(self._cache) > self.capacity:
            _, value = self._cache.popitem(last=False)
            value.invalidate()
            # See comment in remove()
            self._try_to_evict_one_entry()

    def _add_value_to_cache(self, value):
        """Adds a value to the cache data and control structures.

        :param value: Value to add to cache
        :type value: aws_encryption_sdk.caches.CryptoMaterialsCacheEntry
        """
        with self._cache_lock:
            reference = weakref.ref(value)
            self._cache[value.cache_key] = value
            self._lre_deque.appendleft(reference)
            self._prune()

    def put_encryption_materials(self, cache_key, encryption_materials, plaintext_length, entry_hints=None):
        """Adds encryption materials to the cache.

        :param bytes cache_key: Identifier for entries in cache
        :param encryption_materials: Encryption materials to add to cache
        :type encryption_materials: aws_encryption_sdk.materials_managers.EncryptionMaterials
        :param int plaintext_length: Length of plaintext associated with this request to the cache
        :param entry_hints: Metadata to associate with entry (optional)
        :type entry_hints: aws_encryption_sdk.caches.CryptoCacheEntryHints
        :rtype: aws_encryption_sdk.caches.CryptoMaterialsCacheEntry
        """
        entry = CryptoMaterialsCacheEntry(cache_key=cache_key, value=encryption_materials, hints=entry_hints)
        entry._update_with_message_bytes_encrypted(plaintext_length)  # pylint: disable=protected-access
        with self._cache_lock:
            self._try_to_evict_some_entries()
            self._add_value_to_cache(entry)
        return entry

    def put_decryption_materials(self, cache_key, decryption_materials):
        """Adds decryption materials to the cache

        :param bytes cache_key: Identifier for entries in cache
        :param decryption_materials: Decryption materials to add to cache
        :type decryption_materials: aws_encryption_sdk.materials_managers.DecryptionMaterials
        :rtype: aws_encryption_sdk.caches.CryptoMaterialsCacheEntry
        """
        entry = CryptoMaterialsCacheEntry(cache_key=cache_key, value=decryption_materials)
        with self._cache_lock:
            self._try_to_evict_some_entries()
            self._add_value_to_cache(entry)
        return entry

    def remove(self, value):
        """Removes a value from the cache.

        :param value: Value to add to cache
        :type value: aws_encryption_sdk.caches.CryptoMaterialsCacheEntry
        :raises CacheKeyError: if value not found in cache
        """
        with self._cache_lock:
            try:
                value.invalidate()
                del self._cache[value.cache_key]
                # Because removing the now-dead reference from _lre_deque is an O(n)
                # operation, for n <= _OPPORTUNISTIC_EVICTION_ROUNDS it is always more
                # efficient to simply run through a few eviction attempts to clear out
                # dead references.
            except KeyError:
                raise CacheKeyError("Key not found in cache")
            finally:
                self._try_to_evict_some_entries()

    def _get_single_entry(self, cache_key):
        """Locates exactly one available cache entry for the specified cache_key.

        :param bytes cache_key: Cache ID for which to locate cache entries
        :rtype: aws_encryption_sdk.caches.CryptoMaterialsCacheEntry
        :raises CacheKeyError: if no values found in cache for cache_key
        """
        with self._cache_lock:
            try:
                cache_entry = self._cache[cache_key]
            except KeyError:
                raise CacheKeyError("Key not found in cache")

            if not cache_entry.valid:
                self.remove(cache_entry)
                raise CacheKeyError("Key not found in cache")

            return cache_entry

    def get_encryption_materials(self, cache_key, plaintext_length):
        """Locates exactly one available encryption materials cache entry for the specified cache_key,
        incrementing the entry's usage stats prior to returning it to the caller.

        :param bytes cache_key: Cache ID for which to locate cache entries
        :param int plaintext_length: Length of plaintext associated with this request to the cache
        :rtype: aws_encryption_sdk.caches.CryptoMaterialsCacheEntry
        :raises CacheKeyError: if no values found in cache for cache_key
        """
        _LOGGER.debug("Looking in cache for encryption materials to encrypt %d bytes.", plaintext_length)
        with self._cache_lock:
            entry = self._get_single_entry(cache_key)
            entry._update_with_message_bytes_encrypted(plaintext_length)  # pylint: disable=protected-access
            return entry

    def get_decryption_materials(self, cache_key):
        """Locates exactly one available decryption materials cache entry for the specified cache_key.

        :param bytes cache_key: Cache ID for which to locate cache entries
        :rtype: aws_encryption_sdk.caches.CryptoMaterialsCacheEntry
        :raises CacheKeyError: if no values found in cache for cache_key
        """
        with self._cache_lock:
            return self._get_single_entry(cache_key)

    def clear(self):
        """Clears the cache."""
        with self._cache_lock:
            self._cache = OrderedDict()
            self._lre_deque = deque()
