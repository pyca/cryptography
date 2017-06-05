# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os

from cryptography import utils
from cryptography.hazmat.backends.openssl.backend import backend


class ChaCha20Poly1305(object):
    def __init__(self, key):
        utils.check_bytes("key", key)

        if len(key) != 32:
            raise ValueError("ChaCha20Poly1305 key must be 32 bytes.")

        self._key = key

    @classmethod
    def generate_key(cls):
        return os.urandom(32)

    def encrypt(self, nonce, data, associated_data):
        if associated_data is None:
            associated_data = b""

        self._check_vars(nonce, data, associated_data)
        return backend.chacha20poly1305_encrypt(
            self._key, nonce, data, associated_data
        )

    def decrypt(self, nonce, tag, data, associated_data):
        if associated_data is None:
            associated_data = b""

        self._check_vars(nonce, data, associated_data)
        utils.check_bytes("tag", tag)
        if not len(tag) == 16:
            raise ValueError("tag must be 16 bytes")

        return backend.chacha20poly1305_decrypt(
            self._key, nonce, tag, data, associated_data
        )

    def _check_vars(self, nonce, data, associated_data):
        utils.check_bytes("nonce", nonce)
        utils.check_bytes("data", data)
        utils.check_bytes("associated_data", associated_data)
        if not len(nonce) == 12:
            raise ValueError("Nonce must be 12 bytes")
