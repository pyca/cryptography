# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os

from cryptography.hazmat.backends.openssl.backend import backend


class ChaCha20Poly1305(object):
    def __init__(self, key):
        if len(key) != 32:
            raise ValueError("ChaCha20Poly1305 key must be 32 bytes.")

        self._key = key

    @classmethod
    def generate_key(cls):
        return os.urandom(32)

    def encrypt(self, nonce, data, additional_data):
        return backend.chacha20poly1305_encrypt(
            self._key, nonce, data, additional_data
        )

    def decrypt(self, nonce, tag, data, additional_data):
        return backend.chacha20poly1305_decrypt(
            self._key, nonce, tag, data, additional_data
        )
