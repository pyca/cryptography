# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import binascii
import os
import struct
import time

import six

from cryptography.hazmat.bindings import default_backend
from cryptography.hazmat.primitives import padding, hashes, constant_time
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class InvalidToken(Exception):
    pass


_MAX_CLOCK_SKEW = 60


class Fernet(object):
    def __init__(self, key):
        key = base64.urlsafe_b64decode(key)
        assert len(key) == 32
        self.signing_key = key[:16]
        self.encryption_key = key[16:]
        self.backend = default_backend()

    @classmethod
    def generate_key(cls):
        return base64.urlsafe_b64encode(os.urandom(32))

    def encrypt(self, data):
        current_time = int(time.time())
        iv = os.urandom(16)
        return self._encrypt_from_parts(data, current_time, iv)

    def _encrypt_from_parts(self, data, current_time, iv):
        if isinstance(data, six.text_type):
            raise TypeError(
                "Unicode-objects must be encoded before encryption"
            )

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encryptor = Cipher(
            algorithms.AES(self.encryption_key), modes.CBC(iv), self.backend
        ).encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        basic_parts = (
            b"\x80" + struct.pack(">Q", current_time) + iv + ciphertext
        )

        h = HMAC(self.signing_key, hashes.SHA256(), self.backend)
        h.update(basic_parts)
        hmac = h.finalize()
        return base64.urlsafe_b64encode(basic_parts + hmac)

    def decrypt(self, data, ttl=None):
        if isinstance(data, six.text_type):
            raise TypeError(
                "Unicode-objects must be encoded before decryption"
            )

        current_time = int(time.time())

        try:
            data = base64.urlsafe_b64decode(data)
        except (TypeError, binascii.Error):
            raise InvalidToken

        assert six.indexbytes(data, 0) == 0x80
        timestamp = data[1:9]
        iv = data[9:25]
        ciphertext = data[25:-32]
        if ttl is not None:
            if struct.unpack(">Q", timestamp)[0] + ttl < current_time:
                raise InvalidToken
        if current_time + _MAX_CLOCK_SKEW < struct.unpack(">Q", timestamp)[0]:
            raise InvalidToken
        h = HMAC(self.signing_key, hashes.SHA256(), self.backend)
        h.update(data[:-32])
        hmac = h.finalize()
        if not constant_time.bytes_eq(hmac, data[-32:]):
            raise InvalidToken

        decryptor = Cipher(
            algorithms.AES(self.encryption_key), modes.CBC(iv), self.backend
        ).decryptor()
        plaintext_padded = decryptor.update(ciphertext)
        try:
            plaintext_padded += decryptor.finalize()
        except ValueError:
            raise InvalidToken
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

        unpadded = unpadder.update(plaintext_padded)
        try:
            unpadded += unpadder.finalize()
        except ValueError:
            raise InvalidToken
        return unpadded
