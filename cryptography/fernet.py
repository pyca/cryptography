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

import cffi

import six

from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class InvalidToken(Exception):
    pass


_ffi = cffi.FFI()
_ffi.cdef("""
bool Cryptography_constant_time_compare(uint8_t *, size_t, uint8_t *, size_t);
""")
_lib = _ffi.verify("""
#include <stdbool.h>

bool Cryptography_constant_time_compare(uint8_t *a, size_t len_a, uint8_t *b,
                                        size_t len_b) {
    size_t i = 0;
    uint8_t mismatch = 0;
    if (len_a != len_b) {
        return false;
    }
    for (i = 0; i < len_a; i++) {
        mismatch |= a[i] ^ b[i];
    }

    /* Make sure any bits set are copied to the lowest bit */
    mismatch |= mismatch >> 4;
    mismatch |= mismatch >> 2;
    mismatch |= mismatch >> 1;
    /* Now check the low bit to see if it's set */
    return (mismatch & 1) == 0;
}
""")


class Fernet(object):
    def __init__(self, key, backend=None):
        key = base64.urlsafe_b64decode(key)
        assert len(key) == 32
        self.signing_key = key[:16]
        self.encryption_key = key[16:]
        self.backend = backend

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
        h = HMAC(self.signing_key, hashes.SHA256(), self.backend)
        h.update(data[:-32])
        hmac = h.finalize()
        valid = _lib.Cryptography_constant_time_compare(
            hmac, len(hmac), data[-32:], 32
        )
        if not valid:
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
