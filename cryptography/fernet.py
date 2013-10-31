import base64
import os
import struct
import time

import six

from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.block import BlockCipher, ciphers, modes


class InvalidToken(Exception):
    pass


class Fernet(object):
    def __init__(self, key):
        super(Fernet, self).__init__()
        assert len(key) == 32
        self.signing_key = key[:16]
        self.encryption_key = key[16:]

    def encrypt(self, data):
        current_time = int(time.time())
        iv = os.urandom(16)
        return self._encrypt_from_parts(data, current_time, iv)

    def _encrypt_from_parts(self, data, current_time, iv):
        if isinstance(data, six.text_type):
            raise TypeError(
                "Unicode-objects must be encoded before encryption"
            )

        padder = padding.PKCS7(ciphers.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encryptor = BlockCipher(
            ciphers.AES(self.encryption_key), modes.CBC(iv)
        ).encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        h = HMAC(self.signing_key, digestmod=hashes.SHA256)
        h.update(b"\x80")
        h.update(struct.pack(">Q", current_time))
        h.update(iv)
        h.update(ciphertext)
        hmac = h.digest()
        return base64.urlsafe_b64encode(
            b"\x80" + struct.pack(">Q", current_time) + iv + ciphertext + hmac
        )

    def decrypt(self, data, ttl=None, current_time=None):
        if isinstance(data, six.text_type):
            raise TypeError(
                "Unicode-objects must be encoded before decryption"
            )

        if current_time is None:
            current_time = int(time.time())

        try:
            data = base64.urlsafe_b64decode(data)
        except TypeError:
            raise InvalidToken

        assert six.indexbytes(data, 0) == 0x80
        timestamp = data[1:9]
        iv = data[9:25]
        ciphertext = data[25:-32]
        if ttl is not None:
            if struct.unpack(">Q", timestamp)[0] + ttl < current_time:
                raise InvalidToken
        h = HMAC(self.signing_key, digestmod=hashes.SHA256)
        h.update(data[:-32])
        hmac = h.digest()

        if not constant_time_compare(hmac, data[-32:]):
            raise InvalidToken

        decryptor = BlockCipher(
            ciphers.AES(self.encryption_key), modes.CBC(iv)
        ).decryptor()
        plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(ciphers.AES.block_size).unpadder()

        unpadded = unpadder.update(plaintext_padded)
        try:
            unpadded += unpadder.finalize()
        except ValueError:
            raise InvalidToken
        return unpadded


def constant_time_compare(a, b):
    # TOOD: replace with a cffi function
    assert isinstance(a, bytes) and isinstance(b, bytes)
    if len(a) != len(b):
        return False
    result = 0
    for i in range(len(a)):
        result |= six.indexbytes(a, i) ^ six.indexbytes(b, i)
    return result == 0
