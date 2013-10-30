import base64
import os
import struct
import time

from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.block import BlockCipher, ciphers, modes


class Fernet(object):
    def __init__(self, key):
        super(Fernet, self).__init__()
        self.signing_key = key[:16]
        self.encryption_key = key[16:]

    def encrypt(self, data):
        current_time = int(time.time())
        iv = os.urandom(16)
        return self._encrypt_from_parts(data, current_time, iv)

    def _encrypt_from_parts(self, data, current_time, iv):
        padder = padding.PKCS7(ciphers.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encryptor = BlockCipher(ciphers.AES(self.encryption_key), modes.CBC(iv)).encryptor()
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
