# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import base64
import binascii
import os
import struct
import time

import six

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC


class InvalidToken(Exception):
    pass


_MAX_CLOCK_SKEW = 60


class FernetBase(object):
    """
    Base class for Fernet objects. Do not use directly.
    """

    def __init__(self, key, backend=None):
        if backend is None:
            backend = default_backend()

        # key size in bytes = len(key) * 8 bits/byte / 2 keys
        key_size = len(key) * 4
        key_bytes = len(key) // 2
        if key_size not in algorithms.AES.key_sizes:
            raise ValueError(
                "Fernet key must be 32 or 48 or 64 url-safe"
                " base64-encoded bytes."
            )

        self._signing_key = key[:key_bytes]
        self._encryption_key = key[key_bytes:]
        self._backend = backend
        # Base class has an invalid version byte
        self._version = b"\x00"

    @classmethod
    def generate_key(cls, key_bits):
        if key_bits not in algorithms.AES.key_sizes:
            raise ValueError(
                "Fernet key must be 128 or 192 or 256 bits."
            )
        # Need random bytes for 2 keys at 8 bits/byte/key
        key_bytes = key_bits // 4
        return base64.urlsafe_b64encode(os.urandom(key_bytes))

    def encrypt(self, data):
        current_time = int(time.time())
        iv = os.urandom(16)
        return self._encrypt_from_parts(data, current_time, iv)

    def _encrypt_from_parts(self, data, current_time, iv):
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes.")

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CBC(iv), self._backend
        ).encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        basic_parts = (
            self._version + struct.pack(">Q", current_time) + iv + ciphertext
        )

        h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        h.update(basic_parts)
        hmac = h.finalize()
        return base64.urlsafe_b64encode(basic_parts + hmac)

    def decrypt(self, token, ttl=None):
        if not isinstance(token, bytes):
            raise TypeError("token must be bytes.")

        current_time = int(time.time())

        try:
            data = base64.urlsafe_b64decode(token)
        except (TypeError, binascii.Error):
            raise InvalidToken

        if not data or six.indexbytes(data, 0) != six.byte2int(self._version):
            raise InvalidToken

        try:
            timestamp, = struct.unpack(">Q", data[1:9])
        except struct.error:
            raise InvalidToken
        if ttl is not None:
            if timestamp + ttl < current_time:
                raise InvalidToken

            if current_time + _MAX_CLOCK_SKEW < timestamp:
                raise InvalidToken

        h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        h.update(data[:-32])
        try:
            h.verify(data[-32:])
        except InvalidSignature:
            raise InvalidToken

        iv = data[9:25]
        ciphertext = data[25:-32]
        decryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CBC(iv), self._backend
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


class MultiFernet(object):
    def __init__(self, fernets):
        fernets = list(fernets)
        if not fernets:
            raise ValueError(
                "MultiFernet requires at least one Fernet instance"
            )
        self._fernets = fernets

    def encrypt(self, msg):
        return self._fernets[0].encrypt(msg)

    def decrypt(self, msg, ttl=None):
        for f in self._fernets:
            try:
                return f.decrypt(msg, ttl)
            except InvalidToken:
                pass
        raise InvalidToken


class Fernet(FernetBase):
    """
    Standard Fernet using AES128 encryption.
    """

    def __init__(self, key, backend=None):
        key = base64.urlsafe_b64decode(key)
        if len(key) != 32:
            raise ValueError(
                "Fernet key must be 32 url-safe base64-encoded bytes."
            )
        super(self.__class__, self).__init__(key, backend)
        # Overwrite the version byte FernetBase's __init__ set
        self._version = b"\x80"

    @classmethod
    def generate_key(cls):
        return FernetBase.generate_key(128)


class ExtFernet192(FernetBase):
    """
    Extended version of Fernet using AES192 encryption.

    The version byte differs from standard Fernet to distinguish this format.
    The low 5 bits indicate the version of standard Fernet the extended version
    is based on, with 0x1 indicating Fernet version 0x80. The high 3 bits
    indicate the encryption key length, with binary 001 (0x1) indicating
    192-bit AES. This yields a version byte of 0x21 (binary 00100001).
    """

    def __init__(self, key, backend=None):
        key = base64.urlsafe_b64decode(key)
        if len(key) != 48:
            raise ValueError(
                "Fernet192 key must be 48 url-safe base64-encoded bytes."
            )
        super(self.__class__, self).__init__(key, backend)
        self._version = b"\x21"

    @classmethod
    def generate_key(cls):
        return FernetBase.generate_key(192)


class ExtFernet256(FernetBase):
    """
    Extended version of Fernet using AES256 encryption.

    The version byte differs from standard Fernet to distinguish this format.
    The low 5 bits indicate the version of standard Fernet the extended version
    is based on, with 0x1 indicating Fernet version 0x80. The high 3 bits
    indicate the encryption key length, with binary 010 (0x2) indicating
    256-bit AES. This yields a version byte of 0x41 (binary 01000001).
    """

    def __init__(self, key, backend=None):
        key = base64.urlsafe_b64decode(key)
        if len(key) != 64:
            raise ValueError(
                "Fernet256 key must be 64 url-safe base64-encoded bytes."
            )
        super(self.__class__, self).__init__(key, backend)
        self._version = b"\x41"

    @classmethod
    def generate_key(cls):
        return FernetBase.generate_key(256)
