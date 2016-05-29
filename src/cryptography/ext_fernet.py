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


class ExtFernet192(FernetBase):
    """
    Extended version of Fernet using AES192 encryption.

    The version byte differs from standard Fernet to distinguish this format. The low
    5 bits indicate the version of standard Fernet the extended version is based on,
    with 0x1 indicating Fernet version 0x80. The high 3 bits indicate the encryption
    key length, with binary 001 (0x1) indicating 192-bit AES. This yields a version byte
    of 0x21 (binary 00100001).
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

    The version byte differs from standard Fernet to distinguish this format. The low
    5 bits indicate the version of standard Fernet the extended version is based on,
    with 0x1 indicating Fernet version 0x80. The high 3 bits indicate the encryption
    key length, with binary 010 (0x2) indicating 192-bit AES. This yields a version byte
    of 0x41 (binary 01000001).
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
