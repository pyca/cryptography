# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import base64
import binascii
import os
import struct
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC


class InvalidToken(Exception):
    pass


_MAX_CLOCK_SKEW = 60


class _Encryptor(object):
    def __init__(self, signing_key, encryption_key, backend):
        # Generate header string
        version = 0x80
        timestamp = int(time.time())
        iv = os.urandom(16)
        self._header = struct.pack('>BQ', version, timestamp) + iv
        self._started = False

        # Initialize HMAC, cipher and padder
        self._hmac = HMAC(signing_key, hashes.SHA256(), backend)
        self._padder = padding.PKCS7(algorithms.AES.block_size).padder()
        self._cipher = Cipher(
            algorithms.AES(encryption_key), modes.CBC(iv), backend
        ).encryptor()

    def update(self, data):
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes.")

        # Apply padding onto data
        data = self._padder.update(data)

        # Apply cipher onto data
        data = self._cipher.update(data)

        # Prepend header if this is the first call
        if not self._started:
            self._started = True
            data = self._header + data

        # Feed final data set to HMAC
        self._hmac.update(data)

        return data

    def finalize(self):
        # Finalize padder
        data = self._padder.finalize()

        # Cipher final padding data, then finalize cipher as well
        data = self._cipher.update(data) + self._cipher.finalize()

        # Feed final cipher data to HMAC, then finalize and append HMAC data
        self._hmac.update(data)
        data += self._hmac.finalize()

        self._started = False

        return data


class _Decryptor(object):
    def __init__(self, ttl, signing_key, encryption_key, backend):
        self._ttl = ttl

        self._encryption_key = encryption_key
        self._backend = backend

        self._time = int(time.time())
        self._header = bytes()
        self._buffer = bytearray()

        self._hmac = HMAC(signing_key, hashes.SHA256(), backend)
        self._padder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        self._cipher = None  # Requires IV from header

    def update(self, data):
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes.")

        if not self._cipher:
            # Wait for entire header to arrive before continuing
            if (len(self._header) + len(data)) < 25:
                self._header += data
                return
            else:
                data_header_end = 25 - len(self._header)
                self._header += data[0:data_header_end]
                data = data[data_header_end:]

            # Validate version
            if self._header[0:1] != b"\x80":
                raise InvalidToken

            # Validate timestamp
            try:
                timestamp, = struct.unpack(">Q", self._header[1:9])
            except struct.error:
                raise InvalidToken
            if self._ttl is not None:
                if timestamp + self._ttl < self._time:
                    raise InvalidToken

                if self._time + _MAX_CLOCK_SKEW < timestamp:
                    raise InvalidToken

            # Send header data to MAC
            self._hmac.update(self._header)

            # Create cipher using the given IV
            self._cipher = Cipher(
                algorithms.AES(self._encryption_key),
                modes.CBC(self._header[9:25]),
                self._backend
            ).decryptor()

        # At this point:
        #  - data will contain ciphertext and (possibly) the HMAC verify value
        #  - the header will have been stored in `self._header` and verified
        #  - `self._cipher` will have been initialized

        # Cop off the last 32 bytes as they may contain the HMAC verification
        self._buffer += data
        ciphertext = bytes(self._buffer[:-32])
        self._buffer = self._buffer[-32:]

        # Feed ciphertext to HMAC
        self._hmac.update(ciphertext)

        # Feed ciphertext to cipher
        plaintext_padded = self._cipher.update(ciphertext)

        # Feed ciphertext to unpadder
        plaintext = self._padder.update(plaintext_padded)

        # Return the plain text result
        return plaintext

    def finalize(self):
        if not self._cipher or len(self._buffer) < 32:
            raise InvalidToken

        # Finalize HMAC check
        try:
            self._hmac.verify(bytes(self._buffer))
        except InvalidSignature:
            raise InvalidToken

        # Finalize cipher processing
        try:
            plaintext_padded = self._cipher.finalize()
        except ValueError:
            raise InvalidToken

        # Finalize unpadder processing
        plaintext = self._padder.update(plaintext_padded)
        try:
            plaintext += self._padder.finalize()
        except ValueError:
            raise InvalidToken

        return plaintext


class Fernet(object):
    def __init__(self, key, backend=None):
        if backend is None:
            backend = default_backend()

        key = base64.urlsafe_b64decode(key)
        if len(key) != 32:
            raise ValueError(
                "Fernet key must be 32 url-safe base64-encoded bytes."
            )

        self._signing_key = key[:16]
        self._encryption_key = key[16:]
        self._backend = backend

    @classmethod
    def generate_key(cls):
        return base64.urlsafe_b64encode(os.urandom(32))

    def encryptor(self):
        return _Encryptor(self._signing_key,
                          self._encryption_key,
                          self._backend)

    def encrypt(self, data):
        encryptor = self.encryptor()
        return base64.urlsafe_b64encode(
            encryptor.update(data) + encryptor.finalize()
        )

    def decryptor(self, ttl=None):
        return _Decryptor(ttl,
                          self._signing_key,
                          self._encryption_key,
                          self._backend)

    def decrypt(self, token, ttl=None):
        if not isinstance(token, bytes):
            raise TypeError("token must be bytes.")

        try:
            data = base64.urlsafe_b64decode(token)
        except (TypeError, binascii.Error):
            raise InvalidToken

        decryptor = self.decryptor(ttl)
        return decryptor.update(data) + decryptor.finalize()


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
