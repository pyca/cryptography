# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import base64
import binascii
import os
from pathlib import Path
import struct
import time
from typing import Iterator

import six

from cryptography import utils
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC


class InvalidToken(Exception):
    pass


_MAX_CLOCK_SKEW = 60


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

    def encrypt(self, data):
        current_time = int(time.time())
        iv = os.urandom(16)
        return self._encrypt_from_parts(data, current_time, iv)

    def _encrypt_from_parts(self, data, current_time, iv):
        utils._check_bytes("data", data)

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CBC(iv), self._backend
        ).encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        basic_parts = (
            b"\x80" + struct.pack(">Q", current_time) + iv + ciphertext
        )

        h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        h.update(basic_parts)
        hmac = h.finalize()
        return base64.urlsafe_b64encode(basic_parts + hmac)

    def decrypt(self, token, ttl=None):
        timestamp, data = Fernet._get_unverified_token_data(token)
        return self._decrypt_data(data, timestamp, ttl)

    def extract_timestamp(self, token):
        timestamp, data = Fernet._get_unverified_token_data(token)
        # Verify the token was not tampered with.
        self._verify_signature(data)
        return timestamp

    @staticmethod
    def _get_unverified_token_data(token):
        utils._check_bytes("token", token)
        try:
            data = base64.urlsafe_b64decode(token)
        except (TypeError, binascii.Error):
            raise InvalidToken

        if not data or six.indexbytes(data, 0) != 0x80:
            raise InvalidToken

        try:
            timestamp, = struct.unpack(">Q", data[1:9])
        except struct.error:
            raise InvalidToken
        return timestamp, data

    def _verify_signature(self, data):
        h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        h.update(data[:-32])
        try:
            h.verify(data[-32:])
        except InvalidSignature:
            raise InvalidToken

    def _decrypt_data(self, data, timestamp, ttl):
        current_time = int(time.time())
        if ttl is not None:
            if timestamp + ttl < current_time:
                raise InvalidToken

            if current_time + _MAX_CLOCK_SKEW < timestamp:
                raise InvalidToken

        self._verify_signature(data)

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

    def rotate(self, msg):
        timestamp, data = Fernet._get_unverified_token_data(msg)
        for f in self._fernets:
            try:
                p = f._decrypt_data(data, timestamp, None)
                break
            except InvalidToken:
                pass
        else:
            raise InvalidToken

        iv = os.urandom(16)
        return self._fernets[0]._encrypt_from_parts(p, timestamp, iv)

    def decrypt(self, msg, ttl=None):
        for f in self._fernets:
            try:
                return f.decrypt(msg, ttl)
            except InvalidToken:
                pass
        raise InvalidToken


class StreamFernet(object):
    """
    Stream version of Fernet.

    The enrypted stream looks like:
      magic + timestamp + nonce + ciphertext + HMAC signature
    """

    magic = b'\x8a'

    def __init__(self, key: bytes):
        backend = default_backend()

        key = base64.urlsafe_b64decode(key)
        if len(key) != 32:
            raise ValueError(
                'Key must be 32 url-safe base64-encoded bytes.'
            )

        self._signing_key = key[:16]
        self._encryption_key = key[16:]
        self._backend = backend

    @classmethod
    def generate_key(cls) -> bytes:
        return base64.urlsafe_b64encode(os.urandom(32))

    def encrypt_file(self, src: Path, dst: Path):
        with open(src, 'rb') as s, open(dst, 'wb') as d:
            ciphertext = self.encrypt_stream(iter(lambda: s.read(4096), b''))
            for data in ciphertext:
                if data:
                    d.write(data)

    def encrypt_stream(self, src: Iterator[bytes]) -> Iterator[bytes]:
        nonce = os.urandom(16)
        encryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CTR(
                nonce), self._backend
        ).encryptor()
        hmac = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        # Format header
        current_time = int(time.time())
        basic_parts = (
            self.magic + struct.pack('>Q', current_time) + nonce
        )
        hmac.update(basic_parts) # The header is part of signature
        yield basic_parts
        # Encryption phase
        for data in src:
            ciphertext = encryptor.update(data)
            hmac.update(ciphertext)
            yield ciphertext
        # Process last bytes if any
        fin = encryptor.finalize()
        hmac.update(fin)
        yield fin
        # Write HMAC
        yield hmac.finalize()

    def decrypt_file(self, src: Path, dst: Path, ttl: int = None):
        with open(src, 'rb') as s, open(dst, 'wb') as d:
            plaintext = self.decrypt_stream(
                iter(lambda: s.read(4096), b''), ttl)
            for data in plaintext:
                if data:
                    d.write(data)

    def decrypt_stream(self, src: Iterator[bytes], ttl: int = None) -> Iterator[bytes]:
        # Use internal buffer as cache. This is needed because iterator could
        # return too small chunks of data.
        buffer = b''
        # Collect enougth bytes for header
        for data in src:
            buffer += data
            if len(buffer) < 25:
                yield b''
        self._check_header(buffer, ttl)
        # Prepare HMAC checking
        hmac = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        # Prepare decryptor
        decryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CTR(buffer[9:25]),
            self._backend).decryptor()
        # Decryption phase
        hmac.update(buffer[0:25])  # Header is under HMAC too
        buffer = buffer[25:]      # Drop header. Leave body and HMAC.
        # In cycle process previous block of data if current is large enougth
        # to store HMAC. Otherwise append current block of data to buffer and
        # wait for enother block of ciphertext.
        for data in src:
            if len(data) < 32:
                buffer += data
                yield b''
            hmac.update(buffer)
            yield decryptor.update(buffer)
            buffer = data
        # At this point last 32 bytes should countain HMAC
        signature = buffer[-32:]
        # And signature is not part of HMAC check
        buffer = buffer[:-32]
        hmac.update(buffer)
        try:
            plaintext = decryptor.update(buffer) + decryptor.finalize()
            yield plaintext
        except ValueError:
            raise InvalidToken
        # Check HMAC
        try:
            hmac.verify(signature)
        except InvalidSignature:
            raise InvalidToken

    @staticmethod
    def _get_timestamp(data: bytes) -> int:
        try:
            timestamp, = struct.unpack('>Q', data[1:9])
        except struct.error:
            raise InvalidToken
        return timestamp

    @classmethod
    def _check_header(cls, buffer: bytes, ttl: int = None):
        if len(buffer) < 9:
            raise InvalidToken
        # Check magic number
        if buffer[0:1] != cls.magic:
            raise InvalidToken
        # Check timestamp
        if ttl is not None:
            timestamp = cls._get_timestamp(buffer[1:9])
            current_time = int(time.time())
            if timestamp + ttl < current_time:
                raise InvalidToken

            if current_time + _MAX_CLOCK_SKEW < timestamp:
                raise InvalidToken
