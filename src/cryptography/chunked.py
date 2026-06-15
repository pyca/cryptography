# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import os

from cryptography import utils
from cryptography.exceptions import AlreadyFinalized, InvalidTag
from cryptography.hazmat.primitives import constant_time, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.utils import Buffer

# This implements the C2SP "chunked encryption" specification using its
# RECOMMENDED instantiation of SHA-256 and AES-128-GCM:
# https://github.com/C2SP/C2SP/blob/main/chunked-encryption.md

_CHUNK_SIZE = 16 * 1024
_KEY_LENGTH = 16
_NONCE_LENGTH = 12
_TAG_LENGTH = 16
_SALT_LENGTH = 24
_COMMITMENT_LENGTH = 32
_HEADER_LENGTH = _SALT_LENGTH + _COMMITMENT_LENGTH

# The length of a non-final ("full") AEAD ciphertext chunk. Every chunk but the
# last one encrypts exactly ``_CHUNK_SIZE`` bytes of plaintext.
_FULL_CIPHERTEXT_CHUNK = _CHUNK_SIZE + _TAG_LENGTH

# The maximum number of chunks a message may be split into (2**38), which caps
# the message size at 4 PiB - 1 byte.
_MAX_CHUNKS = 2**38

# "c2sp.org/chunked-encryption@v1+" || aead || 0x00, where aead is the name of
# the underlying AEAD from the IANA AEAD Algorithms registry.
_INFO_PREFIX = b"c2sp.org/chunked-encryption@v1+AEAD_AES_128_GCM\x00"


class InvalidChunk(Exception):
    pass


def _xor_nonce(base_nonce: bytes, chunk_number: int) -> bytes:
    counter = chunk_number.to_bytes(_NONCE_LENGTH, "big")
    return bytes(a ^ b for a, b in zip(base_nonce, counter))


class ChunkedEncryption:
    def __init__(self, key: bytes) -> None:
        utils._check_bytes("key", key)
        if len(key) != _KEY_LENGTH:
            raise ValueError(f"key must be {_KEY_LENGTH} bytes.")
        self._key = key

    @classmethod
    def generate_key(cls) -> bytes:
        return os.urandom(_KEY_LENGTH)

    def _derive(
        self, salt: bytes, context: bytes
    ) -> tuple[AESGCM, bytes, bytes]:
        hkdf = HKDFExpand(
            algorithm=hashes.SHA256(),
            length=_KEY_LENGTH + _NONCE_LENGTH + _COMMITMENT_LENGTH,
            info=_INFO_PREFIX + salt + context,
        )
        derived = hkdf.derive(self._key)
        key = derived[:_KEY_LENGTH]
        base_nonce = derived[_KEY_LENGTH : _KEY_LENGTH + _NONCE_LENGTH]
        commitment = derived[_KEY_LENGTH + _NONCE_LENGTH :]
        return AESGCM(key), base_nonce, commitment

    def encryptor(self, context: bytes = b"") -> _EncryptionStream:
        utils._check_bytes("context", context)
        salt = os.urandom(_SALT_LENGTH)
        aead, base_nonce, commitment = self._derive(salt, context)
        return _EncryptionStream(aead, base_nonce, salt + commitment)

    def decryptor(self, context: bytes = b"") -> _DecryptionStream:
        utils._check_bytes("context", context)
        return _DecryptionStream(self, context)


class _EncryptionStream:
    def __init__(self, aead: AESGCM, base_nonce: bytes, header: bytes) -> None:
        self._aead = aead
        self._base_nonce = base_nonce
        self._header = header
        self._buffer = bytearray()
        self._chunk_number = 0
        self._finalized = False

    def _take_header(self) -> bytes:
        header, self._header = self._header, b""
        return header

    def _seal_chunk(self, plaintext: bytes) -> bytes:
        if self._chunk_number >= _MAX_CHUNKS:
            raise OverflowError("Message is too long.")
        nonce = _xor_nonce(self._base_nonce, self._chunk_number)
        self._chunk_number += 1
        return self._aead.encrypt(nonce, plaintext, None)

    def update(self, data: Buffer) -> bytes:
        if self._finalized:
            raise AlreadyFinalized("Context was already finalized.")
        utils._check_byteslike("data", data)

        out = bytearray(self._take_header())
        self._buffer += data
        # Keep at least one byte buffered so that the final chunk, which
        # MUST be shorter than a full chunk, is emitted by finalize().
        while len(self._buffer) > _CHUNK_SIZE:
            out += self._seal_chunk(bytes(self._buffer[:_CHUNK_SIZE]))
            del self._buffer[:_CHUNK_SIZE]
        return bytes(out)

    def finalize(self) -> bytes:
        if self._finalized:
            raise AlreadyFinalized("Context was already finalized.")
        self._finalized = True

        out = bytearray(self._take_header())
        # The buffer holds between 0 and _CHUNK_SIZE bytes. If it is exactly
        # a full chunk it must be sealed as one, then an empty final chunk.
        if len(self._buffer) == _CHUNK_SIZE:
            out += self._seal_chunk(bytes(self._buffer))
            self._buffer.clear()
        out += self._seal_chunk(bytes(self._buffer))
        return bytes(out)


class _DecryptionStream:
    def __init__(self, scheme: ChunkedEncryption, context: bytes) -> None:
        self._scheme = scheme
        self._context = context
        self._aead: AESGCM | None = None
        self._base_nonce = b""
        self._buffer = bytearray()
        self._chunk_number = 0
        self._finalized = False

    def _open_chunk(self, ciphertext: bytes) -> bytes:
        assert self._aead is not None
        if self._chunk_number >= _MAX_CHUNKS:
            raise InvalidChunk
        nonce = _xor_nonce(self._base_nonce, self._chunk_number)
        try:
            plaintext = self._aead.decrypt(nonce, ciphertext, None)
        except InvalidTag:
            raise InvalidChunk
        self._chunk_number += 1
        return plaintext

    def _read_header(self) -> None:
        salt = bytes(self._buffer[:_SALT_LENGTH])
        commitment = bytes(self._buffer[_SALT_LENGTH:_HEADER_LENGTH])
        del self._buffer[:_HEADER_LENGTH]

        aead, base_nonce, expected = self._scheme._derive(salt, self._context)
        if not constant_time.bytes_eq(commitment, expected):
            raise InvalidChunk
        self._aead = aead
        self._base_nonce = base_nonce

    def update(self, data: Buffer) -> bytes:
        if self._finalized:
            raise AlreadyFinalized("Context was already finalized.")
        utils._check_byteslike("data", data)

        self._buffer += data
        if self._aead is None:
            if len(self._buffer) < _HEADER_LENGTH:
                return b""
            self._read_header()

        out = bytearray()
        # Keep at least one full chunk buffered: until we see more data we
        # can't tell whether it is a non-final chunk or the (shorter) final.
        while len(self._buffer) > _FULL_CIPHERTEXT_CHUNK:
            out += self._open_chunk(
                bytes(self._buffer[:_FULL_CIPHERTEXT_CHUNK])
            )
            del self._buffer[:_FULL_CIPHERTEXT_CHUNK]
        return bytes(out)

    def finalize(self) -> bytes:
        if self._finalized:
            raise AlreadyFinalized("Context was already finalized.")
        self._finalized = True

        if self._aead is None:
            # The header was never fully received.
            raise InvalidChunk

        # A valid final chunk is shorter than a full one (it carries fewer than
        # _CHUNK_SIZE plaintext bytes) and is at least a bare authentication
        # tag. Anything else means the message was truncated or corrupted.
        if not _TAG_LENGTH <= len(self._buffer) < _FULL_CIPHERTEXT_CHUNK:
            raise InvalidChunk
        return self._open_chunk(bytes(self._buffer))
