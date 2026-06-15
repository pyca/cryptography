# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import os
from unittest import mock

import pytest

from cryptography.chunked import ChunkedEncryption, InvalidChunk
from cryptography.exceptions import AlreadyFinalized

_CHUNK_SIZE = 16 * 1024
_HEADER_LENGTH = 24 + 32
_TAG_LENGTH = 16

# Deterministic known-answer vectors, generated with a fixed key and salt by
# patching os.urandom. They lock the c2sp.org/chunked-encryption@v1 wire format
# (SHA-256 + AES-128-GCM) against regressions.
_KEY = bytes(range(16))
_SALT = bytes(range(100, 124))
_KAT = [
    # (plaintext, context, ciphertext)
    (
        b"",
        b"",
        bytes.fromhex(
            "6465666768696a6b6c6d6e6f707172737475767778797a7b"
            "75e15016f9c6148f4187e0d5a8bae956547f6cdb0bbe1868"
            "93f89be78b2eb99e24b59214be2555c6be3d9c47e69bb360"
        ),
    ),
    (
        b"hello world",
        b"",
        bytes.fromhex(
            "6465666768696a6b6c6d6e6f707172737475767778797a7b"
            "75e15016f9c6148f4187e0d5a8bae956547f6cdb0bbe1868"
            "93f89be78b2eb99e6d10d8998e07bb7c7af28058b509d8f3"
            "18f3997000a8fbc9b3b1b1"
        ),
    ),
    (
        b"hello world",
        b"context",
        bytes.fromhex(
            "6465666768696a6b6c6d6e6f707172737475767778797a7b"
            "711dfd6fbb3120e7395b4789dab0ceeb762130ac47db988d"
            "757715173d00543a48b27223e04af784859ccd37e9a68020"
            "556e4e0e12b66b3fe91241"
        ),
    ),
]


def _encrypt(scheme, data, context=b"", chunk=None):
    encryptor = scheme.encryptor(context)
    out = bytearray()
    if chunk is None:
        out += encryptor.update(data)
    else:
        for i in range(0, len(data), chunk):
            out += encryptor.update(data[i : i + chunk])
    out += encryptor.finalize()
    return bytes(out)


def _decrypt(scheme, ciphertext, context=b"", chunk=None):
    decryptor = scheme.decryptor(context)
    out = bytearray()
    if chunk is None:
        out += decryptor.update(ciphertext)
    else:
        for i in range(0, len(ciphertext), chunk):
            out += decryptor.update(ciphertext[i : i + chunk])
    out += decryptor.finalize()
    return bytes(out)


class TestChunkedEncryption:
    def test_generate_key(self):
        key = ChunkedEncryption.generate_key()
        assert isinstance(key, bytes)
        assert len(key) == 16
        assert ChunkedEncryption.generate_key() != key

    @pytest.mark.parametrize("key", [b"", b"\x00" * 15, b"\x00" * 32])
    def test_invalid_key_length(self, key):
        with pytest.raises(ValueError):
            ChunkedEncryption(key)

    def test_key_not_bytes(self):
        with pytest.raises(TypeError):
            ChunkedEncryption("0" * 16)  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "size",
        [
            0,
            1,
            100,
            _CHUNK_SIZE - 1,
            _CHUNK_SIZE,
            _CHUNK_SIZE + 1,
            2 * _CHUNK_SIZE,
            2 * _CHUNK_SIZE + 1,
            5 * _CHUNK_SIZE + 123,
        ],
    )
    def test_round_trip(self, size):
        scheme = ChunkedEncryption(ChunkedEncryption.generate_key())
        data = os.urandom(size)
        ciphertext = _encrypt(scheme, data)
        assert _decrypt(scheme, ciphertext) == data

    @pytest.mark.parametrize("write_chunk", [1, 7, 4096, _CHUNK_SIZE, 40000])
    @pytest.mark.parametrize("read_chunk", [1, 13, _CHUNK_SIZE, 40000])
    def test_round_trip_streaming_boundaries(self, write_chunk, read_chunk):
        scheme = ChunkedEncryption(ChunkedEncryption.generate_key())
        data = os.urandom(2 * _CHUNK_SIZE + 500)
        ciphertext = _encrypt(scheme, data, chunk=write_chunk)
        assert _decrypt(scheme, ciphertext, chunk=read_chunk) == data

    def test_streaming_matches_one_shot(self):
        scheme = ChunkedEncryption(ChunkedEncryption.generate_key())
        data = os.urandom(3 * _CHUNK_SIZE + 7)
        with mock.patch("os.urandom", lambda n: bytes(range(n))):
            one_shot = _encrypt(scheme, data)
            streamed = _encrypt(scheme, data, chunk=1000)
        assert one_shot == streamed

    def test_context_must_match(self):
        scheme = ChunkedEncryption(ChunkedEncryption.generate_key())
        ciphertext = _encrypt(scheme, b"secret", context=b"a")
        assert _decrypt(scheme, ciphertext, context=b"a") == b"secret"
        with pytest.raises(InvalidChunk):
            _decrypt(scheme, ciphertext, context=b"b")
        with pytest.raises(InvalidChunk):
            _decrypt(scheme, ciphertext, context=b"")

    def test_wrong_key(self):
        scheme = ChunkedEncryption(ChunkedEncryption.generate_key())
        other = ChunkedEncryption(ChunkedEncryption.generate_key())
        ciphertext = _encrypt(scheme, b"data")
        with pytest.raises(InvalidChunk):
            _decrypt(other, ciphertext)

    def test_header_layout(self):
        scheme = ChunkedEncryption(ChunkedEncryption.generate_key())
        data = b"hello world"
        ciphertext = _encrypt(scheme, data)
        # salt(24) + commitment(32) + single chunk (data + tag)
        assert len(ciphertext) == _HEADER_LENGTH + len(data) + _TAG_LENGTH

    def test_full_message_appends_empty_chunk(self):
        scheme = ChunkedEncryption(ChunkedEncryption.generate_key())
        data = os.urandom(_CHUNK_SIZE)
        ciphertext = _encrypt(scheme, data)
        # one full chunk + one empty final chunk, each with a tag
        expected = _HEADER_LENGTH + (_CHUNK_SIZE + _TAG_LENGTH) + _TAG_LENGTH
        assert len(ciphertext) == expected
        assert _decrypt(scheme, ciphertext) == data

    @pytest.mark.parametrize(("plaintext", "context", "ciphertext"), _KAT)
    def test_known_answers(self, plaintext, context, ciphertext):
        scheme = ChunkedEncryption(_KEY)
        with mock.patch("os.urandom", lambda n: _SALT):
            assert _encrypt(scheme, plaintext, context=context) == ciphertext
        assert _decrypt(scheme, ciphertext, context=context) == plaintext

    def test_tampering_detected(self):
        scheme = ChunkedEncryption(ChunkedEncryption.generate_key())
        ciphertext = bytearray(_encrypt(scheme, b"x" * 50))
        ciphertext[-1] ^= 1
        with pytest.raises(InvalidChunk):
            _decrypt(scheme, bytes(ciphertext))

    def test_truncated_final_chunk_detected(self):
        # A message that is an exact multiple of the chunk size ends with an
        # empty final chunk. Dropping it must be rejected.
        scheme = ChunkedEncryption(ChunkedEncryption.generate_key())
        ciphertext = _encrypt(scheme, os.urandom(_CHUNK_SIZE))
        with pytest.raises(InvalidChunk):
            _decrypt(scheme, ciphertext[:-_TAG_LENGTH])

    def test_truncated_to_full_chunk_detected(self):
        scheme = ChunkedEncryption(ChunkedEncryption.generate_key())
        ciphertext = _encrypt(scheme, os.urandom(2 * _CHUNK_SIZE + 5))
        # Keep only the header and the first full chunk.
        truncated = ciphertext[: _HEADER_LENGTH + _CHUNK_SIZE + _TAG_LENGTH]
        with pytest.raises(InvalidChunk):
            _decrypt(scheme, truncated)

    def test_appended_data_detected(self):
        scheme = ChunkedEncryption(ChunkedEncryption.generate_key())
        ciphertext = _encrypt(scheme, b"short")
        with pytest.raises(InvalidChunk):
            _decrypt(scheme, ciphertext + b"\x00" * 10)

    def test_truncated_header_detected(self):
        scheme = ChunkedEncryption(ChunkedEncryption.generate_key())
        decryptor = scheme.decryptor()
        decryptor.update(b"\x00" * (_HEADER_LENGTH - 1))
        with pytest.raises(InvalidChunk):
            decryptor.finalize()

    def test_encryptor_already_finalized(self):
        scheme = ChunkedEncryption(ChunkedEncryption.generate_key())
        encryptor = scheme.encryptor()
        encryptor.update(b"data")
        encryptor.finalize()
        with pytest.raises(AlreadyFinalized):
            encryptor.update(b"more")
        with pytest.raises(AlreadyFinalized):
            encryptor.finalize()

    def test_decryptor_already_finalized(self):
        scheme = ChunkedEncryption(ChunkedEncryption.generate_key())
        ciphertext = _encrypt(scheme, b"data")
        decryptor = scheme.decryptor()
        decryptor.update(ciphertext)
        decryptor.finalize()
        with pytest.raises(AlreadyFinalized):
            decryptor.update(ciphertext)
        with pytest.raises(AlreadyFinalized):
            decryptor.finalize()

    def test_update_accepts_bytes_like(self):
        scheme = ChunkedEncryption(ChunkedEncryption.generate_key())
        data = bytearray(b"a memoryview works too")
        ciphertext = _encrypt(scheme, memoryview(data))
        assert _decrypt(scheme, bytearray(ciphertext)) == data

    @pytest.mark.parametrize("bad", ["str", 123, None])
    def test_update_rejects_non_bytes_like(self, bad):
        scheme = ChunkedEncryption(ChunkedEncryption.generate_key())
        with pytest.raises(TypeError):
            scheme.encryptor().update(bad)

    def test_context_must_be_bytes(self):
        scheme = ChunkedEncryption(ChunkedEncryption.generate_key())
        with pytest.raises(TypeError):
            scheme.encryptor("ctx")  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            scheme.decryptor("ctx")  # type: ignore[arg-type]
