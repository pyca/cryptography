# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import io
import mmap
import os

import pytest

from cryptography.cobblestone import (
    Cobblestone128Decryptor,
    Cobblestone128Encryptor,
    Cobblestone256Decryptor,
    Cobblestone256Encryptor,
)
from cryptography.exceptions import AlreadyFinalized, InvalidTag

CHUNK_SIZE = 16 * 1024
TAG_LEN = 16
WIRE_CHUNK_SIZE = CHUNK_SIZE + TAG_LEN
SALT_LEN = 24
COMMITMENT_LEN = 32
HEADER_LEN = SALT_LEN + COMMITMENT_LEN

VARIANTS = [
    pytest.param(
        (Cobblestone128Encryptor, Cobblestone128Decryptor, 16),
        id="cobblestone128",
    ),
    pytest.param(
        (Cobblestone256Encryptor, Cobblestone256Decryptor, 32),
        id="cobblestone256",
    ),
]


def _encrypt_all(encryptor_cls, key: bytes, context: bytes, plaintext: bytes):
    enc = encryptor_cls(key, context)
    return enc.update(plaintext) + enc.finalize()


def _decrypt_all(decryptor_cls, key: bytes, context: bytes, ciphertext: bytes):
    dec = decryptor_cls(key, context)
    return dec.update(ciphertext) + dec.finalize()


MESSAGE_LENGTHS = [
    0,
    1,
    57,
    CHUNK_SIZE - 1,
    CHUNK_SIZE,
    CHUNK_SIZE + 1,
    20 * 1024,
    2 * CHUNK_SIZE - 1,
    2 * CHUNK_SIZE,
    2 * CHUNK_SIZE + 1,
    3 * CHUNK_SIZE + 5000,
]


@pytest.mark.parametrize("variant", VARIANTS)
class TestCobblestone:
    @pytest.mark.parametrize("length", MESSAGE_LENGTHS)
    def test_round_trip(self, variant, length):
        encryptor_cls, decryptor_cls, _ = variant
        key = encryptor_cls.generate_key()
        context = b"test context"
        plaintext = os.urandom(length)

        ciphertext = _encrypt_all(encryptor_cls, key, context, plaintext)
        n_chunks = length // CHUNK_SIZE + 1
        assert len(ciphertext) == HEADER_LEN + length + n_chunks * TAG_LEN
        assert (
            _decrypt_all(decryptor_cls, key, context, ciphertext) == plaintext
        )

    @pytest.mark.parametrize("piece_size", [1, 57, 1024, 16384, 16400])
    def test_streaming(self, variant, piece_size):
        encryptor_cls, decryptor_cls, _ = variant
        key = encryptor_cls.generate_key()
        context = b""
        plaintext = os.urandom(2 * CHUNK_SIZE + 12345)

        enc = encryptor_cls(key, context)
        ciphertext = b""
        for i in range(0, len(plaintext), piece_size):
            ciphertext += enc.update(plaintext[i : i + piece_size])
        ciphertext += enc.finalize()
        # The result matches a single-shot encryption's structure, and
        # decrypts to the plaintext regardless of how the ciphertext is
        # split up.
        assert len(ciphertext) == HEADER_LEN + len(plaintext) + 3 * TAG_LEN

        dec = decryptor_cls(key, context)
        decrypted = b""
        for i in range(0, len(ciphertext), piece_size):
            decrypted += dec.update(ciphertext[i : i + piece_size])
        decrypted += dec.finalize()
        assert decrypted == plaintext

    def test_empty_message(self, variant):
        encryptor_cls, decryptor_cls, _ = variant
        key = encryptor_cls.generate_key()
        enc = encryptor_cls(key, b"ctx")
        ciphertext = enc.finalize()
        assert len(ciphertext) == HEADER_LEN + TAG_LEN
        assert _decrypt_all(decryptor_cls, key, b"ctx", ciphertext) == b""

    def test_update_with_empty_data_emits_header(self, variant):
        encryptor_cls, decryptor_cls, _ = variant
        key = encryptor_cls.generate_key()
        enc = encryptor_cls(key, b"")
        header = enc.update(b"")
        assert len(header) == HEADER_LEN
        assert enc.update(b"") == b""
        ciphertext = header + enc.finalize()
        assert _decrypt_all(decryptor_cls, key, b"", ciphertext) == b""

    def test_exact_chunk_boundary_has_empty_final_chunk(self, variant):
        encryptor_cls, decryptor_cls, _ = variant
        key = encryptor_cls.generate_key()
        plaintext = os.urandom(CHUNK_SIZE)
        ciphertext = _encrypt_all(encryptor_cls, key, b"", plaintext)
        # One full chunk plus an empty final chunk.
        assert len(ciphertext) == HEADER_LEN + WIRE_CHUNK_SIZE + TAG_LEN
        assert _decrypt_all(decryptor_cls, key, b"", ciphertext) == plaintext

    def test_decrypter_streams_plaintext_incrementally(self, variant):
        encryptor_cls, decryptor_cls, _ = variant
        key = encryptor_cls.generate_key()
        plaintext = os.urandom(3 * CHUNK_SIZE)
        ciphertext = _encrypt_all(encryptor_cls, key, b"", plaintext)

        dec = decryptor_cls(key, b"")
        out = dec.update(ciphertext[: HEADER_LEN + WIRE_CHUNK_SIZE])
        assert out == plaintext[:CHUNK_SIZE]
        out = dec.update(ciphertext[HEADER_LEN + WIRE_CHUNK_SIZE :])
        assert out == plaintext[CHUNK_SIZE:]
        assert dec.finalize() == b""

    def test_wrong_key(self, variant):
        encryptor_cls, decryptor_cls, _ = variant
        key = encryptor_cls.generate_key()
        ciphertext = _encrypt_all(encryptor_cls, key, b"", b"message")
        dec = decryptor_cls(encryptor_cls.generate_key(), b"")
        with pytest.raises(InvalidTag):
            dec.update(ciphertext)

    def test_wrong_context(self, variant):
        encryptor_cls, decryptor_cls, _ = variant
        key = encryptor_cls.generate_key()
        ciphertext = _encrypt_all(encryptor_cls, key, b"context a", b"msg")
        dec = decryptor_cls(key, b"context b")
        with pytest.raises(InvalidTag):
            dec.update(ciphertext)

    @pytest.mark.parametrize(
        "position",
        [
            0,  # salt
            SALT_LEN,  # commitment
            HEADER_LEN,  # first chunk ciphertext
            HEADER_LEN + WIRE_CHUNK_SIZE - 1,  # first chunk tag
            HEADER_LEN + WIRE_CHUNK_SIZE + 3,  # final chunk
        ],
    )
    def test_tampering_detected(self, variant, position):
        encryptor_cls, decryptor_cls, _ = variant
        key = encryptor_cls.generate_key()
        plaintext = os.urandom(CHUNK_SIZE + 100)
        ciphertext = bytearray(
            _encrypt_all(encryptor_cls, key, b"", plaintext)
        )
        ciphertext[position] ^= 1

        dec = decryptor_cls(key, b"")
        with pytest.raises(InvalidTag):
            dec.update(bytes(ciphertext))
            dec.finalize()

    def test_swapped_chunks_detected(self, variant):
        encryptor_cls, decryptor_cls, _ = variant
        key = encryptor_cls.generate_key()
        plaintext = os.urandom(2 * CHUNK_SIZE + 100)
        ciphertext = _encrypt_all(encryptor_cls, key, b"", plaintext)

        chunk0_start = HEADER_LEN
        chunk1_start = HEADER_LEN + WIRE_CHUNK_SIZE
        chunk2_start = HEADER_LEN + 2 * WIRE_CHUNK_SIZE
        swapped = (
            ciphertext[:HEADER_LEN]
            + ciphertext[chunk1_start:chunk2_start]
            + ciphertext[chunk0_start:chunk1_start]
            + ciphertext[chunk2_start:]
        )
        dec = decryptor_cls(key, b"")
        with pytest.raises(InvalidTag):
            dec.update(swapped)

    @pytest.mark.parametrize(
        "length",
        [
            0,
            1,
            HEADER_LEN - 1,
            HEADER_LEN,  # no final chunk at all
            HEADER_LEN + TAG_LEN - 1,  # final chunk shorter than its tag
            HEADER_LEN + WIRE_CHUNK_SIZE,  # ends on a chunk boundary
            HEADER_LEN + WIRE_CHUNK_SIZE + TAG_LEN - 1,
        ],
    )
    def test_truncation_detected(self, variant, length):
        encryptor_cls, decryptor_cls, _ = variant
        key = encryptor_cls.generate_key()
        plaintext = os.urandom(CHUNK_SIZE + 100)
        ciphertext = _encrypt_all(encryptor_cls, key, b"", plaintext)

        dec = decryptor_cls(key, b"")
        with pytest.raises(InvalidTag):
            dec.update(ciphertext[:length])
            dec.finalize()

    def test_extension_detected(self, variant):
        encryptor_cls, decryptor_cls, _ = variant
        key = encryptor_cls.generate_key()
        ciphertext = _encrypt_all(encryptor_cls, key, b"", b"message")

        dec = decryptor_cls(key, b"")
        with pytest.raises(InvalidTag):
            dec.update(ciphertext + b"extra garbage bytes!")
            dec.finalize()

    def test_ciphertexts_are_randomized(self, variant):
        encryptor_cls, _, _ = variant
        key = encryptor_cls.generate_key()
        assert _encrypt_all(encryptor_cls, key, b"", b"data") != _encrypt_all(
            encryptor_cls, key, b"", b"data"
        )

    def test_update_into(self, variant):
        encryptor_cls, decryptor_cls, _ = variant
        key = encryptor_cls.generate_key()
        plaintext = os.urandom(CHUNK_SIZE + 100)

        enc = encryptor_cls(key, b"")
        buf = bytearray(HEADER_LEN + 2 * WIRE_CHUNK_SIZE)
        n = enc.update_into(plaintext, buf)
        assert n == HEADER_LEN + WIRE_CHUNK_SIZE
        ciphertext = bytes(buf[:n]) + enc.finalize()
        assert _decrypt_all(decryptor_cls, key, b"", ciphertext) == plaintext

        dec = decryptor_cls(key, b"")
        out = bytearray(2 * CHUNK_SIZE)
        n = dec.update_into(ciphertext, out)
        assert n == CHUNK_SIZE
        assert bytes(out[:n]) + dec.finalize() == plaintext

    def test_update_into_accepts_larger_buffer(self, variant):
        encryptor_cls, decryptor_cls, _ = variant
        key = encryptor_cls.generate_key()
        enc = encryptor_cls(key, b"")
        buf = bytearray(10 * WIRE_CHUNK_SIZE)
        n = enc.update_into(b"abc", buf)
        assert n == HEADER_LEN
        ciphertext = bytes(buf[:n]) + enc.finalize()
        assert _decrypt_all(decryptor_cls, key, b"", ciphertext) == b"abc"

    def test_update_into_buffer_too_small(self, variant):
        encryptor_cls, decryptor_cls, _ = variant
        key = encryptor_cls.generate_key()
        enc = encryptor_cls(key, b"")
        with pytest.raises(ValueError, match="buffer must be at least"):
            enc.update_into(b"abc", bytearray(HEADER_LEN - 1))
        # The context remains usable after the failed call.
        ciphertext = enc.update(b"abc") + enc.finalize()

        dec = decryptor_cls(key, b"")
        with pytest.raises(ValueError, match="buffer must be at least"):
            dec.update_into(
                ciphertext + bytes(WIRE_CHUNK_SIZE), bytearray(CHUNK_SIZE - 1)
            )
        assert dec.update(ciphertext) == b""
        assert dec.finalize() == b"abc"

    def test_update_into_zero_output(self, variant):
        encryptor_cls, decryptor_cls, _ = variant
        key = encryptor_cls.generate_key()
        dec = decryptor_cls(key, b"")
        assert dec.update_into(b"", bytearray(0)) == 0

    def test_use_after_finalize(self, variant):
        encryptor_cls, decryptor_cls, _ = variant
        key = encryptor_cls.generate_key()
        enc = encryptor_cls(key, b"")
        ciphertext = enc.update(b"data") + enc.finalize()
        with pytest.raises(AlreadyFinalized):
            enc.update(b"more")
        with pytest.raises(AlreadyFinalized):
            enc.update_into(b"more", bytearray(WIRE_CHUNK_SIZE))
        with pytest.raises(AlreadyFinalized):
            enc.finalize()

        dec = decryptor_cls(key, b"")
        dec.update(ciphertext)
        dec.finalize()
        with pytest.raises(AlreadyFinalized):
            dec.update(b"more")
        with pytest.raises(AlreadyFinalized):
            dec.update_into(b"more", bytearray(WIRE_CHUNK_SIZE))
        with pytest.raises(AlreadyFinalized):
            dec.finalize()

    def test_decryptor_unusable_after_invalid_tag(self, variant):
        encryptor_cls, decryptor_cls, _ = variant
        key = encryptor_cls.generate_key()
        ciphertext = bytearray(_encrypt_all(encryptor_cls, key, b"", b"data"))
        ciphertext[-1] ^= 1

        dec = decryptor_cls(key, b"")
        dec.update(bytes(ciphertext))
        with pytest.raises(InvalidTag):
            dec.finalize()
        # All subsequent operations fail.
        with pytest.raises(AlreadyFinalized):
            dec.update(b"")
        with pytest.raises(AlreadyFinalized):
            dec.finalize()

    def test_decryptor_update_into_unusable_after_invalid_tag(self, variant):
        encryptor_cls, decryptor_cls, _ = variant
        key = encryptor_cls.generate_key()
        plaintext = os.urandom(CHUNK_SIZE + 100)
        ciphertext = bytearray(
            _encrypt_all(encryptor_cls, key, b"", plaintext)
        )
        ciphertext[HEADER_LEN] ^= 1  # corrupt the first full chunk

        dec = decryptor_cls(key, b"")
        buf = bytearray(2 * CHUNK_SIZE)
        with pytest.raises(InvalidTag):
            dec.update_into(bytes(ciphertext), buf)
        # All subsequent operations fail.
        with pytest.raises(AlreadyFinalized):
            dec.update_into(b"", buf)
        with pytest.raises(AlreadyFinalized):
            dec.finalize()

    def test_finalize_only_decryptor_rejects_empty_stream(self, variant):
        encryptor_cls, decryptor_cls, _ = variant
        key = encryptor_cls.generate_key()
        dec = decryptor_cls(key, b"")
        with pytest.raises(InvalidTag):
            dec.finalize()

    def test_generate_key(self, variant):
        encryptor_cls, _, key_len = variant
        key = encryptor_cls.generate_key()
        assert isinstance(key, bytes)
        assert len(key) == key_len
        assert encryptor_cls.generate_key() != encryptor_cls.generate_key()

    def test_invalid_key_size(self, variant):
        encryptor_cls, decryptor_cls, key_len = variant
        for length in [0, key_len - 1, key_len + 1, 64]:
            with pytest.raises(ValueError):
                encryptor_cls(b"\x00" * length, b"")
            with pytest.raises(ValueError):
                decryptor_cls(b"\x00" * length, b"")

    def test_invalid_types(self, variant):
        encryptor_cls, decryptor_cls, _ = variant
        key = encryptor_cls.generate_key()
        with pytest.raises(TypeError):
            encryptor_cls("not bytes", b"")
        with pytest.raises(TypeError):
            encryptor_cls(key, "not bytes")
        with pytest.raises(TypeError):
            decryptor_cls("not bytes", b"")
        enc = encryptor_cls(key, b"")
        with pytest.raises(TypeError):
            enc.update("not bytes")
        with pytest.raises(TypeError):
            enc.update_into(b"", b"immutable")

    def test_accepts_buffers(self, variant):
        encryptor_cls, decryptor_cls, _ = variant
        key = bytearray(encryptor_cls.generate_key())
        plaintext = os.urandom(1000)
        enc = encryptor_cls(key, memoryview(b"ctx"))
        ciphertext = enc.update(memoryview(plaintext)) + enc.finalize()
        dec = decryptor_cls(memoryview(bytes(key)), bytearray(b"ctx"))
        assert dec.update(bytearray(ciphertext)) + dec.finalize() == plaintext


MAX_CHUNK_COUNT = 1 << 38


class _RangeFetcher:
    """A minimal seek()/read() source, standing in for remote range fetches."""

    def __init__(self, data: bytes, none_at_eof: bool = False):
        self._data = bytes(data)
        self._pos = 0
        self.reads = 0
        # Some streams return None (rather than b"") to signal no data.
        self._none_at_eof = none_at_eof

    def seek(self, offset, whence=0):
        assert whence == 0
        self._pos = offset
        return self._pos

    def read(self, size):
        self.reads += 1
        chunk = self._data[self._pos : self._pos + size]
        self._pos += len(chunk)
        if not chunk and self._none_at_eof:
            return None
        return chunk


def _buffer_and_filelike_sources(ciphertext: bytes):
    # Buffer-protocol sources take the direct-indexing path; io.BytesIO and the
    # range fetcher exercise the seek()/read() path.
    yield "bytes", bytes(ciphertext)
    yield "bytearray", bytearray(ciphertext)
    yield "memoryview", memoryview(bytes(ciphertext))
    yield "bytesio", io.BytesIO(ciphertext)
    yield "range_fetcher", _RangeFetcher(ciphertext)


SEEK_RANGES = [
    (0, 10),  # start of the first chunk
    (100, 50),  # within the first chunk
    (CHUNK_SIZE - 10, 20),  # spanning the 0/1 chunk boundary
    (CHUNK_SIZE, CHUNK_SIZE),  # exactly one full interior chunk
    (CHUNK_SIZE + 5, 2 * CHUNK_SIZE),  # spanning several chunks
    (50000, 100),  # within the final (short) chunk
    (3 * CHUNK_SIZE, 5000),  # the whole final chunk
    (3 * CHUNK_SIZE + 4990, 10),  # the very end of the message
]


@pytest.mark.parametrize("variant", VARIANTS)
class TestCobblestoneSeekable:
    def _encrypt(self, variant, context, plaintext):
        encryptor_cls, _, _ = variant
        key = encryptor_cls.generate_key()
        return key, _encrypt_all(encryptor_cls, key, context, plaintext)

    @pytest.mark.parametrize("offset,length", SEEK_RANGES)
    def test_decrypt_range_matches_plaintext(self, variant, offset, length):
        _, decryptor_cls, _ = variant
        context = b"seekable context"
        plaintext = os.urandom(3 * CHUNK_SIZE + 5000)
        key, ciphertext = self._encrypt(variant, context, plaintext)
        expected = plaintext[offset : offset + length]

        for source_id, source in _buffer_and_filelike_sources(ciphertext):
            dec = decryptor_cls(key, context)
            assert dec.decrypt_range(source, offset, length) == expected, (
                source_id
            )

    def test_decrypt_range_whole_message(self, variant):
        _, decryptor_cls, _ = variant
        plaintext = os.urandom(2 * CHUNK_SIZE + 1234)
        key, ciphertext = self._encrypt(variant, b"", plaintext)
        dec = decryptor_cls(key, b"")
        assert dec.decrypt_range(ciphertext, 0, len(plaintext)) == plaintext

    def test_decrypt_range_on_exact_chunk_boundary_message(self, variant):
        # A message whose length is a multiple of CHUNK_SIZE has an empty
        # final chunk; ranges not touching it still decrypt.
        _, decryptor_cls, _ = variant
        plaintext = os.urandom(2 * CHUNK_SIZE)
        key, ciphertext = self._encrypt(variant, b"", plaintext)
        dec = decryptor_cls(key, b"")
        assert dec.decrypt_range(ciphertext, 0, 2 * CHUNK_SIZE) == plaintext
        assert (
            dec.decrypt_range(ciphertext, 2 * CHUNK_SIZE - 5, 5)
            == plaintext[-5:]
        )

    def test_decrypt_range_via_mmap(self, variant):
        _, decryptor_cls, _ = variant
        plaintext = os.urandom(2 * CHUNK_SIZE + 777)
        key, ciphertext = self._encrypt(variant, b"ctx", plaintext)
        mm = mmap.mmap(-1, len(ciphertext))
        try:
            mm[:] = ciphertext
            dec = decryptor_cls(key, b"ctx")
            assert (
                dec.decrypt_range(mm, CHUNK_SIZE - 3, 10)
                == plaintext[CHUNK_SIZE - 3 : CHUNK_SIZE + 7]
            )
        finally:
            mm.close()

    def test_zero_length_returns_empty(self, variant):
        _, decryptor_cls, _ = variant
        key, ciphertext = self._encrypt(variant, b"", b"some data")
        dec = decryptor_cls(key, b"")
        # No source access is required for a zero-length range.
        assert dec.decrypt_range(b"", 0, 0) == b""
        assert dec.decrypt_range(ciphertext, 3, 0) == b""

    def test_instance_is_reusable_for_many_ranges(self, variant):
        _, decryptor_cls, _ = variant
        plaintext = os.urandom(3 * CHUNK_SIZE)
        key, ciphertext = self._encrypt(variant, b"", plaintext)
        dec = decryptor_cls(key, b"")
        assert dec.decrypt_range(ciphertext, 10, 20) == plaintext[10:30]
        assert (
            dec.decrypt_range(ciphertext, 2 * CHUNK_SIZE, 100)
            == plaintext[2 * CHUNK_SIZE : 2 * CHUNK_SIZE + 100]
        )

    def test_multi_chunk_range_is_a_single_body_read(self, variant):
        _, decryptor_cls, _ = variant
        plaintext = os.urandom(4 * CHUNK_SIZE)
        key, ciphertext = self._encrypt(variant, b"", plaintext)
        fetcher = _RangeFetcher(ciphertext)
        dec = decryptor_cls(key, b"")
        dec.decrypt_range(fetcher, 100, 2 * CHUNK_SIZE)
        # One read for the header, one contiguous read for the covering chunks.
        assert fetcher.reads == 2

    def test_wrong_key_rejected(self, variant):
        encryptor_cls, decryptor_cls, _ = variant
        _, ciphertext = self._encrypt(variant, b"", os.urandom(CHUNK_SIZE + 1))
        dec = decryptor_cls(encryptor_cls.generate_key(), b"")
        with pytest.raises(InvalidTag):
            dec.decrypt_range(ciphertext, 0, 10)

    def test_wrong_context_rejected(self, variant):
        _, decryptor_cls, _ = variant
        key, ciphertext = self._encrypt(
            variant, b"context a", os.urandom(CHUNK_SIZE + 1)
        )
        dec = decryptor_cls(key, b"context b")
        with pytest.raises(InvalidTag):
            dec.decrypt_range(ciphertext, 0, 10)

    @pytest.mark.parametrize(
        "position",
        [
            0,  # salt
            SALT_LEN,  # commitment
            HEADER_LEN,  # first chunk ciphertext
            HEADER_LEN + WIRE_CHUNK_SIZE - 1,  # first chunk tag
        ],
    )
    def test_tampering_in_range_detected(self, variant, position):
        _, decryptor_cls, _ = variant
        key, ciphertext = self._encrypt(
            variant, b"", os.urandom(CHUNK_SIZE + 100)
        )
        ciphertext = bytearray(ciphertext)
        ciphertext[position] ^= 1
        dec = decryptor_cls(key, b"")
        with pytest.raises(InvalidTag):
            dec.decrypt_range(bytes(ciphertext), 0, 100)

    def test_reading_past_end_rejected(self, variant):
        _, decryptor_cls, _ = variant
        plaintext = os.urandom(CHUNK_SIZE + 500)
        key, ciphertext = self._encrypt(variant, b"", plaintext)
        dec = decryptor_cls(key, b"")
        # Starting exactly at the end, and overshooting the end, both fail
        # rather than returning short: past the authenticated end there are no
        # bytes to return.
        with pytest.raises(InvalidTag):
            dec.decrypt_range(ciphertext, len(plaintext), 1)
        with pytest.raises(InvalidTag):
            dec.decrypt_range(ciphertext, len(plaintext) - 2, 5)

    def test_truncated_source_in_range_rejected(self, variant):
        _, decryptor_cls, _ = variant
        plaintext = os.urandom(2 * CHUNK_SIZE + 10)
        key, ciphertext = self._encrypt(variant, b"", plaintext)
        # Drop everything after the first chunk.
        truncated = ciphertext[: HEADER_LEN + WIRE_CHUNK_SIZE]

        dec = decryptor_cls(key, b"")
        # A range served entirely by the surviving first chunk still succeeds:
        # decrypt_range cannot detect truncation beyond the requested range.
        assert dec.decrypt_range(truncated, 0, 100) == plaintext[:100]
        # A range needing a dropped chunk is rejected.
        with pytest.raises(InvalidTag):
            dec.decrypt_range(truncated, CHUNK_SIZE, 10)

    def test_too_large_offset_rejected(self, variant):
        _, decryptor_cls, _ = variant
        key, ciphertext = self._encrypt(variant, b"", b"data")
        dec = decryptor_cls(key, b"")
        with pytest.raises(ValueError):
            dec.decrypt_range(ciphertext, MAX_CHUNK_COUNT * CHUNK_SIZE, 1)

    def test_negative_arguments_rejected(self, variant):
        _, decryptor_cls, _ = variant
        key, ciphertext = self._encrypt(variant, b"", b"data")
        dec = decryptor_cls(key, b"")
        with pytest.raises((ValueError, OverflowError)):
            dec.decrypt_range(ciphertext, -1, 1)
        with pytest.raises((ValueError, OverflowError)):
            dec.decrypt_range(ciphertext, 0, -1)

    def test_invalid_source_type_rejected(self, variant):
        _, decryptor_cls, _ = variant
        key, _ = self._encrypt(variant, b"", b"data")
        dec = decryptor_cls(key, b"")
        with pytest.raises((TypeError, AttributeError)):
            dec.decrypt_range(12345, 0, 10)

    def test_cannot_seek_after_streaming(self, variant):
        _, decryptor_cls, _ = variant
        key, ciphertext = self._encrypt(variant, b"", os.urandom(CHUNK_SIZE))
        dec = decryptor_cls(key, b"")
        dec.update(ciphertext[:HEADER_LEN])
        with pytest.raises(ValueError, match="cannot be used for both"):
            dec.decrypt_range(ciphertext, 0, 10)

    def test_cannot_stream_after_seeking(self, variant):
        _, decryptor_cls, _ = variant
        key, ciphertext = self._encrypt(variant, b"", os.urandom(CHUNK_SIZE))
        dec = decryptor_cls(key, b"")
        dec.decrypt_range(ciphertext, 0, 10)
        with pytest.raises(ValueError, match="cannot be used for both"):
            dec.update(ciphertext)
        with pytest.raises(ValueError, match="cannot be used for both"):
            dec.update_into(ciphertext, bytearray(2 * CHUNK_SIZE))
        with pytest.raises(ValueError, match="cannot be used for both"):
            dec.finalize()

    def test_final_chunk_read_via_none_returning_source(self, variant):
        # A file-like source that signals end-of-input with None (rather than
        # b"") is handled: reading the short final chunk asks past its end.
        _, decryptor_cls, _ = variant
        plaintext = os.urandom(CHUNK_SIZE + 1234)
        key, ciphertext = self._encrypt(variant, b"", plaintext)
        source = _RangeFetcher(ciphertext, none_at_eof=True)
        dec = decryptor_cls(key, b"")
        assert (
            dec.decrypt_range(source, CHUNK_SIZE, 1234) == plaintext[CHUNK_SIZE:]
        )

    def test_short_header_rejected(self, variant):
        # A source too short to even hold the 56-byte header is truncated.
        _, decryptor_cls, _ = variant
        key, _ = self._encrypt(variant, b"", b"data")
        dec = decryptor_cls(key, b"")
        with pytest.raises(InvalidTag):
            dec.decrypt_range(b"\x00" * (HEADER_LEN - 1), 0, 1)

    def test_final_chunk_shorter_than_tag_rejected(self, variant):
        # A final wire chunk shorter than the tag cannot be authenticated.
        _, decryptor_cls, _ = variant
        key, ciphertext = self._encrypt(variant, b"", os.urandom(100))
        # Keep the full header, but leave only a few (< TAG_LEN) body bytes.
        truncated = ciphertext[: HEADER_LEN + TAG_LEN - 1]
        dec = decryptor_cls(key, b"")
        with pytest.raises(InvalidTag):
            dec.decrypt_range(truncated, 0, 1)

    def test_seeking_instance_survives_out_of_range_error(self, variant):
        # Unlike the streaming decryptor, a random-access failure (here, a
        # read past the end) does not poison the instance.
        _, decryptor_cls, _ = variant
        plaintext = os.urandom(CHUNK_SIZE + 200)
        key, ciphertext = self._encrypt(variant, b"", plaintext)
        dec = decryptor_cls(key, b"")
        with pytest.raises(InvalidTag):
            dec.decrypt_range(ciphertext, len(plaintext), 1)
        assert dec.decrypt_range(ciphertext, 0, 50) == plaintext[:50]


class TestVariantsAreDistinct:
    def test_key_sizes_differ(self):
        assert len(Cobblestone128Encryptor.generate_key()) == 16
        assert len(Cobblestone256Encryptor.generate_key()) == 32

    def test_cross_variant_key_sizes_rejected(self):
        key128 = Cobblestone128Encryptor.generate_key()
        key256 = Cobblestone256Encryptor.generate_key()
        with pytest.raises(ValueError, match="key must be 16 bytes"):
            Cobblestone128Encryptor(key256, b"")
        with pytest.raises(ValueError, match="key must be 32 bytes"):
            Cobblestone256Decryptor(key128, b"")
