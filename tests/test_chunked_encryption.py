# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import os

import pytest

from cryptography.chunked_encryption import (
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
class TestChunkedEncryption:
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
        encryptor_cls, decryptor_cls, key_len = variant
        key = encryptor_cls.generate_key()
        assert isinstance(key, bytes)
        assert len(key) == key_len
        assert not hasattr(decryptor_cls, "generate_key")
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
