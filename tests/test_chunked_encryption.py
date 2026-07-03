# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import hashlib
import hmac
import os

import pytest

from cryptography.chunked_encryption import Decrypter, Encrypter
from cryptography.exceptions import AlreadyFinalized, InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CHUNK_SIZE = 16 * 1024
TAG_LEN = 16
WIRE_CHUNK_SIZE = CHUNK_SIZE + TAG_LEN
SALT_LEN = 24
COMMITMENT_LEN = 32
HEADER_LEN = SALT_LEN + COMMITMENT_LEN


def _hkdf_expand_sha256(prk: bytes, info: bytes, length: int) -> bytes:
    # Independent HKDF-Expand implementation (RFC 5869), using only the
    # standard library.
    out = b""
    t = b""
    i = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def _derive(key: bytes, salt: bytes, context: bytes):
    info = (
        b"c2sp.org/chunked-encryption@v1+"
        + b"AEAD_AES_128_GCM"
        + b"\x00"
        + salt
        + context
    )
    okm = _hkdf_expand_sha256(key, info, 16 + 12 + COMMITMENT_LEN)
    return okm[:16], okm[16:28], okm[28:]


def _nonce(base_nonce: bytes, counter: int) -> bytes:
    return (int.from_bytes(base_nonce, "big") ^ counter).to_bytes(12, "big")


def _chunks(data: bytes) -> list[bytes]:
    chunks = [
        data[i : i + CHUNK_SIZE] for i in range(0, len(data), CHUNK_SIZE)
    ]
    if not chunks or len(chunks[-1]) == CHUNK_SIZE:
        chunks.append(b"")
    return chunks


def _reference_encrypt(
    key: bytes, context: bytes, salt: bytes, plaintext: bytes
) -> bytes:
    # A minimal reference implementation of c2sp.org/chunked-encryption,
    # used to cross-check the real implementation.
    aead_key, base_nonce, commitment = _derive(key, salt, context)
    aead = AESGCM(aead_key)
    result = salt + commitment
    for i, chunk in enumerate(_chunks(plaintext)):
        result += aead.encrypt(_nonce(base_nonce, i), chunk, None)
    return result


def _reference_decrypt(key: bytes, context: bytes, ciphertext: bytes) -> bytes:
    assert len(ciphertext) >= HEADER_LEN
    salt = ciphertext[:SALT_LEN]
    aead_key, base_nonce, commitment = _derive(key, salt, context)
    assert ciphertext[SALT_LEN:HEADER_LEN] == commitment
    aead = AESGCM(aead_key)
    body = ciphertext[HEADER_LEN:]
    result = b""
    for i in range(0, len(body), WIRE_CHUNK_SIZE):
        chunk = body[i : i + WIRE_CHUNK_SIZE]
        counter = i // WIRE_CHUNK_SIZE
        result += aead.decrypt(_nonce(base_nonce, counter), chunk, None)
    assert len(body) % WIRE_CHUNK_SIZE != 0
    return result


def _encrypt_all(key: bytes, context: bytes, plaintext: bytes) -> bytes:
    enc = Encrypter(key, context)
    return enc.update(plaintext) + enc.finalize()


def _decrypt_all(key: bytes, context: bytes, ciphertext: bytes) -> bytes:
    dec = Decrypter(key, context)
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


class TestChunkedEncryption:
    @pytest.mark.parametrize("length", MESSAGE_LENGTHS)
    def test_round_trip(self, length):
        key = Encrypter.generate_key()
        context = b"test context"
        plaintext = os.urandom(length)

        ciphertext = _encrypt_all(key, context, plaintext)
        n_chunks = length // CHUNK_SIZE + 1
        assert len(ciphertext) == HEADER_LEN + length + n_chunks * TAG_LEN
        assert _decrypt_all(key, context, ciphertext) == plaintext

    @pytest.mark.parametrize("length", MESSAGE_LENGTHS)
    def test_matches_reference_implementation(self, length):
        key = Encrypter.generate_key()
        context = b"reference check"
        plaintext = os.urandom(length)

        # The encrypter generates a random salt internally, so recompute
        # the expected ciphertext with the reference implementation using
        # the salt it chose.
        ciphertext = _encrypt_all(key, context, plaintext)
        salt = ciphertext[:SALT_LEN]
        assert ciphertext == _reference_encrypt(key, context, salt, plaintext)
        assert _reference_decrypt(key, context, ciphertext) == plaintext

        # And decrypt a reference-produced ciphertext with a fixed salt.
        reference = _reference_encrypt(
            key, context, bytes(range(SALT_LEN)), plaintext
        )
        assert _decrypt_all(key, context, reference) == plaintext

    @pytest.mark.parametrize("piece_size", [1, 57, 1024, 16384, 16400])
    def test_streaming(self, piece_size):
        key = Encrypter.generate_key()
        context = b""
        plaintext = os.urandom(2 * CHUNK_SIZE + 12345)

        enc = Encrypter(key, context)
        ciphertext = b""
        for i in range(0, len(plaintext), piece_size):
            ciphertext += enc.update(plaintext[i : i + piece_size])
        ciphertext += enc.finalize()
        assert ciphertext == _reference_encrypt(
            key, context, ciphertext[:SALT_LEN], plaintext
        )

        dec = Decrypter(key, context)
        decrypted = b""
        for i in range(0, len(ciphertext), piece_size):
            decrypted += dec.update(ciphertext[i : i + piece_size])
        decrypted += dec.finalize()
        assert decrypted == plaintext

    def test_empty_message(self):
        key = Encrypter.generate_key()
        enc = Encrypter(key, b"ctx")
        ciphertext = enc.finalize()
        assert len(ciphertext) == HEADER_LEN + TAG_LEN
        assert _decrypt_all(key, b"ctx", ciphertext) == b""

    def test_update_with_empty_data_emits_header(self):
        key = Encrypter.generate_key()
        enc = Encrypter(key, b"")
        header = enc.update(b"")
        assert len(header) == HEADER_LEN
        assert enc.update(b"") == b""
        ciphertext = header + enc.finalize()
        assert _decrypt_all(key, b"", ciphertext) == b""

    def test_exact_chunk_boundary_has_empty_final_chunk(self):
        key = Encrypter.generate_key()
        plaintext = os.urandom(CHUNK_SIZE)
        ciphertext = _encrypt_all(key, b"", plaintext)
        # One full chunk plus an empty final chunk.
        assert len(ciphertext) == HEADER_LEN + WIRE_CHUNK_SIZE + TAG_LEN
        assert _decrypt_all(key, b"", ciphertext) == plaintext

    def test_decrypter_streams_plaintext_incrementally(self):
        key = Encrypter.generate_key()
        plaintext = os.urandom(3 * CHUNK_SIZE)
        ciphertext = _encrypt_all(key, b"", plaintext)

        dec = Decrypter(key, b"")
        out = dec.update(ciphertext[: HEADER_LEN + WIRE_CHUNK_SIZE])
        assert out == plaintext[:CHUNK_SIZE]
        out = dec.update(ciphertext[HEADER_LEN + WIRE_CHUNK_SIZE :])
        assert out == plaintext[CHUNK_SIZE:]
        assert dec.finalize() == b""

    def test_wrong_key(self):
        key = Encrypter.generate_key()
        ciphertext = _encrypt_all(key, b"", b"message")
        dec = Decrypter(Decrypter.generate_key(), b"")
        with pytest.raises(InvalidTag):
            dec.update(ciphertext)

    def test_wrong_context(self):
        key = Encrypter.generate_key()
        ciphertext = _encrypt_all(key, b"context a", b"message")
        dec = Decrypter(key, b"context b")
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
    def test_tampering_detected(self, position):
        key = Encrypter.generate_key()
        plaintext = os.urandom(CHUNK_SIZE + 100)
        ciphertext = bytearray(_encrypt_all(key, b"", plaintext))
        ciphertext[position] ^= 1

        dec = Decrypter(key, b"")
        with pytest.raises(InvalidTag):
            dec.update(bytes(ciphertext))
            dec.finalize()

    def test_swapped_chunks_detected(self):
        key = Encrypter.generate_key()
        plaintext = os.urandom(2 * CHUNK_SIZE + 100)
        ciphertext = _encrypt_all(key, b"", plaintext)

        chunk0_start = HEADER_LEN
        chunk1_start = HEADER_LEN + WIRE_CHUNK_SIZE
        chunk2_start = HEADER_LEN + 2 * WIRE_CHUNK_SIZE
        swapped = (
            ciphertext[:HEADER_LEN]
            + ciphertext[chunk1_start:chunk2_start]
            + ciphertext[chunk0_start:chunk1_start]
            + ciphertext[chunk2_start:]
        )
        dec = Decrypter(key, b"")
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
    def test_truncation_detected(self, length):
        key = Encrypter.generate_key()
        plaintext = os.urandom(CHUNK_SIZE + 100)
        ciphertext = _encrypt_all(key, b"", plaintext)

        dec = Decrypter(key, b"")
        with pytest.raises(InvalidTag):
            dec.update(ciphertext[:length])
            dec.finalize()

    def test_extension_detected(self):
        key = Encrypter.generate_key()
        ciphertext = _encrypt_all(key, b"", b"message")

        dec = Decrypter(key, b"")
        with pytest.raises(InvalidTag):
            dec.update(ciphertext + b"extra garbage bytes!")
            dec.finalize()

    def test_ciphertexts_are_randomized(self):
        key = Encrypter.generate_key()
        assert _encrypt_all(key, b"", b"data") != _encrypt_all(
            key, b"", b"data"
        )

    def test_update_into(self):
        key = Encrypter.generate_key()
        plaintext = os.urandom(CHUNK_SIZE + 100)

        enc = Encrypter(key, b"")
        buf = bytearray(HEADER_LEN + 2 * WIRE_CHUNK_SIZE)
        n = enc.update_into(plaintext, buf)
        assert n == HEADER_LEN + WIRE_CHUNK_SIZE
        ciphertext = bytes(buf[:n]) + enc.finalize()
        assert _decrypt_all(key, b"", ciphertext) == plaintext

        dec = Decrypter(key, b"")
        out = bytearray(2 * CHUNK_SIZE)
        n = dec.update_into(ciphertext, out)
        assert n == CHUNK_SIZE
        assert bytes(out[:n]) + dec.finalize() == plaintext

    def test_update_into_accepts_larger_buffer(self):
        key = Encrypter.generate_key()
        enc = Encrypter(key, b"")
        buf = bytearray(10 * WIRE_CHUNK_SIZE)
        n = enc.update_into(b"abc", buf)
        assert n == HEADER_LEN
        ciphertext = bytes(buf[:n]) + enc.finalize()
        assert _decrypt_all(key, b"", ciphertext) == b"abc"

    def test_update_into_buffer_too_small(self):
        key = Encrypter.generate_key()
        enc = Encrypter(key, b"")
        with pytest.raises(ValueError, match="buffer must be at least"):
            enc.update_into(b"abc", bytearray(HEADER_LEN - 1))
        # The context remains usable after the failed call.
        ciphertext = enc.update(b"abc") + enc.finalize()

        dec = Decrypter(key, b"")
        with pytest.raises(ValueError, match="buffer must be at least"):
            dec.update_into(
                ciphertext + bytes(WIRE_CHUNK_SIZE), bytearray(CHUNK_SIZE - 1)
            )
        assert dec.update(ciphertext) == b""
        assert dec.finalize() == b"abc"

    def test_update_into_zero_output(self):
        key = Encrypter.generate_key()
        dec = Decrypter(key, b"")
        assert dec.update_into(b"", bytearray(0)) == 0

    def test_use_after_finalize(self):
        key = Encrypter.generate_key()
        enc = Encrypter(key, b"")
        ciphertext = enc.update(b"data") + enc.finalize()
        with pytest.raises(AlreadyFinalized):
            enc.update(b"more")
        with pytest.raises(AlreadyFinalized):
            enc.update_into(b"more", bytearray(WIRE_CHUNK_SIZE))
        with pytest.raises(AlreadyFinalized):
            enc.finalize()

        dec = Decrypter(key, b"")
        dec.update(ciphertext)
        dec.finalize()
        with pytest.raises(AlreadyFinalized):
            dec.update(b"more")
        with pytest.raises(AlreadyFinalized):
            dec.update_into(b"more", bytearray(WIRE_CHUNK_SIZE))
        with pytest.raises(AlreadyFinalized):
            dec.finalize()

    def test_decrypter_poisoned_after_invalid_tag(self):
        key = Encrypter.generate_key()
        ciphertext = bytearray(_encrypt_all(key, b"", b"data"))
        ciphertext[-1] ^= 1

        dec = Decrypter(key, b"")
        dec.update(bytes(ciphertext))
        with pytest.raises(InvalidTag):
            dec.finalize()
        # All subsequent operations fail.
        with pytest.raises(InvalidTag):
            dec.update(b"")
        with pytest.raises(InvalidTag):
            dec.finalize()

    def test_finalize_only_decrypter_rejects_empty_stream(self):
        key = Decrypter.generate_key()
        dec = Decrypter(key, b"")
        with pytest.raises(InvalidTag):
            dec.finalize()

    def test_generate_key(self):
        key = Encrypter.generate_key()
        assert isinstance(key, bytes)
        assert len(key) == 16
        assert len(Decrypter.generate_key()) == 16
        assert Encrypter.generate_key() != Encrypter.generate_key()

    @pytest.mark.parametrize("length", [0, 15, 17, 32])
    def test_invalid_key_size(self, length):
        with pytest.raises(ValueError):
            Encrypter(b"\x00" * length, b"")
        with pytest.raises(ValueError):
            Decrypter(b"\x00" * length, b"")

    def test_invalid_types(self):
        key = Encrypter.generate_key()
        with pytest.raises(TypeError):
            Encrypter("not bytes", b"")  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            Encrypter(key, "not bytes")  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            Decrypter("not bytes", b"")  # type: ignore[arg-type]
        enc = Encrypter(key, b"")
        with pytest.raises(TypeError):
            enc.update("not bytes")  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            enc.update_into(b"", b"immutable")

    def test_accepts_buffers(self):
        key = bytearray(Encrypter.generate_key())
        plaintext = os.urandom(1000)
        enc = Encrypter(key, memoryview(b"ctx"))
        ciphertext = enc.update(memoryview(plaintext)) + enc.finalize()
        dec = Decrypter(memoryview(bytes(key)), bytearray(b"ctx"))
        assert dec.update(bytearray(ciphertext)) + dec.finalize() == plaintext
