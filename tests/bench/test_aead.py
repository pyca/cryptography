# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import pytest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESOCB3, AESCCM, AESSIV, ChaCha20Poly1305

from ..hazmat.primitives.test_aead import _aead_supported


@pytest.mark.skipif(
    not _aead_supported(ChaCha20Poly1305),
    reason="Requires OpenSSL with ChaCha20Poly1305 support",
)
def test_chacha20poly1305(benchmark):
    chacha = ChaCha20Poly1305(b"\x00" * 32)
    benchmark(chacha.encrypt, b"\x00" * 12, b"hello world plaintext", b"")


def test_aesgcm(benchmark):
    aes = AESGCM(b"\x00" * 32)
    benchmark(aes.encrypt, b"\x00" * 12, b"hello world plaintext", None)


@pytest.mark.skipif(
    not _aead_supported(AESSIV),
    reason="Requires OpenSSL with AES-SIV support",
)
def test_aessiv(benchmark):
    aes = AESSIV(b"\x00" * 32)
    benchmark(aes.encrypt, b"hello world plaintext", None)


@pytest.mark.skipif(
    not _aead_supported(AESOCB3),
    reason="Requires OpenSSL with AES-OCB3 support",
)
def test_aesocb3(benchmark):
    aes = AESOCB3(b"\x00" * 32)
    benchmark(aes.encrypt, b"\x00" * 12, b"hello world plaintext", None)


@pytest.mark.skipif(
    not _aead_supported(AESCCM),
    reason="Requires OpenSSL with AES-CCM support",
)
def test_aesccm(benchmark):
    aes = AESCCM(b"\x00" * 32)
    benchmark(aes.encrypt, b"\x00" * 12, b"hello world plaintext", None)
