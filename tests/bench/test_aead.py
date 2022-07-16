# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import pytest

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from ..hazmat.primitives.test_aead import _aead_supported


@pytest.mark.skipif(
    not _aead_supported(ChaCha20Poly1305),
    reason="Requires OpenSSL with ChaCha20Poly1305 support",
)
def test_chacha20poly1305(benchmark):
    chacha = ChaCha20Poly1305(b"\x00" * 32)
    benchmark(chacha.encrypt, b"\x00" * 12, b"hello world plaintext", b"")
