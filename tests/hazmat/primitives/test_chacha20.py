# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import binascii
import os
import struct

import pytest

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

from .utils import _load_all_params
from ...utils import load_nist_vectors


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.ChaCha20(b"\x00" * 32, b"0" * 16), None
    ),
    skip_message="Does not support ChaCha20",
)
class TestChaCha20:
    @pytest.mark.parametrize(
        "vector",
        _load_all_params(
            os.path.join("ciphers", "ChaCha20"),
            ["rfc7539.txt"],
            load_nist_vectors,
        ),
    )
    def test_vectors(self, vector, backend):
        key = binascii.unhexlify(vector["key"])
        nonce = binascii.unhexlify(vector["nonce"])
        ibc = struct.pack("<i", int(vector["initial_block_counter"]))
        pt = binascii.unhexlify(vector["plaintext"])
        encryptor = Cipher(
            algorithms.ChaCha20(key, ibc + nonce), None, backend
        ).encryptor()
        computed_ct = encryptor.update(pt) + encryptor.finalize()
        assert binascii.hexlify(computed_ct) == vector["ciphertext"]

    def test_buffer_protocol(self, backend):
        key = bytearray(os.urandom(32))
        nonce = bytearray(os.urandom(16))
        cipher = Cipher(algorithms.ChaCha20(key, nonce), None, backend)
        enc = cipher.encryptor()
        ct = enc.update(bytearray(b"hello")) + enc.finalize()
        dec = cipher.decryptor()
        pt = dec.update(ct) + dec.finalize()
        assert pt == b"hello"

    def test_key_size(self):
        chacha = algorithms.ChaCha20(b"0" * 32, b"0" * 16)
        assert chacha.key_size == 256

    def test_invalid_key_size(self):
        with pytest.raises(ValueError):
            algorithms.ChaCha20(b"wrongsize", b"0" * 16)

    def test_invalid_nonce(self):
        with pytest.raises(ValueError):
            algorithms.ChaCha20(b"0" * 32, b"0")

        with pytest.raises(TypeError):
            algorithms.ChaCha20(b"0" * 32, object())  # type:ignore[arg-type]

    def test_invalid_key_type(self):
        with pytest.raises(TypeError, match="key must be bytes"):
            algorithms.ChaCha20("0" * 32, b"0" * 16)  # type:ignore[arg-type]
