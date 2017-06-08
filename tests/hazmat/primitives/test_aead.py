# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import binascii
import os

import pytest

from cryptography.exceptions import InvalidTag, _Reasons
from cryptography.hazmat.backends.interfaces import CipherBackend
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from ...utils import (
    load_nist_vectors, load_vectors_from_file, raises_unsupported_algorithm
)


@pytest.mark.supported(
    only_if=lambda backend: (
        not backend.chacha20poly1305_supported()
    ),
    skip_message="Requires OpenSSL without ChaCha20Poly1305 support"
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
def test_chacha20poly1305_unsupported_on_older_openssl(backend):
    with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_CIPHER):
        ChaCha20Poly1305(ChaCha20Poly1305.generate_key())


@pytest.mark.supported(
    only_if=lambda backend: backend.chacha20poly1305_supported(),
    skip_message="Does not support ChaCha20Poly1305"
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
class TestChaCha20Poly1305(object):
    def test_generate_key(self):
        key = ChaCha20Poly1305.generate_key()
        assert len(key) == 32

    def test_bad_key(self, backend):
        with pytest.raises(TypeError):
            ChaCha20Poly1305(object())

        with pytest.raises(ValueError):
            ChaCha20Poly1305(b"0" * 31)

    @pytest.mark.parametrize(
        ("nonce", "data", "associated_data"),
        [
            [object(), b"data", b""],
            [b"0" * 12, object(), b""],
            [b"0" * 12, b"data", object()]
        ]
    )
    def test_params_not_bytes_encrypt(self, nonce, data, associated_data,
                                      backend):
        key = ChaCha20Poly1305.generate_key()
        chacha = ChaCha20Poly1305(key)
        with pytest.raises(TypeError):
            chacha.encrypt(nonce, data, associated_data)

        with pytest.raises(TypeError):
            chacha.decrypt(nonce, data, associated_data)

    def test_nonce_not_12_bytes(self, backend):
        key = ChaCha20Poly1305.generate_key()
        chacha = ChaCha20Poly1305(key)
        with pytest.raises(ValueError):
            chacha.encrypt(b"00", b"hello", b"")

        with pytest.raises(ValueError):
            chacha.decrypt(b"00", b"hello", b"")

    def test_decrypt_data_too_short(self, backend):
        key = ChaCha20Poly1305.generate_key()
        chacha = ChaCha20Poly1305(key)
        with pytest.raises(InvalidTag):
            chacha.decrypt(b"0" * 12, b"0", None)

    def test_associated_data_none_equal_to_empty_bytestring(self, backend):
        key = ChaCha20Poly1305.generate_key()
        chacha = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        ct1 = chacha.encrypt(nonce, b"some_data", None)
        ct2 = chacha.encrypt(nonce, b"some_data", b"")
        assert ct1 == ct2
        pt1 = chacha.decrypt(nonce, ct1, None)
        pt2 = chacha.decrypt(nonce, ct2, b"")
        assert pt1 == pt2

    @pytest.mark.parametrize(
        "vector",
        load_vectors_from_file(
            os.path.join("ciphers", "ChaCha20Poly1305", "openssl.txt"),
            load_nist_vectors
        )
    )
    def test_openssl_vectors(self, vector, backend):
        key = binascii.unhexlify(vector["key"])
        nonce = binascii.unhexlify(vector["iv"])
        aad = binascii.unhexlify(vector["aad"])
        tag = binascii.unhexlify(vector["tag"])
        pt = binascii.unhexlify(vector["plaintext"])
        ct = binascii.unhexlify(vector["ciphertext"])
        chacha = ChaCha20Poly1305(key)
        if vector.get("result") == b"CIPHERFINAL_ERROR":
            with pytest.raises(InvalidTag):
                chacha.decrypt(nonce, ct + tag, aad)
        else:
            computed_pt = chacha.decrypt(nonce, ct + tag, aad)
            assert computed_pt == pt
            computed_ct = chacha.encrypt(nonce, pt, aad)
            assert computed_ct == ct + tag

    @pytest.mark.parametrize(
        "vector",
        load_vectors_from_file(
            os.path.join("ciphers", "ChaCha20Poly1305", "boringssl.txt"),
            load_nist_vectors
        )
    )
    def test_boringssl_vectors(self, vector, backend):
        key = binascii.unhexlify(vector["key"])
        nonce = binascii.unhexlify(vector["nonce"])
        if vector["ad"].startswith(b'"'):
            aad = vector["ad"][1:-1]
        else:
            aad = binascii.unhexlify(vector["ad"])
        tag = binascii.unhexlify(vector["tag"])
        if vector["in"].startswith(b'"'):
            pt = vector["in"][1:-1]
        else:
            pt = binascii.unhexlify(vector["in"])
        ct = binascii.unhexlify(vector["ct"].strip(b'"'))
        chacha = ChaCha20Poly1305(key)
        computed_pt = chacha.decrypt(nonce, ct + tag, aad)
        assert computed_pt == pt
        computed_ct = chacha.encrypt(nonce, pt, aad)
        assert computed_ct == ct + tag
