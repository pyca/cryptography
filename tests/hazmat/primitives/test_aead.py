# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import binascii
import os

import pytest

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends.interfaces import CipherBackend
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from ...utils import load_nist_vectors, load_vectors_from_file


@pytest.mark.supported(
    only_if=lambda backend: backend.chacha20poly1305_supported(),
    skip_message="Does not support ChaCha20Poly1305"
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
class TestChaCha20Poly1305(object):
    def test_generate_key(self):
        key = ChaCha20Poly1305.generate_key()
        assert len(key) == 32

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
                chacha.decrypt(nonce, tag, ct, aad)
        else:
            computed_pt = chacha.decrypt(nonce, tag, ct, aad)
            assert computed_pt == pt
            computed_ct, computed_tag = chacha.encrypt(nonce, pt, aad)
            assert computed_ct == ct
            assert computed_tag == tag

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
        if vector["ad"].startswith(b"\""):
            aad = vector["ad"].strip(b"\"")
        else:
            aad = binascii.unhexlify(vector["ad"].strip(b"\""))
        tag = binascii.unhexlify(vector["tag"])
        if vector["in"].startswith(b"\""):
            pt = vector["in"].strip(b"\"")
        else:
            pt = binascii.unhexlify(vector["in"])
        ct = binascii.unhexlify(vector["ct"].strip(b"\""))
        chacha = ChaCha20Poly1305(key)
        computed_pt = chacha.decrypt(nonce, tag, ct, aad)
        assert computed_pt == pt
        computed_ct, computed_tag = chacha.encrypt(nonce, pt, aad)
        assert computed_ct == ct
        assert computed_tag == tag
