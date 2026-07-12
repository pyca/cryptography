# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

# The Rust layer releases the GIL when processing buffers of at least
# 2048 bytes (matching CPython's HASHLIB_GIL_MINSIZE) and holds it for
# smaller ones. These tests run every affected primitive with sizes on
# both sides of -- and exactly at -- that threshold, so that both the
# GIL-held and GIL-released code paths are exercised.

import hashlib
import hmac as stdlib_hmac
import os

import pytest

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.bindings._rust import openssl as rust_openssl
from cryptography.hazmat.primitives import cmac, hashes, hmac, poly1305
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)
from cryptography.hazmat.primitives.ciphers.aead import (
    AESCCM,
    AESGCM,
    AESOCB3,
    AESSIV,
    ChaCha20Poly1305,
)

# The GIL is released for buffers >= this size (see
# GIL_DETACH_MINSIZE in src/rust/src/backend/utils.rs).
_THRESHOLD = 2048
# One size well below the threshold, the two sizes straddling it, and one
# size well above it (deliberately not a multiple of any block size).
_SIZES = [23, _THRESHOLD - 1, _THRESHOLD, 65536 + 3]
# Chunks of this size always take the GIL-held path.
_SMALL_CHUNK = 1024


def _aead_supported(cls):
    try:
        cls(b"0" * 32)
        return True
    except UnsupportedAlgorithm:
        return False


def _chunks(data):
    return [
        data[i : i + _SMALL_CHUNK] for i in range(0, len(data), _SMALL_CHUNK)
    ]


@pytest.mark.parametrize("size", _SIZES)
class TestHashBulkData:
    def test_update(self, size, backend):
        data = os.urandom(size)
        h = hashes.Hash(hashes.SHA256())
        h.update(data)
        assert h.finalize() == hashlib.sha256(data).digest()

    def test_oneshot(self, size, backend):
        data = os.urandom(size)
        assert (
            rust_openssl.hashes.Hash.hash(hashes.SHA256(), data)
            == hashlib.sha256(data).digest()
        )


@pytest.mark.supported(
    only_if=lambda backend: (
        rust_openssl.CRYPTOGRAPHY_OPENSSL_330_OR_GREATER
        or rust_openssl.CRYPTOGRAPHY_IS_AWSLC
    ),
    skip_message="Requires backend with XOF support",
)
@pytest.mark.parametrize("size", _SIZES)
class TestXOFHashBulkData:
    def test_update_and_squeeze(self, size, backend):
        data = os.urandom(size)
        h = hashes.XOFHash(hashes.SHAKE128(digest_size=size))
        h.update(data)
        squeezed = h.squeeze(size)
        assert squeezed == hashlib.shake_128(data).digest(size)


@pytest.mark.parametrize("size", _SIZES)
class TestHMACBulkData:
    def test_update(self, size, backend):
        key = os.urandom(32)
        data = os.urandom(size)
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(data)
        assert (
            h.finalize() == stdlib_hmac.new(key, data, hashlib.sha256).digest()
        )


@pytest.mark.parametrize("size", _SIZES)
class TestCMACBulkData:
    def test_update(self, size, backend):
        key = os.urandom(32)
        data = os.urandom(size)

        # A single large update takes the GIL-released path (for sizes
        # over the threshold), while sub-threshold chunks always take the
        # GIL-held path; both must produce the same tag.
        c = cmac.CMAC(algorithms.AES(key))
        c.update(data)
        tag = c.finalize()

        c = cmac.CMAC(algorithms.AES(key))
        for chunk in _chunks(data):
            c.update(chunk)
        c.verify(tag)


@pytest.mark.supported(
    only_if=lambda backend: backend.poly1305_supported(),
    skip_message="Requires OpenSSL with poly1305 support",
)
@pytest.mark.parametrize("size", _SIZES)
class TestPoly1305BulkData:
    def test_update(self, size, backend):
        key = os.urandom(32)
        data = os.urandom(size)

        p = poly1305.Poly1305(key)
        p.update(data)
        tag = p.finalize()

        p = poly1305.Poly1305(key)
        for chunk in _chunks(data):
            p.update(chunk)
        p.verify(tag)

        assert poly1305.Poly1305.generate_tag(key, data) == tag


@pytest.mark.parametrize("size", _SIZES)
class TestCipherBulkData:
    def test_update(self, size, backend):
        key = os.urandom(32)
        nonce = os.urandom(16)
        data = os.urandom(size)

        enc = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
        ct = enc.update(data) + enc.finalize()
        assert len(ct) == len(data)

        enc = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
        ct_chunked = (
            b"".join(enc.update(chunk) for chunk in _chunks(data))
            + enc.finalize()
        )
        assert ct == ct_chunked

        dec = Cipher(algorithms.AES(key), modes.CTR(nonce)).decryptor()
        assert dec.update(ct) + dec.finalize() == data

    def test_update_into(self, size, backend):
        key = os.urandom(32)
        nonce = os.urandom(16)
        data = os.urandom(size)

        enc = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
        ct = enc.update(data) + enc.finalize()

        enc = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
        buf = bytearray(len(data) + 15)
        n = enc.update_into(data, buf)
        enc.finalize()
        assert bytes(buf[:n]) == ct

    def test_gcm_streaming_with_aad(self, size, backend):
        key = os.urandom(32)
        iv = os.urandom(12)
        data = os.urandom(size)
        aad = os.urandom(size)

        enc = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
        enc.authenticate_additional_data(aad)
        ct = enc.update(data) + enc.finalize()

        dec = Cipher(algorithms.AES(key), modes.GCM(iv, enc.tag)).decryptor()
        dec.authenticate_additional_data(aad)
        assert dec.update(ct) + dec.finalize() == data


@pytest.mark.parametrize("size", _SIZES)
class TestAEADBulkData:
    def test_aesgcm(self, size, backend):
        key = AESGCM.generate_key(256)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        data = os.urandom(size)
        aad = os.urandom(size)

        ct = aesgcm.encrypt(nonce, data, aad)
        assert aesgcm.decrypt(nonce, ct, aad) == data

        # Cross-check the one-shot AEAD implementation against the
        # streaming GCM implementation, which is an independent code
        # path in the Rust layer.
        enc = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        enc.authenticate_additional_data(aad)
        streaming_ct = enc.update(data) + enc.finalize() + enc.tag
        assert ct == streaming_ct

    @pytest.mark.skipif(
        not _aead_supported(ChaCha20Poly1305),
        reason="Does not support ChaCha20Poly1305",
    )
    def test_chacha20poly1305(self, size, backend):
        key = ChaCha20Poly1305.generate_key()
        chacha = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        data = os.urandom(size)
        aad = os.urandom(size)

        ct = chacha.encrypt(nonce, data, aad)
        assert chacha.decrypt(nonce, ct, aad) == data

    @pytest.mark.skipif(
        not _aead_supported(AESCCM),
        reason="Does not support AESCCM",
    )
    def test_aesccm(self, size, backend):
        key = AESCCM.generate_key(256)
        aesccm = AESCCM(key)
        nonce = os.urandom(12)
        data = os.urandom(size)
        aad = os.urandom(size)

        ct = aesccm.encrypt(nonce, data, aad)
        assert aesccm.decrypt(nonce, ct, aad) == data

    @pytest.mark.skipif(
        not _aead_supported(AESOCB3),
        reason="Does not support AESOCB3",
    )
    def test_aesocb3(self, size, backend):
        # OCB is block-based (block size > 1), so this exercises the
        # non-streaming branch of the AEAD data processing.
        key = AESOCB3.generate_key(256)
        aesocb3 = AESOCB3(key)
        nonce = os.urandom(12)
        data = os.urandom(size)
        aad = os.urandom(size)

        ct = aesocb3.encrypt(nonce, data, aad)
        assert aesocb3.decrypt(nonce, ct, aad) == data

    @pytest.mark.skipif(
        not _aead_supported(AESSIV),
        reason="Does not support AESSIV",
    )
    def test_aessiv(self, size, backend):
        # AESSIV takes a *list* of associated data items, exercising the
        # multi-item AAD path.
        key = AESSIV.generate_key(512)
        aessiv = AESSIV(key)
        data = os.urandom(size)
        aad = [os.urandom(size), os.urandom(_SMALL_CHUNK)]

        ct = aessiv.encrypt(data, aad)
        assert aessiv.decrypt(ct, aad) == data
