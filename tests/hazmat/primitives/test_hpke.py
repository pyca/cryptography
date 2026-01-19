# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

"""
Tests for HPKE (Hybrid Public Key Encryption) implementation.
"""

import json
import os

import pytest

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.hpke import (
    AEAD,
    KDF,
    KEM,
    Suite,
)

# X25519 enc size
NENC = 32


def load_vectors():
    """Load HPKE test vectors from the vectors package."""
    vector_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "..",
        "vectors",
        "cryptography_vectors",
        "HPKE",
        "test-vectors.json",
    )
    if os.path.exists(vector_path):
        with open(vector_path) as f:
            return json.load(f)
    return []


HPKE_VECTORS = load_vectors()


def filter_supported_vectors(vectors):
    """Filter vectors to only those we currently support."""
    supported = []
    for v in vectors:
        # Currently support: mode 0 (Base), X25519, HKDF-SHA256, AES-128-GCM
        if (
            v.get("mode") == 0
            and v.get("kem_id") == 0x0020
            and v.get("kdf_id") == 0x0001
            and v.get("aead_id") == 0x0001
        ):
            supported.append(v)
    return supported


SUPPORTED_VECTORS = filter_supported_vectors(HPKE_VECTORS)


@pytest.mark.supported(
    only_if=lambda backend: backend.x25519_supported(),
    skip_message="Requires OpenSSL with X25519 support",
)
class TestHPKEBasicFunctionality:
    """Test basic HPKE functionality."""

    def test_roundtrip(self):
        """Test basic encryption/decryption."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        ciphertext = suite.encrypt(
            b"Hello, HPKE!", pk_r, info=b"test", aad=b"additional data"
        )
        plaintext = suite.decrypt(
            ciphertext, sk_r, info=b"test", aad=b"additional data"
        )

        assert plaintext == b"Hello, HPKE!"

    def test_roundtrip_no_aad(self):
        """Test encryption/decryption without AAD."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        ciphertext = suite.encrypt(b"Hello!", pk_r)
        plaintext = suite.decrypt(ciphertext, sk_r)

        assert plaintext == b"Hello!"

    def test_wrong_key_fails(self):
        """Test that decryption with wrong key fails."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()
        sk_wrong = x25519.X25519PrivateKey.generate()

        ciphertext = suite.encrypt(b"Secret message", pk_r)

        with pytest.raises(InvalidTag):
            suite.decrypt(ciphertext, sk_wrong)

    def test_wrong_aad_fails(self):
        """Test that decryption with wrong AAD fails."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        ciphertext = suite.encrypt(b"Secret message", pk_r, aad=b"correct aad")

        with pytest.raises(InvalidTag):
            suite.decrypt(ciphertext, sk_r, aad=b"wrong aad")

    def test_info_mismatch_fails(self):
        """Test that mismatched info strings cause decryption failure."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        ciphertext = suite.encrypt(b"Secret", pk_r, info=b"sender info")

        with pytest.raises(InvalidTag):
            suite.decrypt(ciphertext, sk_r, info=b"different info")

    def test_ciphertext_format(self):
        """Test that ciphertext is enc || ct format."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        ciphertext = suite.encrypt(b"test", pk_r)

        # ciphertext should be: enc (32 bytes) + ct (4 bytes pt + 16 bytes tag)
        assert len(ciphertext) == NENC + 4 + 16

    def test_empty_plaintext(self):
        """Test encryption/decryption of empty plaintext."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        ciphertext = suite.encrypt(b"", pk_r)
        plaintext = suite.decrypt(ciphertext, sk_r)

        assert plaintext == b""

    def test_large_plaintext(self):
        """Test encryption/decryption of large plaintext."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        large_message = b"A" * 100000

        ciphertext = suite.encrypt(large_message, pk_r)
        plaintext = suite.decrypt(ciphertext, sk_r)

        assert plaintext == large_message


@pytest.mark.supported(
    only_if=lambda backend: backend.x25519_supported(),
    skip_message="Requires OpenSSL with X25519 support",
)
class TestHPKEErrorCases:
    """Test error handling in HPKE."""

    def test_corrupted_ciphertext(self):
        """Test that corrupted ciphertext fails decryption."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        ciphertext = suite.encrypt(b"test", pk_r)

        # Corrupt the ciphertext (after enc)
        corrupted = ciphertext[:NENC] + bytes([ciphertext[NENC] ^ 0xFF]) + \
            ciphertext[NENC + 1:]

        with pytest.raises(InvalidTag):
            suite.decrypt(corrupted, sk_r)

    def test_truncated_ciphertext(self):
        """Test that truncated ciphertext fails decryption."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        ciphertext = suite.encrypt(b"test", pk_r)

        # Truncate the ciphertext
        truncated = ciphertext[:-1]

        with pytest.raises(InvalidTag):
            suite.decrypt(truncated, sk_r)


@pytest.mark.supported(
    only_if=lambda backend: backend.x25519_supported(),
    skip_message="Requires OpenSSL with X25519 support",
)
class TestHPKEVectors:
    """Test HPKE against RFC 9180 test vectors."""

    @pytest.mark.skipif(
        len(SUPPORTED_VECTORS) == 0,
        reason="No HPKE test vectors available",
    )
    @pytest.mark.parametrize(
        "vector",
        SUPPORTED_VECTORS,
        ids=lambda v: f"mode{v['mode']}_kem{v['kem_id']:04x}_"
        f"kdf{v['kdf_id']:04x}_aead{v['aead_id']:04x}",
    )
    def test_vector_decryption(self, vector):
        """Test decryption using RFC 9180 test vectors."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        # Load keys from vector
        sk_r_bytes = bytes.fromhex(vector["skRm"])
        sk_r = x25519.X25519PrivateKey.from_private_bytes(sk_r_bytes)
        enc = bytes.fromhex(vector["enc"])
        info = bytes.fromhex(vector["info"])

        # Test first encryption only (single-shot API)
        encryptions = vector.get("encryptions", [])
        if encryptions:
            encryption = encryptions[0]
            aad = bytes.fromhex(encryption["aad"])
            ct = bytes.fromhex(encryption["ct"])
            pt_expected = bytes.fromhex(encryption["pt"])

            # Combine enc || ct for single-shot decrypt
            ciphertext = enc + ct
            pt = suite.decrypt(ciphertext, sk_r, info=info, aad=aad)
            assert pt == pt_expected


def test_load_vectors_missing_file(monkeypatch):
    """Test that load_vectors returns empty list when file doesn't exist."""
    monkeypatch.setattr(os.path, "exists", lambda path: False)
    assert load_vectors() == []
