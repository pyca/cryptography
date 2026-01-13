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
    MessageLimitReachedError,
    Suite,
)


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

        # Sender side
        sender = suite.sender(pk_r, info=b"test")
        enc = sender.enc
        ciphertext = sender.encrypt(b"Hello, HPKE!", b"additional data")

        # Recipient side
        recipient = suite.recipient(enc, sk_r, info=b"test")
        plaintext = recipient.decrypt(ciphertext, b"additional data")

        assert plaintext == b"Hello, HPKE!"

    def test_roundtrip_no_aad(self):
        """Test encryption/decryption without AAD."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        sender = suite.sender(pk_r)
        enc = sender.enc
        ciphertext = sender.encrypt(b"Hello!")

        recipient = suite.recipient(enc, sk_r)
        plaintext = recipient.decrypt(ciphertext)

        assert plaintext == b"Hello!"

    def test_wrong_key_fails(self):
        """Test that decryption with wrong key fails."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()
        sk_wrong = x25519.X25519PrivateKey.generate()

        sender = suite.sender(pk_r)
        enc = sender.enc
        ciphertext = sender.encrypt(b"Secret message")

        recipient = suite.recipient(enc, sk_wrong)
        with pytest.raises(InvalidTag):
            recipient.decrypt(ciphertext)

    def test_wrong_aad_fails(self):
        """Test that decryption with wrong AAD fails."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        sender = suite.sender(pk_r)
        enc = sender.enc
        ciphertext = sender.encrypt(b"Secret message", b"correct aad")

        recipient = suite.recipient(enc, sk_r)
        with pytest.raises(InvalidTag):
            recipient.decrypt(ciphertext, b"wrong aad")

    def test_multiple_messages(self):
        """Test encrypting/decrypting multiple messages with same context."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        sender = suite.sender(pk_r)
        enc = sender.enc

        ct1 = sender.encrypt(b"Message 1")
        ct2 = sender.encrypt(b"Message 2")
        ct3 = sender.encrypt(b"Message 3")

        recipient = suite.recipient(enc, sk_r)
        assert recipient.decrypt(ct1) == b"Message 1"
        assert recipient.decrypt(ct2) == b"Message 2"
        assert recipient.decrypt(ct3) == b"Message 3"

    def test_info_mismatch_fails(self):
        """Test that mismatched info strings cause decryption failure."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        sender = suite.sender(pk_r, info=b"sender info")
        enc = sender.enc
        ciphertext = sender.encrypt(b"Secret")

        recipient = suite.recipient(enc, sk_r, info=b"different info")
        with pytest.raises(InvalidTag):
            recipient.decrypt(ciphertext)

    def test_enc_property(self):
        """Test that enc property returns the encapsulated key."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        sender = suite.sender(pk_r)
        enc = sender.enc

        # X25519 enc is 32 bytes
        assert len(enc) == 32
        # enc should be consistent
        assert sender.enc == enc

    def test_empty_plaintext(self):
        """Test encryption/decryption of empty plaintext."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        sender = suite.sender(pk_r)
        enc = sender.enc
        ciphertext = sender.encrypt(b"")

        recipient = suite.recipient(enc, sk_r)
        plaintext = recipient.decrypt(ciphertext)

        assert plaintext == b""

    def test_large_plaintext(self):
        """Test encryption/decryption of large plaintext."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        large_message = b"A" * 100000

        sender = suite.sender(pk_r)
        enc = sender.enc
        ciphertext = sender.encrypt(large_message)

        recipient = suite.recipient(enc, sk_r)
        plaintext = recipient.decrypt(ciphertext)

        assert plaintext == large_message


@pytest.mark.supported(
    only_if=lambda backend: backend.x25519_supported(),
    skip_message="Requires OpenSSL with X25519 support",
)
class TestHPKEErrorCases:
    """Test error handling in HPKE."""

    def test_message_limit_sender(self):
        """Test that message limit is enforced for sender."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        sender = suite.sender(pk_r)
        # Manually set seq to max to trigger limit
        sender._seq = sender._max_seq

        with pytest.raises(MessageLimitReachedError):
            sender.encrypt(b"test")

    def test_message_limit_recipient(self):
        """Test that message limit is enforced for recipient."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        sender = suite.sender(pk_r)
        enc = sender.enc
        ciphertext = sender.encrypt(b"test")

        recipient = suite.recipient(enc, sk_r)
        # Manually set seq to max to trigger limit
        recipient._seq = recipient._max_seq

        with pytest.raises(MessageLimitReachedError):
            recipient.decrypt(ciphertext)

    def test_corrupted_ciphertext(self):
        """Test that corrupted ciphertext fails decryption."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        sender = suite.sender(pk_r)
        enc = sender.enc
        ciphertext = sender.encrypt(b"test")

        # Corrupt the ciphertext
        corrupted = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]

        recipient = suite.recipient(enc, sk_r)
        with pytest.raises(InvalidTag):
            recipient.decrypt(corrupted)

    def test_truncated_ciphertext(self):
        """Test that truncated ciphertext fails decryption."""
        suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_128_GCM)

        sk_r = x25519.X25519PrivateKey.generate()
        pk_r = sk_r.public_key()

        sender = suite.sender(pk_r)
        enc = sender.enc
        ciphertext = sender.encrypt(b"test")

        # Truncate the ciphertext
        truncated = ciphertext[:-1]

        recipient = suite.recipient(enc, sk_r)
        with pytest.raises(InvalidTag):
            recipient.decrypt(truncated)


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

        # Create recipient context
        recipient = suite.recipient(enc, sk_r, info=info)

        # Test each encryption in the vector
        for encryption in vector.get("encryptions", []):
            aad = bytes.fromhex(encryption["aad"])
            ct = bytes.fromhex(encryption["ct"])
            pt_expected = bytes.fromhex(encryption["pt"])

            pt = recipient.decrypt(ct, aad)
            assert pt == pt_expected
